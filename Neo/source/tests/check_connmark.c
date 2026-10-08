#include "fake_nf.h"

/* hrneo before 1le2: old R1 and an unconditional restore, HydraRoute first. */
static const char *const OLD_RULES[] = {
    "-A PREROUTING -m mark ! --mark 0xffffaa0/0xffffff0 -m connmark --mark 0x0 -m set --match-set HydraRoute dst -j CONNMARK --set-xmark 0xff2/0xffffffff",
    "-A PREROUTING -m set --match-set HydraRoute dst -j CONNMARK --restore-mark --nfmask 0xffffffff --ctmask 0xffffffff",
    "-A PREROUTING -m mark ! --mark 0xffffaa0/0xffffff0 -m connmark --mark 0x0 -m set --match-set RU dst -j CONNMARK --set-xmark 0xff1/0xffffffff",
    "-A PREROUTING -m set --match-set RU dst -j CONNMARK --restore-mark --nfmask 0xffffffff --ctmask 0xffffffff",
};

static const char *const OLD_RULES6[] = {
    "-A PREROUTING -m mark ! --mark 0xffffaa0/0xffffff0 -m connmark --mark 0x0 -m set --match-set HydraRoute6 dst -j CONNMARK --set-xmark 0xff2/0xffffffff",
    "-A PREROUTING -m set --match-set HydraRoute6 dst -j CONNMARK --restore-mark --nfmask 0xffffffff --ctmask 0xffffffff",
};

/* An unconditional restore hrneo does not own: old hrneo, or a target no
 * longer in the config. */
#define OLD_FOREIGN  "-A PREROUTING -m set --match-set Old dst -j CONNMARK --restore-mark --nfmask 0xffffffff --ctmask 0xffffffff"
#define OLD_FOREIGN6 "-A PREROUTING -m set --match-set Old6 dst -j CONNMARK --restore-mark --nfmask 0xffffffff --ctmask 0xffffffff"

/* HydraRoute's raw rule as hrneo 1le2 wrote it, per family. */
static const char *const HR_RAW[2] = {
    "-A HRNEO_GUARD -m set --match-set HydraRoute dst -j MARK --set-xmark 0xff2/0xffffffff",
    "-A HRNEO_GUARD -m set --match-set HydraRoute6 dst -j MARK --set-xmark 0xff2/0xffffffff",
};

/* A chain with HydraRoute's rule and one jump into it, as 1le2 leaves it. */
static void raw_leftover(int fi) {
    nf[fi].guard_exists = 1;
    lines_add(nf[fi].guard, &nf[fi].guard_len, HR_RAW[fi]);
    lines_add(nf[fi].raw_pre, &nf[fi].raw_pre_len, GUARD_JUMP);
}

/* RU, HydraRoute and the DirectRoute interface target wg0. */
static void targets_with_wg0(unified_target_t *t3, const unified_target_t *t) {
    memcpy(t3, t, 2 * sizeof(*t));
    memset(&t3[2], 0, sizeof(t3[2]));
    strcpy(t3[2].pair.ipv4, "wg0");
    strcpy(t3[2].pair.ipv6, "wg0v6");
    t3[2].is_interface = 1;
    t3[2].fwmark = 0x3001;
}

/* While the process starts every policy is asked over RCI on each commit,
 * until one commit succeeds; failures are retried. */
static void check_start_and_migration(const unified_target_t *t, config_t *cfg) {
    lines_add(nf[0].mangle, &nf[0].mangle_len, NDM_LINE);
    for (int i = 0; i < 4; i++) lines_add(nf[0].mangle, &nf[0].mangle_len, OLD_RULES[i]);
    for (int i = 0; i < 2; i++) lines_add(nf[1].mangle, &nf[1].mangle_len, OLD_RULES6[i]);
    /* hrneo 1le2 ran before and was rolled back to 1le1 without raw-off: the
     * chains and their jumps are still there, next to the old rules. */
    raw_leftover(0);
    raw_leftover(1);

    /* xt_conntrack does not load: no RCI and no mangle write, the next commit
     * tries again. Old R1 and R2 stay, so the jumps next to them go in both
     * families: the safety step needs neither the module nor the marks
     * (Ruling 29). */
    reset();
    kmod_result = -1;
    assert(apply_unified_connmark_rules(t, 2, cfg, NULL) == -1);
    assert(kmod_calls == 1 && rci_calls == 0);
    assert(restores[0][0] == 0 && restores[1][0] == 0);
    assert(strcmp(calls, "r4 r6 ") == 0);
    assert(raw_kmod_calls[0] == 0 && raw_kmod_calls[1] == 0);
    assert(raw_jumps(0) == 0 && nf[0].guard_len == 0);
    assert(raw_jumps(1) == 0 && nf[1].guard_len == 0);
    assert(warns == 3);                     /* two jump removals, the raw guard */
    assert(strstr(warn_log, "iptables: removed the jump to raw HRNEO_GUARD"));
    assert(strstr(warn_log, "ip6tables: removed the jump to raw HRNEO_GUARD"));
    assert(status_has("raw_guard=degraded:old-restore-v4"));
    assert(status_has("raw_rules_v4=0") && status_has("raw_rules_v6=0"));

    /* Still not loaded: nothing left to take down; the status names the module. */
    reset();
    assert(apply_unified_connmark_rules(t, 2, cfg, NULL) == -1);
    assert(kmod_calls == 1 && rci_calls == 0 && calls[0] == '\0');
    assert(warns == 1 && strstr(warn_log, "raw guard degraded: conntrack-module-v4"));
    assert(status_has("raw_guard=degraded:conntrack-module-v4"));
    kmod_result = 0;

    /* An IPv6 chain and jump are back while RCI is still down (a 1le2 binary
     * run by hand): the same step in the normal path follows. */
    raw_leftover(1);

    /* RCI down at start: no mark is known; the old rules are kept as written,
     * only put in PolicyOrder (RU first). The raw chain stays out while they
     * are there, and the status says why. The IPv6 jump next to the old
     * unconditional restore that mangle could not replace goes (§4.5's one
     * exception): with it, every new IPv6 connection would leak. */
    reset();
    rci_result = RCI_MARK_TRANSPORT;
    assert(apply_unified_connmark_rules(t, 2, cfg, NULL) == -1);
    assert(kmod_calls == 1);
    assert(raw_kmod_calls[0] == 1 && raw_kmod_calls[1] == 1);
    assert(warns == 4);                     /* two policies, the jump removal, the raw guard */
    assert(strstr(warn_log, "ip6tables: removed the jump to raw HRNEO_GUARD"));
    assert(strstr(warn_log, "raw guard degraded: no-mark-v4"));
    assert(restores[0][0] == 1 && restores[1][0] == 0);
    assert(strcmp(calls, "m4 r6 ") == 0);
    assert(nf[0].mangle_len == 5);
    assert(strcmp(nf[0].mangle[1], OLD_RULES[2]) == 0 && strcmp(nf[0].mangle[2], OLD_RULES[3]) == 0);
    assert(strcmp(nf[0].mangle[3], OLD_RULES[0]) == 0 && strcmp(nf[0].mangle[4], OLD_RULES[1]) == 0);
    assert(nf[1].mangle_len == 2);
    assert(raw_jumps(0) == 0 && nf[0].guard_len == 0);
    assert(raw_jumps(1) == 0 && nf[1].guard_len == 0);
    assert(status_has("raw_guard=degraded:no-mark-v4"));
    assert(status_has("raw_rules_v4=0") && status_has("raw_rules_v6=0"));

    /* Still down: both policies are asked again, the cause is a WARN only
     * once; the raw modules are not loaded again. */
    reset();
    assert(apply_unified_connmark_rules(t, 2, cfg, NULL) == -1);
    assert(kmod_calls == 0 && rci_calls == 2 && warns == 0);
    assert(raw_kmod_calls[0] == 0 && raw_kmod_calls[1] == 0);
    assert(restores[0][0] == 0 && restores[1][0] == 0);
    assert(calls[0] == '\0');

    /* HydraRoute has no mark (RCI_MARK_ABSENT): its rules leave both
     * families; RU moves to R0..R3. No unconditional restore is left and every
     * remaining policy has its mark: the migration from hrneo before 1le2.
     * Mangle is replaced and read back in both families before the raw chain
     * goes in (§3.2); the fake asserts no unconditional restore while it marks. */
    reset();
    rci_result = RCI_MARK_OK;
    rci_result_hr = RCI_MARK_ABSENT;
    assert(apply_unified_connmark_rules(t, 2, cfg, NULL) == -1);
    assert(rci_calls == 2 && warns == 2);
    assert(strstr(warn_log, "Policy HydraRoute has no mark ID yet"));
    assert(strstr(warn_log, "raw guard on again (was degraded: no-mark-v4)"));
    assert(restores[0][0] == 1 && restores[1][0] == 1);
    assert(strcmp(calls, "m4 m6 r4 r6 ") == 0);
    assert(strcmp(nf[0].mangle[0], NDM_LINE) == 0);
    assert_mangle_of(0, 1, 1, 0, 0);
    assert_mangle_of(1, 0, 1, 0, 0);
    assert_raw_of(0, 1, 0);
    assert_raw_of(1, 1, 0);
    assert(status_has("raw_guard=on") && status_has("raw_rules_v4=1") && status_has("raw_rules_v6=1"));

    /* The same again: no WARN, nothing to change. RU's mark is known, but
     * RCI is asked for every policy until the start is over: no ip rule dump. */
    reset();
    assert(apply_unified_connmark_rules(t, 2, cfg, NULL) == -1);
    assert(rci_calls == 2 && warns == 0 && rule_dumps == 0);
    assert(restores[0][0] == 0 && restores[1][0] == 0);
    assert(calls[0] == '\0');

    /* HydraRoute gets its mark, which RCI spells with a leading zero and
     * capitals; RCI fails for RU, which keeps the rules of its known mark.
     * Every mark is known: the chain gets HydraRoute too. */
    reset();
    rci_result_ru = RCI_MARK_TRANSPORT;
    rci_result_hr = RCI_MARK_OK;
    mark_hr = "0FF2";
    assert(apply_unified_connmark_rules(t, 2, cfg, NULL) == -1);
    assert(warns == 1 && strstr(warn_log, "RCI unreachable while reading policy RU"));
    assert(restores[0][0] == 1 && restores[1][0] == 1);
    assert(strcmp(calls, "m4 m6 r4 r6 ") == 0);
    assert_mangle(0, 1, 0xff2, 0);
    assert_mangle(1, 0, 0xff2, 0);
    assert_raw(0, 0xff2);
    assert_raw(1, 0xff2);

    /* Once the policy worked, a new failure is reported again; its rules
     * leave mangle and the chain. */
    reset();
    rci_result_hr = RCI_MARK_ABSENT;
    assert(apply_unified_connmark_rules(t, 2, cfg, NULL) == -1);
    assert(warns == 1 && strstr(warn_log, "Policy HydraRoute has no mark ID yet"));
    assert(restores[0][0] == 1 && restores[1][0] == 1);
    assert(strcmp(calls, "m4 m6 r4 r6 ") == 0);
    assert_mangle_of(0, 1, 1, 0, 0);
    assert_mangle_of(1, 0, 1, 0, 0);
    assert_raw_of(0, 1, 0);
    assert_raw_of(1, 1, 0);

    /* RCI answers for both: one replace per family, and the start is over. */
    reset();
    rci_result_ru = rci_result_hr = RCI_MARK_OK;
    assert(apply_unified_connmark_rules(t, 2, cfg, NULL) == 0);
    mark_hr = "ff2";
    assert(rci_calls == 2 && warns == 0);
    assert(restores[0][0] == 1 && restores[1][0] == 1);
    assert(strcmp(calls, "m4 m6 r4 r6 ") == 0);
    assert(strcmp(nf[0].mangle[0], NDM_LINE) == 0);
    assert_mangle(0, 1, 0xff2, 0);
    assert_mangle(1, 0, 0xff2, 0);
    assert_raw(0, 0xff2);
    assert_raw(1, 0xff2);
    assert(status_has("raw_guard=on") && status_has("raw_rules_v4=2") && status_has("raw_rules_v6=2"));
}

static void check_audit(const unified_target_t *t, config_t *cfg) {
    /* Nothing changed: no RCI, no restore. */
    reset();
    assert(apply_unified_connmark_rules(t, 2, cfg, NULL) == 0);
    assert(rci_calls == 0 && restores[0][0] == 0 && restores[1][0] == 0);

    /* NDMS rebuilt mangle without hrneo's rules: back from the known marks, no
     * RCI. NDMS leaves raw alone, and so does hrneo. */
    reset();
    mangle_remove_matching(0, "--match-set ");
    assert(apply_unified_connmark_rules(t, 2, cfg, NULL) == 0);
    assert(rci_calls == 0 && restores[0][0] == 1 && restores[1][0] == 0);
    assert(strcmp(calls, "m4 ") == 0);
    assert_mangle(0, 1, 0xff2, 0);
    assert_raw(0, 0xff2);

    /* One rule missing. */
    reset();
    mangle_remove_matching(1, "--ctdir REPLY -m connmark --mark 0x0 -m set --match-set RU6 dst");
    assert(apply_unified_connmark_rules(t, 2, cfg, NULL) == 0);
    assert(restores[1][0] == 1);
    assert_mangle(1, 0, 0xff2, 0);

    /* A stray old unconditional restore next to a working chain: this call
     * replaces mangle and reads it back clean, so the jump stays and the
     * guard stays on (correction 1, case b). */
    reset();
    lines_add(nf[0].mangle, &nf[0].mangle_len, OLD_RULES[1]);
    assert(apply_unified_connmark_rules(t, 2, cfg, NULL) == 0);
    assert(restores[0][0] == 1);
    assert(strcmp(calls, "m4 ") == 0);
    assert_mangle(0, 1, 0xff2, 0);
    assert_raw(0, 0xff2);
    assert(status_has("raw_guard=on"));

    /* A rule twice: both copies go, one comes back. */
    reset();
    lines_add(nf[1].mangle, &nf[1].mangle_len, nf[1].mangle[2]);
    assert(apply_unified_connmark_rules(t, 2, cfg, NULL) == 0);
    assert(restores[0][0] == 0 && restores[1][0] == 1);
    assert_mangle(1, 0, 0xff2, 0);

    /* Blocks out of PolicyOrder: RU's R0 behind HydraRoute's block. */
    reset();
    {
        char ru0[LINE_LEN];
        snprintf(ru0, sizeof(ru0), "%s", nf[0].mangle[1]);
        lines_remove(nf[0].mangle, &nf[0].mangle_len, 1);
        lines_add(nf[0].mangle, &nf[0].mangle_len, ru0);
    }
    assert(apply_unified_connmark_rules(t, 2, cfg, NULL) == 0);
    assert(restores[0][0] == 1);
    assert_mangle(0, 1, 0xff2, 0);

    /* The rules of hrneo before 1le2 are back (a rollback ran in between):
     * replaced from the known marks, no RCI, one restore per family. */
    reset();
    mangle_remove_matching(0, "--match-set ");
    mangle_remove_matching(1, "--match-set ");
    for (int i = 0; i < 4; i++) lines_add(nf[0].mangle, &nf[0].mangle_len, OLD_RULES[i]);
    for (int i = 0; i < 2; i++) lines_add(nf[1].mangle, &nf[1].mangle_len, OLD_RULES6[i]);
    assert(apply_unified_connmark_rules(t, 2, cfg, NULL) == 0);
    assert(rci_calls == 0 && restores[0][0] == 1 && restores[1][0] == 1);
    assert(strcmp(calls, "m4 m6 ") == 0);
    assert_mangle(0, 1, 0xff2, 0);
    assert_mangle(1, 0, 0xff2, 0);
    assert_raw(0, 0xff2);
    assert_raw(1, 0xff2);

    /* GlobalRouting=true drops the NDMS mark condition from R1. */
    reset();
    cfg->global_routing = 1;
    assert(apply_unified_connmark_rules(t, 2, cfg, NULL) == 0);
    assert(restores[0][0] == 1 && restores[1][0] == 1);
    assert_mangle(0, 1, 0xff2, 1);
    assert_mangle(1, 0, 0xff2, 1);
    cfg->global_routing = 0;
    assert(apply_unified_connmark_rules(t, 2, cfg, NULL) == 0);
    assert_mangle(0, 1, 0xff2, 0);
    assert_mangle(1, 0, 0xff2, 0);
}

static void check_failures(const unified_target_t *t, config_t *cfg) {
    /* A failed restore reports what iptables-restore said and is retried. */
    reset();
    restore_error = "iptables-restore: line 3 failed";
    mangle_remove_matching(0, "--match-set RU dst ");
    assert(apply_unified_connmark_rules(t, 2, cfg, NULL) == -1);
    assert(strstr(warn_log, "iptables-restore failed (exit 1): iptables-restore: line 3 failed"));
    assert(status_has("raw_guard=degraded:restore-v4"));
    assert_raw(0, 0xff2);                   /* a working chain is kept */
    restore_error = NULL;
    assert(apply_unified_connmark_rules(t, 2, cfg, NULL) == 0);
    assert_mangle(0, 1, 0xff2, 0);
    assert(status_has("raw_guard=on"));

    /* iptables -S fails or is truncated: nothing is written to that family,
     * and "no dump" is not taken for "no rules"; the other family is still
     * audited, and the next commit starts over. */
    reset();
    mangle_remove_matching(0, "--match-set RU dst ");
    mangle_remove_matching(1, "--match-set RU6 dst ");
    dump_fail[0] = 1;
    assert(apply_unified_connmark_rules(t, 2, cfg, NULL) == -1);
    assert(rci_calls == 0);
    assert(restores[0][0] == 0 && restores[1][0] == 1);
    assert(strstr(warn_log, "iptables -t mangle -S PREROUTING failed or output truncated"));
    assert(mangle_count(0, "--match-set RU dst ") == 0);
    assert_mangle(1, 0, 0xff2, 0);
    assert(status_has("raw_guard=degraded:dump-v4"));
    dump_fail[0] = 0;
    assert(apply_unified_connmark_rules(t, 2, cfg, NULL) == 0);
    assert_mangle(0, 1, 0xff2, 0);
    assert(status_has("raw_guard=on"));

    /* IPv4 goes in, ip6tables-restore fails: the commit fails, and the next
     * one replaces IPv6 only. */
    reset();
    mangle_remove_matching(0, "--match-set HydraRoute dst ");
    mangle_remove_matching(1, "--match-set HydraRoute6 dst ");
    restore_error = "ip6tables-restore: line 2 failed";
    restore_error_family = 1;
    assert(apply_unified_connmark_rules(t, 2, cfg, NULL) == -1);
    assert(restores[0][0] == 1 && restores[1][0] == 1);
    assert(warns == 2);                     /* the restore, the raw guard */
    assert(strstr(warn_log, "ip6tables-restore failed (exit 1): ip6tables-restore: line 2 failed"));
    assert(strstr(warn_log, "raw guard degraded: restore-v6"));
    assert(strcmp(calls, "m4 m6 ") == 0);
    assert_mangle(0, 1, 0xff2, 0);
    assert(mangle_count(1, "--match-set HydraRoute6 dst ") == 0);
    restore_error = NULL;
    restore_error_family = -1;
    reset();
    assert(apply_unified_connmark_rules(t, 2, cfg, NULL) == 0);
    assert(restores[0][0] == 0 && restores[1][0] == 1);
    assert_mangle(1, 0, 0xff2, 0);

    /* Rules that read back in another spelling: one WARN naming both lines,
     * the commit fails and is retried; no silent replace on every commit. */
    reset();
    echo_full_mask = 1;
    mangle_remove_matching(0, "--match-set ");
    assert(apply_unified_connmark_rules(t, 2, cfg, NULL) == -1);
    assert(apply_unified_connmark_rules(t, 2, cfg, NULL) == -1);
    assert(warns == 2);                     /* the read-back, the raw guard */
    assert(status_has("raw_guard=degraded:audit-v4"));
    assert(strstr(warn_log, "iptables: mangle PREROUTING differs after replace: expected '-A PREROUTING -m mark --mark 0xff1 "));
    assert(strstr(warn_log, "found '-A PREROUTING -m mark --mark 0xff1 -m conntrack --ctdir ORIGINAL -m connmark --mark 0x0/0xffffffff "));
    echo_full_mask = 0;
    assert(apply_unified_connmark_rules(t, 2, cfg, NULL) == 0);
    assert_mangle(0, 1, 0xff2, 0);
}

/* L7 on: the NFLOG rules in mangle FORWARD and OUTPUT ride in the same batch
 * as the replace, and once in place they are left alone. */
static void check_l7(const unified_target_t *t, const config_t *cfg) {
    reset();
    assert(apply_unified_connmark_rules(t, 2, cfg, "eth3") == 0);
    assert(restores[0][0] == 1 && restores[1][0] == 1);
    for (int fi = 0; fi < 2; fi++) {
        assert(nf[fi].fwd_len == 2 && nf[fi].out_len == 2);
        assert(strncmp(nf[fi].fwd[0], "-A FORWARD -o eth3 -p tcp --dport 443 ", 38) == 0);
        assert(strncmp(nf[fi].out[1], "-A OUTPUT -o eth3 -p tcp --dport 80 ", 36) == 0);
    }
    assert_mangle(0, 1, 0xff2, 0);
    assert_mangle(1, 0, 0xff2, 0);

    reset();
    assert(apply_unified_connmark_rules(t, 2, cfg, "eth3") == 0);
    assert(restores[0][0] == 0 && restores[1][0] == 0);

    /* A missing hrneo rule and a missing NFLOG rule: one restore for both. */
    reset();
    mangle_remove_matching(0, "--ctdir REPLY -m connmark --mark 0x0 -m set --match-set RU dst");
    lines_remove(nf[0].fwd, &nf[0].fwd_len, 0);
    assert(apply_unified_connmark_rules(t, 2, cfg, "eth3") == 0);
    assert(restores[0][0] == 1 && restores[1][0] == 0);
    assert_mangle(0, 1, 0xff2, 0);
    assert(nf[0].fwd_len == 2 && nf[0].out_len == 2);

    /* Only an hrneo rule missing: the NFLOG rules stay as they are. */
    reset();
    mangle_remove_matching(1, "--match-set HydraRoute6 dst -j CONNMARK --restore-mark");
    assert(apply_unified_connmark_rules(t, 2, cfg, "eth3") == 0);
    assert(restores[0][0] == 0 && restores[1][0] == 1);
    assert_mangle(1, 0, 0xff2, 0);
    assert(nf[1].fwd_len == 2 && nf[1].out_len == 2);
}

/* The raw chain HRNEO_GUARD (§3.1, §4): audited exactly on every commit,
 * replaced in one iptables-restore, and only after this call left mangle
 * known-good in both families. */
static void check_raw(const unified_target_t *t, config_t *cfg) {
    /* Chain flushed by someone and a second jump: one raw restore fixes both. */
    reset();
    nf[0].guard_len = 0;
    lines_add(nf[0].raw_pre, &nf[0].raw_pre_len, GUARD_JUMP);
    assert(apply_unified_connmark_rules(t, 2, cfg, NULL) == 0);
    assert(strcmp(calls, "r4 ") == 0);
    assert_raw(0, 0xff2);

    /* Jump gone, a foreign raw rule there: the jump comes back first. */
    reset();
    lines_remove(nf[1].raw_pre, &nf[1].raw_pre_len, 0);
    lines_add(nf[1].raw_pre, &nf[1].raw_pre_len, FOREIGN_RAW);
    assert(apply_unified_connmark_rules(t, 2, cfg, NULL) == 0);
    assert(strcmp(calls, "r6 ") == 0);
    assert_raw(1, 0xff2);
    assert(nf[1].raw_pre_len == 2 && strcmp(nf[1].raw_pre[1], FOREIGN_RAW) == 0);

    /* One jump, but behind a foreign rule: a packet that rule accepts never
     * reaches the chain. The jump moves to the front. */
    reset();
    lines_insert0(nf[0].raw_pre, &nf[0].raw_pre_len, FOREIGN_RAW);
    assert(apply_unified_connmark_rules(t, 2, cfg, NULL) == 0);
    assert(strcmp(calls, "r4 ") == 0);
    assert_raw(0, 0xff2);
    assert(nf[0].raw_pre_len == 2 && strcmp(nf[0].raw_pre[1], FOREIGN_RAW) == 0);

    /* Two jumps with foreign rules around and between them, neither first:
     * every own jump goes and one comes back first, in the same restore. */
    reset();
    lines_remove(nf[0].raw_pre, &nf[0].raw_pre_len, 0);
    lines_add(nf[0].raw_pre, &nf[0].raw_pre_len, GUARD_JUMP);
    lines_add(nf[0].raw_pre, &nf[0].raw_pre_len, FOREIGN_RAW2);
    lines_add(nf[0].raw_pre, &nf[0].raw_pre_len, GUARD_JUMP);
    assert(apply_unified_connmark_rules(t, 2, cfg, NULL) == 0);
    assert(strcmp(calls, "r4 ") == 0);
    assert_raw(0, 0xff2);
    assert(nf[0].raw_pre_len == 3);
    assert(strcmp(nf[0].raw_pre[1], FOREIGN_RAW) == 0 && strcmp(nf[0].raw_pre[2], FOREIGN_RAW2) == 0);

    /* A stale rule (another mark) in the chain is replaced. */
    reset();
    snprintf(nf[0].guard[0], LINE_LEN,
             "-A HRNEO_GUARD -m set --match-set HydraRoute dst -j MARK --set-xmark 0xff9/0xffffffff");
    assert(apply_unified_connmark_rules(t, 2, cfg, NULL) == 0);
    assert(strcmp(calls, "r4 ") == 0);
    assert_raw(0, 0xff2);

    /* A rule too many (a target no longer in the config) goes. */
    reset();
    lines_add(nf[1].guard, &nf[1].guard_len,
              "-A HRNEO_GUARD -m set --match-set Old6 dst -j MARK --set-xmark 0xff9/0xffffffff");
    assert(apply_unified_connmark_rules(t, 2, cfg, NULL) == 0);
    assert(strcmp(calls, "r6 ") == 0);
    assert_raw(1, 0xff2);

    /* Raw missing while the mangle replace fails: raw stays out and the
     * status names the cause; once mangle is confirmed, raw follows in the
     * same call. */
    reset();
    raw_clear(0);
    mangle_remove_matching(0, "--match-set ");
    restore_error = "iptables-restore: line 2 failed";
    assert(apply_unified_connmark_rules(t, 2, cfg, NULL) == -1);
    restore_error = NULL;
    assert(strcmp(calls, "m4 ") == 0);
    assert(!nf[0].guard_exists);
    assert(status_has("raw_guard=degraded:restore-v4") && status_has("raw_rules_v4=0"));
    reset();
    assert(apply_unified_connmark_rules(t, 2, cfg, NULL) == 0);
    assert(strcmp(calls, "m4 r4 ") == 0);
    assert_raw(0, 0xff2);
    assert(status_has("raw_guard=on"));

    /* IPv4 raw is missing and IPv4 mangle is fine, but the IPv6 replace
     * fails: raw goes in only once the whole mangle update went through,
     * both families. The IPv6 chain in place stays. */
    reset();
    raw_clear(0);
    mangle_remove_matching(1, "--match-set ");
    restore_error = "ip6tables-restore: line 2 failed";
    restore_error_family = 1;
    assert(apply_unified_connmark_rules(t, 2, cfg, NULL) == -1);
    restore_error = NULL;
    restore_error_family = -1;
    assert(strcmp(calls, "m6 ") == 0);
    assert(!nf[0].guard_exists);
    assert_raw(1, 0xff2);
    assert(status_has("raw_guard=degraded:restore-v6"));
    reset();
    assert(apply_unified_connmark_rules(t, 2, cfg, NULL) == 0);
    assert(strcmp(calls, "m6 r4 ") == 0);
    assert_mangle(1, 0, 0xff2, 0);
    assert_raw(0, 0xff2);
    assert(status_has("raw_guard=on"));

    /* Correction 1, case a: a working chain, an old unconditional restore of a
     * target back in mangle, and the mangle replace fails. Old R1 skips the
     * raw mark and old R2 writes connmark 0 over it on every new connection:
     * worse than no chain. The jump goes (the chain is emptied) in this call,
     * the one case hrneo takes raw down (§4.5); IPv6 is not touched. */
    reset();
    lines_add(nf[0].mangle, &nf[0].mangle_len, OLD_RULES[1]);
    restore_error = "iptables-restore: line 2 failed";
    restore_error_table = 0;
    assert(apply_unified_connmark_rules(t, 2, cfg, NULL) == -1);
    restore_error = NULL;
    restore_error_table = -1;
    assert(strcmp(calls, "m4 r4 ") == 0);
    assert(raw_jumps(0) == 0 && nf[0].guard_len == 0);
    assert(strstr(warn_log, "iptables: removed the jump to raw HRNEO_GUARD"));
    assert(status_has("raw_guard=degraded:old-restore-v4") && status_has("raw_rules_v4=0"));
    assert_raw(1, 0xff2);
    /* The replace goes through: mangle first, then the chain again. */
    reset();
    assert(apply_unified_connmark_rules(t, 2, cfg, NULL) == 0);
    assert(strcmp(calls, "m4 r4 ") == 0);
    assert_mangle(0, 1, 0xff2, 0);
    assert_raw(0, 0xff2);
    assert(status_has("raw_guard=on") && status_has("raw_rules_v4=2"));

    /* The same, and the raw restore that would take the jump out fails too:
     * the call fails and is retried; the retry fixes mangle, so the chain
     * that is still there stays. */
    reset();
    lines_add(nf[0].mangle, &nf[0].mangle_len, OLD_RULES[1]);
    restore_error = "iptables-restore: line 2 failed";
    assert(apply_unified_connmark_rules(t, 2, cfg, NULL) == -1);
    restore_error = NULL;
    assert(strcmp(calls, "m4 r4 ") == 0);
    assert(raw_jumps(0) == 1);
    assert(status_has("raw_guard=degraded:old-restore-v4"));
    reset();
    assert(apply_unified_connmark_rules(t, 2, cfg, NULL) == 0);
    assert(strcmp(calls, "m4 ") == 0);
    assert_mangle(0, 1, 0xff2, 0);
    assert_raw(0, 0xff2);
    assert(status_has("raw_guard=on"));

    /* L7 on: PREROUTING reads back with an old restore, then the FORWARD dump
     * fails (cut short by a large foreign chain, say). Mangle is not replaced
     * and raw cannot go in, but the jumps next to the old restore still go,
     * in both families (Ruling 29). */
    reset();
    lines_add(nf[0].mangle, &nf[0].mangle_len, OLD_RULES[1]);
    lines_add(nf[1].mangle, &nf[1].mangle_len, OLD_RULES6[1]);
    dump_fail_chain[0] = dump_fail_chain[1] = "FORWARD";
    assert(apply_unified_connmark_rules(t, 2, cfg, "eth3") == -1);
    dump_fail_chain[0] = dump_fail_chain[1] = NULL;
    assert(strcmp(calls, "r4 r6 ") == 0);
    assert(raw_jumps(0) == 0 && nf[0].guard_len == 0);
    assert(raw_jumps(1) == 0 && nf[1].guard_len == 0);
    assert(strstr(warn_log, "iptables -t mangle -S FORWARD failed or output truncated"));
    assert(strstr(warn_log, "ip6tables -t mangle -S FORWARD failed or output truncated"));
    assert(status_has("raw_guard=degraded:old-restore-v4"));
    reset();
    assert(apply_unified_connmark_rules(t, 2, cfg, "eth3") == 0);
    assert(strcmp(calls, "m4 m6 r4 r6 ") == 0);
    assert_mangle(0, 1, 0xff2, 0);
    assert_mangle(1, 0, 0xff2, 0);
    assert_raw(0, 0xff2);
    assert_raw(1, 0xff2);
    for (int fi = 0; fi < 2; fi++) assert(nf[fi].fwd_len == 2 && nf[fi].out_len == 2);
    assert(status_has("raw_guard=on"));

    /* An unconditional restore hrneo does not own: mangle cannot fix it, so
     * the jump goes and raw stays out, without retries or more log lines,
     * until the rule is gone. */
    reset();
    lines_add(nf[0].mangle, &nf[0].mangle_len, OLD_FOREIGN);
    assert(apply_unified_connmark_rules(t, 2, cfg, NULL) == 0);
    assert(strcmp(calls, "r4 ") == 0);
    assert(raw_jumps(0) == 0 && nf[0].guard_len == 0);
    assert(warns == 2);                     /* the removal, the raw guard */
    assert(status_has("raw_guard=degraded:old-restore-v4"));
    reset();
    assert(apply_unified_connmark_rules(t, 2, cfg, NULL) == 0);
    assert(calls[0] == '\0' && warns == 0);
    mangle_remove_matching(0, "--match-set Old dst ");
    reset();
    assert(apply_unified_connmark_rules(t, 2, cfg, NULL) == 0);
    assert(strcmp(calls, "r4 ") == 0);
    assert_raw(0, 0xff2);
    assert(status_has("raw_guard=on"));

    /* What an earlier call saw does not count in the next one: the foreign
     * restore is gone and the chain is back (put in by hand), then the mangle
     * read fails. Nothing is known about this call's mangle, so the working
     * jump stays. */
    reset();
    raw_clear(0);
    lines_add(nf[0].mangle, &nf[0].mangle_len, OLD_FOREIGN);
    assert(apply_unified_connmark_rules(t, 2, cfg, NULL) == 0);
    assert(calls[0] == '\0' && status_has("raw_guard=degraded:old-restore-v4"));
    mangle_remove_matching(0, "--match-set Old dst ");
    raw_clear(0);
    nf[0].guard_exists = 1;
    lines_add(nf[0].guard, &nf[0].guard_len, HR_RAW[0]);
    lines_add(nf[0].guard, &nf[0].guard_len,
              "-A HRNEO_GUARD -m set --match-set RU dst -j MARK --set-xmark 0xff1/0xffffffff");
    lines_insert0(nf[0].raw_pre, &nf[0].raw_pre_len, GUARD_JUMP);
    reset();
    dump_fail[0] = 1;
    assert(apply_unified_connmark_rules(t, 2, cfg, NULL) == -1);
    dump_fail[0] = 0;
    assert(calls[0] == '\0');
    assert_raw(0, 0xff2);
    assert(status_has("raw_guard=degraded:dump-v4"));
    reset();
    assert(apply_unified_connmark_rules(t, 2, cfg, NULL) == 0);
    assert(calls[0] == '\0' && status_has("raw_guard=on"));

    /* Any unconditional restore left in mangle keeps raw from going in, in
     * either family: IPv6 has one, IPv4 raw is missing and stays out. */
    reset();
    raw_clear(0);
    lines_add(nf[1].mangle, &nf[1].mangle_len, OLD_FOREIGN6);
    assert(apply_unified_connmark_rules(t, 2, cfg, NULL) == 0);
    assert(strcmp(calls, "r6 ") == 0);
    assert(!nf[0].guard_exists);
    assert(raw_jumps(1) == 0 && nf[1].guard_len == 0);
    assert(status_has("raw_guard=degraded:old-restore-v6"));
    mangle_remove_matching(1, "--match-set Old6 dst ");
    reset();
    assert(apply_unified_connmark_rules(t, 2, cfg, NULL) == 0);
    assert(strcmp(calls, "r4 r6 ") == 0);
    assert_raw(0, 0xff2);
    assert_raw(1, 0xff2);
    assert(status_has("raw_guard=on"));

    /* The raw restore fails: the status names it, and the call is retried. */
    reset();
    nf[0].guard_len = 0;
    restore_error = "iptables-restore: line 3 failed";
    restore_error_table = 1;
    assert(apply_unified_connmark_rules(t, 2, cfg, NULL) == -1);
    restore_error = NULL;
    restore_error_table = -1;
    assert(strcmp(calls, "r4 ") == 0);
    assert(nf[0].guard_len == 0);
    assert(strstr(warn_log, "iptables-restore failed (exit 1): iptables-restore: line 3 failed"));
    assert(status_has("raw_guard=degraded:restore-v4"));
    reset();
    assert(apply_unified_connmark_rules(t, 2, cfg, NULL) == 0);
    assert(strcmp(calls, "r4 ") == 0);
    assert_raw(0, 0xff2);
    assert(status_has("raw_guard=on"));

    /* The chain reads back in another spelling: one WARN naming both lines,
     * the call fails and is retried, no WARN per retry. */
    reset();
    raw_echo_other = 1;
    nf[0].guard_len = 0;
    assert(apply_unified_connmark_rules(t, 2, cfg, NULL) == -1);
    assert(apply_unified_connmark_rules(t, 2, cfg, NULL) == -1);
    assert(strcmp(calls, "r4 r4 ") == 0);
    assert(warns == 2);                     /* the read-back, the raw guard */
    assert(strstr(warn_log, "iptables: raw HRNEO_GUARD differs after replace"));
    assert(strstr(warn_log, "expected '-A HRNEO_GUARD -m set --match-set HydraRoute dst -j MARK --set-xmark 0xff2/0xffffffff'"));
    assert(strstr(warn_log, "found '-A HRNEO_GUARD -m set --match-set HydraRoute dst -j MARK --set-xmark 0xff2'"));
    assert(status_has("raw_guard=degraded:audit-v4") && status_has("raw_rules_v4=2"));
    raw_echo_other = 0;
    reset();
    assert(apply_unified_connmark_rules(t, 2, cfg, NULL) == 0);
    assert(strcmp(calls, "r4 ") == 0);
    assert_raw(0, 0xff2);
    assert(status_has("raw_guard=on"));

    /* The raw dump fails or is cut short while the kernel lists the table:
     * nothing is written to raw, "no dump" is not taken for "no chain", the
     * count is unknown, not 0, and the call is retried. */
    reset();
    raw_dump_fail[0] = 1;
    assert(apply_unified_connmark_rules(t, 2, cfg, NULL) == -1);
    assert(apply_unified_connmark_rules(t, 2, cfg, NULL) == -1);
    assert(calls[0] == '\0' && proc_calls == 2);
    assert(warns == 2);                     /* the dump once, the raw guard */
    assert(strstr(warn_log, "iptables -t raw -S failed or output truncated"));
    assert(status_has("raw_guard=degraded:dump-v4"));
    assert(status_has("raw_rules_v4=unknown") && status_has("raw_rules_v6=2"));
    raw_dump_fail[0] = 0;
    reset();
    assert(apply_unified_connmark_rules(t, 2, cfg, NULL) == 0);
    assert(calls[0] == '\0');
    assert(status_has("raw_guard=on") && status_has("raw_rules_v4=2"));

    /* Only IPv6 fails: IPv4 is put right in the same call, the next call
     * puts IPv6 right. */
    reset();
    nf[0].guard_len = 0;
    nf[1].guard_len = 0;
    restore_error = "ip6tables-restore: line 2 failed";
    restore_error_family = 1;
    restore_error_table = 1;
    assert(apply_unified_connmark_rules(t, 2, cfg, NULL) == -1);
    restore_error = NULL;
    restore_error_family = restore_error_table = -1;
    assert(strcmp(calls, "r4 r6 ") == 0);
    assert_raw(0, 0xff2);
    assert(nf[1].guard_len == 0);
    assert(status_has("raw_guard=degraded:restore-v6") && status_has("raw_rules_v6=0"));
    reset();
    assert(apply_unified_connmark_rules(t, 2, cfg, NULL) == 0);
    assert(strcmp(calls, "r6 ") == 0);
    assert_raw(1, 0xff2);
    assert(strstr(warn_log, "raw guard on again (was degraded: restore-v6)"));

    /* RawGuard=false: raw is not read or written and the status says off. In
     * this version the chain in place is left alone (raw-off is Task 4). */
    reset();
    cfg->raw_guard = 0;
    raw_clear(0);
    assert(apply_unified_connmark_rules(t, 2, cfg, NULL) == 0);
    assert(calls[0] == '\0' && dumps == 2);
    assert(!nf[0].guard_exists);
    assert_raw(1, 0xff2);
    assert(status_has("raw_guard=off"));
    assert(status_has("raw_rules_v4=unknown") && status_has("raw_rules_v6=unknown"));
    cfg->raw_guard = 1;
    reset();
    assert(apply_unified_connmark_rules(t, 2, cfg, NULL) == 0);
    assert(strcmp(calls, "r4 ") == 0);
    assert_raw(0, 0xff2);
    assert(status_has("raw_guard=on"));
}

/* A DirectRoute interface target: its mark is its fwmark (no RCI), it has no
 * raw mark and so no R0; the stop removes its R1..R3 with the rest. */
static void check_interface_target(const unified_target_t *t, const config_t *cfg) {
    unified_target_t t3[3];
    targets_with_wg0(t3, t);

    reset();
    assert(apply_unified_connmark_rules(t3, 3, cfg, NULL) == 0);
    assert(rci_calls == 0);
    assert(restores[0][0] == 1 && restores[1][0] == 1);
    assert(strcmp(calls, "m4 m6 ") == 0);   /* not marked early: raw is unchanged */
    assert_raw(0, 0xff2);
    assert_raw(1, 0xff2);
    for (int fi = 0; fi < 2; fi++) {
        const char *set = fi ? t3[2].pair.ipv6 : t3[2].pair.ipv4;
        int pos = expect_mangle_rules(fi, fi ? 0 : 1, 3, 0xff2, 0);
        assert(nf[fi].mangle_len == pos + 3);
        for (int k = 1; k < GUARD_MANGLE_RULES; k++) {
            char want[GUARD_LINE_MAX];
            assert(guard_mangle_rule(want, sizeof(want), k, set, 0x3001, 1, 0) > 0);
            assert(strcmp(nf[fi].mangle[pos + k - 1], want) == 0);
        }
        assert(mangle_count(fi, "-m mark --mark 0x3001 ") == 0);
    }

    /* wg0's ip rule is hrneo's own, not an NDMS policy's: not checked. */
    reset();
    assert(apply_unified_connmark_rules(t3, 3, cfg, NULL) == 0);
    assert(rci_calls == 0 && restores[0][0] == 0 && restores[1][0] == 0);
    assert(rule_dumps == 1 && warns == 0);

    ipset_pair_t pairs[3] = {t3[0].pair, t3[1].pair, t3[2].pair};
    reset();
    assert(cleanup_connmark_rules(pairs, 3) == 0);
    assert(restores[0][0] == 1 && restores[1][0] == 1);
    assert(nf[0].mangle_len == 1 && strcmp(nf[0].mangle[0], NDM_LINE) == 0);
    assert(nf[1].mangle_len == 0);
    assert_raw(0, 0xff2);                   /* the stop leaves raw in place (§4.5) */
    assert_raw(1, 0xff2);
}

/* More rules than one batch holds: the replace is never split into several
 * commits; nothing is sent, the rules stay as they are, the cause is named. */
static void check_overflow(const unified_target_t *t, const config_t *cfg) {
    static unified_target_t big[MAX_TARGETS];
    const char *p;
    size_t need = 0, avail = 0;

    reset();
    assert(apply_unified_connmark_rules(t, 2, cfg, NULL) == 0);
    assert_mangle(0, 1, 0xff2, 0);
    assert_mangle(1, 0, 0xff2, 0);

    targets_with_wg0(big, t);
    for (int i = 3; i < MAX_TARGETS; i++) {
        snprintf(big[i].pair.ipv4, sizeof(big[i].pair.ipv4), "Policy%03d_with_a_long_name", i);
        snprintf(big[i].pair.ipv6, sizeof(big[i].pair.ipv6), "%sv6", big[i].pair.ipv4);
    }
    reset();
    assert(apply_unified_connmark_rules(big, MAX_TARGETS, cfg, NULL) == -1);
    assert(restores[0][0] == 0 && restores[1][0] == 0);
    assert(calls[0] == '\0');               /* raw neither: mangle is not confirmed */
    assert(status_has("raw_guard=degraded:batch-overflow-v4"));
    assert_raw(0, 0xff2);
    assert_raw(1, 0xff2);
    assert(errors == 2);
    p = strstr(error_log, "mangle batch overflow (");
    assert(p && sscanf(p, "mangle batch overflow (%zu bytes needed, %zu available)", &need, &avail) == 2);
    assert(need > IPT_BATCH_SIZE && avail == IPT_BATCH_SIZE);
    assert_mangle(0, 1, 0xff2, 0);
    assert_mangle(1, 0, 0xff2, 0);
}

/* HydraRoute deleted and created again in NDMS with a new mark: its ip rule
 * "fwmark <mark> lookup <table>" now carries that mark. */
static void recreate_hr(uint32_t mark, const char *hex) {
    fake_rules[1].mark = mark;
    mark_hr = hex;
}

/* §4.4: a policy recreated in NDMS (new mark) or deleted shows as its ip rule
 * gone. Every commit after the start dumps the IPv4 rules once and asks RCI
 * only for a policy whose rule is missing. */
static void check_policy_mark_change(const unified_target_t *t, config_t *cfg) {
    /* Rule in place: one rule dump per commit, no RCI. */
    reset();
    mangle_remove_matching(0, "--match-set ");
    assert(apply_unified_connmark_rules(t, 2, cfg, NULL) == 0);
    assert(rci_calls == 0 && rule_dumps == 1);
    assert(strcmp(calls, "m4 ") == 0);

    /* The dump failed: unknown is not a change. Nothing is asked or
     * removed; one WARN until a dump works again. */
    reset();
    fake_rule_count = -1;
    assert(apply_unified_connmark_rules(t, 2, cfg, NULL) == 0);
    assert(apply_unified_connmark_rules(t, 2, cfg, NULL) == 0);
    assert(rule_dumps == 2 && rci_calls == 0 && calls[0] == '\0');
    assert(warns == 1 && strstr(warn_log, "ip rule dump failed"));
    fake_rule_count = 2;
    reset();
    assert(apply_unified_connmark_rules(t, 2, cfg, NULL) == 0);
    assert(warns == 0);
    fake_rule_count = -1;
    reset();
    assert(apply_unified_connmark_rules(t, 2, cfg, NULL) == 0);
    assert(warns == 1);                     /* a new episode */
    fake_rule_count = 2;

    /* HydraRoute recreated with mark 0xff3: the rule for 0xff2 is gone, RCI
     * gives the new mark, mangle then raw are rebuilt in this commit. */
    reset();
    recreate_hr(0xff3, "ff3");
    assert(apply_unified_connmark_rules(t, 2, cfg, NULL) == 0);
    assert(rci_calls == 1 && rule_dumps == 1);
    assert(strcmp(calls, "m4 m6 r4 r6 ") == 0);
    assert(warns == 2);
    assert(strstr(warn_log, "Policy HydraRoute: no ip rule for fwmark 0xff2, reading its mark again"));
    assert(strstr(warn_log, "Policy HydraRoute mark changed: 0xff2 -> 0xff3, replacing its rules"));
    assert_mangle(0, 1, 0xff3, 0);
    assert_mangle(1, 0, 0xff3, 0);
    assert_raw(0, 0xff3);
    assert_raw(1, 0xff3);
    assert(status_has("raw_guard=on"));

    /* Steady with the new mark. */
    reset();
    assert(apply_unified_connmark_rules(t, 2, cfg, NULL) == 0);
    assert(rci_calls == 0 && calls[0] == '\0' && warns == 0 && rule_dumps == 1);

    /* Rule missing while RCI still says 0xff3: the rules stay, RCI on each
     * commit, one WARN for the whole episode. */
    reset();
    fake_rule_count = 1;
    for (int pass = 0; pass < 3; pass++)
        assert(apply_unified_connmark_rules(t, 2, cfg, NULL) == 0);
    assert(rci_calls == 3 && calls[0] == '\0' && warns == 1);

    /* The rule is back: the episode ends; gone again: a new one. */
    reset();
    fake_rule_count = 2;
    assert(apply_unified_connmark_rules(t, 2, cfg, NULL) == 0);
    assert(rci_calls == 0 && warns == 0);
    fake_rule_count = 1;
    assert(apply_unified_connmark_rules(t, 2, cfg, NULL) == 0);
    assert(rci_calls == 1 && warns == 1);

    /* RCI unreachable, then denied, while the rule is missing: no answer is
     * not "no mark". The known mark and its rules stay, the commit is
     * retried; one WARN per cause. */
    reset();
    rci_result_hr = RCI_MARK_TRANSPORT;
    assert(apply_unified_connmark_rules(t, 2, cfg, NULL) == -1);
    assert(apply_unified_connmark_rules(t, 2, cfg, NULL) == -1);
    assert(rci_calls == 2 && calls[0] == '\0');
    assert(warns == 1 && strstr(warn_log, "RCI unreachable while reading policy HydraRoute"));
    reset();
    rci_result_hr = RCI_MARK_DENIED;
    assert(apply_unified_connmark_rules(t, 2, cfg, NULL) == -1);
    assert(rci_calls == 1 && calls[0] == '\0');
    assert(warns == 1 && strstr(warn_log, "RCI denied reading policy HydraRoute"));
    rci_result_hr = RCI_MARK_OK;

    /* RCI answers, but not with a mark: no answer either (Ruling 33). */
    reset();
    mark_hr = "zz";
    assert(apply_unified_connmark_rules(t, 2, cfg, NULL) == -1);
    assert(rci_calls == 1 && calls[0] == '\0');
    assert(warns == 1 && strstr(warn_log, "RCI unreachable while reading policy HydraRoute"));
    mark_hr = "ff3";
    assert_mangle(0, 1, 0xff3, 0);
    assert_mangle(1, 0, 0xff3, 0);
    assert_raw(0, 0xff3);
    assert_raw(1, 0xff3);
    assert(status_has("raw_guard=on"));

    /* Policy deleted: RCI has no mark, its rules leave mangle and raw. */
    reset();
    rci_result = RCI_MARK_ABSENT;
    assert(apply_unified_connmark_rules(t, 2, cfg, NULL) == -1);
    assert(rci_calls == 1);                 /* RU's rule is there: RU is not asked */
    assert(strstr(warn_log, "Policy HydraRoute has no mark ID yet"));
    assert(strcmp(calls, "m4 m6 r4 r6 ") == 0);
    assert(mangle_count(0, "--match-set HydraRoute dst ") == 0);
    assert(mangle_count(0, "--match-set RU dst ") == 4);
    assert_mangle_of(0, 1, 1, 0, 0);
    assert_mangle_of(1, 0, 1, 0, 0);
    assert_raw_of(0, 1, 0);
    assert_raw_of(1, 1, 0);
    assert(nf[0].guard_len == 1 && nf[1].guard_len == 1);

    /* Policy back: its rules return. */
    reset();
    rci_result = RCI_MARK_OK;
    fake_rule_count = 2;
    assert(apply_unified_connmark_rules(t, 2, cfg, NULL) == 0);
    assert(rci_calls == 1);
    assert(strcmp(calls, "m4 m6 r4 r6 ") == 0);
    assert_mangle(0, 1, 0xff3, 0);
    assert_mangle(1, 0, 0xff3, 0);
    assert_raw(0, 0xff3);
    assert_raw(1, 0xff3);

    /* Recreated again (0xffa) before NDMS put in its new rule: the new mark
     * is used at once, and its missing rule is an episode of its own, with
     * its own WARN. Then the rule shows up; recreated as 0xff3 for what
     * follows. */
    reset();
    recreate_hr(0xffa, "ffa");
    fake_rule_count = 1;
    for (int pass = 0; pass < 3; pass++)
        assert(apply_unified_connmark_rules(t, 2, cfg, NULL) == 0);
    assert(rci_calls == 3 && warns == 3);
    assert(strstr(warn_log, "Policy HydraRoute mark changed: 0xff3 -> 0xffa"));
    assert(strstr(warn_log, "Policy HydraRoute: no ip rule for fwmark 0xffa, reading its mark again"));
    assert_mangle(0, 1, 0xffa, 0);
    assert_raw(0, 0xffa);
    reset();
    fake_rule_count = 2;
    assert(apply_unified_connmark_rules(t, 2, cfg, NULL) == 0);
    assert(rci_calls == 0 && warns == 0 && calls[0] == '\0');
    reset();
    recreate_hr(0xff3, "ff3");
    assert(apply_unified_connmark_rules(t, 2, cfg, NULL) == 0);
    assert(rci_calls == 1 && strcmp(calls, "m4 m6 r4 r6 ") == 0);
    assert_raw(0, 0xff3);
}

/* A new mark goes through the same mangle -> raw gate as any other change:
 * each failure names its cause, keeps raw as it was (the old mark) unless
 * the one safety step applies, and the retry finishes the job without
 * asking RCI again. */
static void check_mark_change_failures(const unified_target_t *t, config_t *cfg) {
    /* The mangle replace fails in both families: raw stays out of it. */
    reset();
    recreate_hr(0xff4, "ff4");
    restore_error = "iptables-restore: line 5 failed";
    restore_error_table = 0;
    assert(apply_unified_connmark_rules(t, 2, cfg, NULL) == -1);
    restore_error = NULL;
    restore_error_table = -1;
    assert(rci_calls == 1 && strcmp(calls, "m4 m6 ") == 0);
    assert(warns == 5);                     /* no rule, new mark, two restores, the raw guard */
    assert(strstr(warn_log, "Policy HydraRoute mark changed: 0xff3 -> 0xff4"));
    assert(status_has("raw_guard=degraded:restore-v4") && status_has("raw_rules_v4=2"));
    assert_mangle(0, 1, 0xff3, 0);
    assert_raw(0, 0xff3);
    assert_raw(1, 0xff3);
    reset();
    assert(apply_unified_connmark_rules(t, 2, cfg, NULL) == 0);
    assert(rci_calls == 0 && strcmp(calls, "m4 m6 r4 r6 ") == 0);
    assert(warns == 1 && strstr(warn_log, "raw guard on again (was degraded: restore-v4)"));
    assert_mangle(0, 1, 0xff4, 0);
    assert_mangle(1, 0, 0xff4, 0);
    assert_raw(0, 0xff4);
    assert_raw(1, 0xff4);

    /* The new mangle rules read back in another spelling. */
    reset();
    recreate_hr(0xff5, "ff5");
    echo_full_mask = 1;
    assert(apply_unified_connmark_rules(t, 2, cfg, NULL) == -1);
    echo_full_mask = 0;
    assert(rci_calls == 1 && strcmp(calls, "m4 m6 ") == 0);
    assert(warns == 5);                     /* no rule, new mark, two read-backs, the raw guard */
    assert(strstr(warn_log, "iptables: mangle PREROUTING differs after replace"));
    assert(status_has("raw_guard=degraded:audit-v4"));
    assert_raw(0, 0xff4);
    assert_raw(1, 0xff4);
    reset();
    assert(apply_unified_connmark_rules(t, 2, cfg, NULL) == 0);
    assert(rci_calls == 0 && strcmp(calls, "m4 m6 r4 r6 ") == 0);
    assert_mangle(0, 1, 0xff5, 0);
    assert_mangle(1, 0, 0xff5, 0);
    assert_raw(0, 0xff5);
    assert_raw(1, 0xff5);
    assert(status_has("raw_guard=on"));

    /* Mangle goes through, the raw restore fails in both families. */
    reset();
    recreate_hr(0xff6, "ff6");
    restore_error = "iptables-restore: line 3 failed";
    restore_error_table = 1;
    assert(apply_unified_connmark_rules(t, 2, cfg, NULL) == -1);
    restore_error = NULL;
    restore_error_table = -1;
    assert(rci_calls == 1 && strcmp(calls, "m4 m6 r4 r6 ") == 0);
    assert(warns == 5);                     /* no rule, new mark, two restores, the raw guard */
    assert(status_has("raw_guard=degraded:restore-v4"));
    assert(status_has("raw_rules_v4=2") && status_has("raw_rules_v6=2"));
    assert_mangle(0, 1, 0xff6, 0);
    assert_raw(0, 0xff5);
    assert_raw(1, 0xff5);
    reset();
    assert(apply_unified_connmark_rules(t, 2, cfg, NULL) == 0);
    assert(rci_calls == 0 && strcmp(calls, "r4 r6 ") == 0);
    assert_raw(0, 0xff6);
    assert_raw(1, 0xff6);
    assert(status_has("raw_guard=on"));

    /* The new chain reads back in another spelling. */
    reset();
    recreate_hr(0xff7, "ff7");
    raw_echo_other = 1;
    assert(apply_unified_connmark_rules(t, 2, cfg, NULL) == -1);
    raw_echo_other = 0;
    assert(rci_calls == 1 && strcmp(calls, "m4 m6 r4 r6 ") == 0);
    assert(warns == 5);                     /* no rule, new mark, two read-backs, the raw guard */
    assert(strstr(warn_log, "iptables: raw HRNEO_GUARD differs after replace"));
    assert(status_has("raw_guard=degraded:audit-v4"));
    reset();
    assert(apply_unified_connmark_rules(t, 2, cfg, NULL) == 0);
    assert(rci_calls == 0 && strcmp(calls, "r4 r6 ") == 0);
    assert_raw(0, 0xff7);
    assert_raw(1, 0xff7);
    assert(status_has("raw_guard=on"));

    /* Only IPv6 fails: IPv4 mangle has the new mark, but raw waits for the
     * whole mangle update in both families. */
    reset();
    recreate_hr(0xff8, "ff8");
    restore_error = "ip6tables-restore: line 2 failed";
    restore_error_family = 1;
    assert(apply_unified_connmark_rules(t, 2, cfg, NULL) == -1);
    restore_error = NULL;
    restore_error_family = -1;
    assert(rci_calls == 1 && strcmp(calls, "m4 m6 ") == 0);
    assert(warns == 4);                     /* no rule, new mark, the restore, the raw guard */
    assert(status_has("raw_guard=degraded:restore-v6"));
    assert_mangle(0, 1, 0xff8, 0);
    assert_mangle(1, 0, 0xff7, 0);
    assert_raw(0, 0xff7);
    assert_raw(1, 0xff7);
    reset();
    assert(apply_unified_connmark_rules(t, 2, cfg, NULL) == 0);
    assert(rci_calls == 0 && strcmp(calls, "m6 r4 r6 ") == 0);
    assert_mangle(1, 0, 0xff8, 0);
    assert_raw(0, 0xff8);
    assert_raw(1, 0xff8);
    assert(status_has("raw_guard=on"));

    /* The new mark comes with an old unconditional restore back in IPv4
     * mangle, and the mangle replace fails: the IPv4 jump goes in this call
     * (Ruling 9); IPv6 keeps its chain. The retry puts everything right
     * with the new mark. */
    reset();
    recreate_hr(0xff2, "ff2");
    lines_add(nf[0].mangle, &nf[0].mangle_len, OLD_RULES[1]);
    restore_error = "iptables-restore: line 2 failed";
    restore_error_table = 0;
    assert(apply_unified_connmark_rules(t, 2, cfg, NULL) == -1);
    restore_error = NULL;
    restore_error_table = -1;
    assert(rci_calls == 1 && strcmp(calls, "m4 m6 r4 ") == 0);
    assert(warns == 6);                     /* no rule, new mark, two restores, the removal, the raw guard */
    assert(strstr(warn_log, "iptables: removed the jump to raw HRNEO_GUARD"));
    assert(raw_jumps(0) == 0 && nf[0].guard_len == 0);
    assert_raw(1, 0xff8);
    assert(status_has("raw_guard=degraded:old-restore-v4") && status_has("raw_rules_v4=0"));
    reset();
    assert(apply_unified_connmark_rules(t, 2, cfg, NULL) == 0);
    assert(rci_calls == 0 && strcmp(calls, "m4 m6 r4 r6 ") == 0);
    assert_mangle(0, 1, 0xff2, 0);
    assert_mangle(1, 0, 0xff2, 0);
    assert_raw(0, 0xff2);
    assert_raw(1, 0xff2);
    assert(status_has("raw_guard=on"));
}

static void check_cleanup(const unified_target_t *t, const config_t *cfg) {
    ipset_pair_t pairs[2] = {t[0].pair, t[1].pair};

    /* A failed stop says so and leaves the rules whole. */
    reset();
    restore_error = "iptables-restore: line 2 failed";
    assert(cleanup_connmark_rules(pairs, 2) == -1);
    restore_error = NULL;
    assert(restores[0][0] == 1 && restores[1][0] == 1);
    assert(strstr(warn_log, "CONNMARK rules cleanup incomplete"));
    assert_mangle(0, 1, 0xff2, 0);
    assert_mangle(1, 0, 0xff2, 0);

    /* No IPv6 dump: IPv6 keeps its rules, the stop reports it. */
    reset();
    dump_fail[1] = 1;
    assert(cleanup_connmark_rules(pairs, 2) == -1);
    dump_fail[1] = 0;
    assert(restores[0][0] == 1 && restores[1][0] == 0);
    assert(nf[0].mangle_len == 1);
    assert_mangle(1, 0, 0xff2, 0);
    assert(apply_unified_connmark_rules(t, 2, cfg, NULL) == 0);
    assert_mangle(0, 1, 0xff2, 0);

    /* Stop: every hrneo rule leaves in one restore per family, others stay. */
    reset();
    assert(cleanup_connmark_rules(pairs, 2) == 0);
    assert(restores[0][0] == 1 && restores[1][0] == 1);
    assert(nf[0].mangle_len == 1 && strcmp(nf[0].mangle[0], NDM_LINE) == 0);
    assert(nf[1].mangle_len == 0);
    for (int fi = 0; fi < 2; fi++) assert(nf[fi].fwd_len == 2 && nf[fi].out_len == 2);
}

int main(void) {
    config_t cfg;
    unified_target_t t[2];
    setup_targets(t, &cfg);
    cfg.raw_guard = 1;
    remove(STATUS_PATH);
    guard_status_init(STATUS_PATH);
    check_start_and_migration(t, &cfg);
    check_audit(t, &cfg);
    check_failures(t, &cfg);
    check_l7(t, &cfg);
    check_raw(t, &cfg);
    check_interface_target(t, &cfg);
    check_overflow(t, &cfg);
    check_policy_mark_change(t, &cfg);
    check_mark_change_failures(t, &cfg);
    check_cleanup(t, &cfg);
    puts("check_connmark: OK");
    return 0;
}
