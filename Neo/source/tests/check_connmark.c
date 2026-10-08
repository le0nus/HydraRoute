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

    /* xt_conntrack does not load: nothing is touched, the next commit tries again. */
    reset();
    kmod_result = -1;
    assert(apply_unified_connmark_rules(t, 2, cfg, NULL) == -1);
    assert(kmod_calls == 1 && dumps == 0 && rci_calls == 0);
    assert(restores[0][0] == 0 && restores[1][0] == 0);
    kmod_result = 0;

    /* RCI down at start: no mark is known; the old rules are kept as written,
     * only put in PolicyOrder (RU first). */
    reset();
    rci_result = RCI_MARK_TRANSPORT;
    assert(apply_unified_connmark_rules(t, 2, cfg, NULL) == -1);
    assert(kmod_calls == 1);
    assert(warns == 2);
    assert(restores[0][0] == 1 && restores[1][0] == 0);
    assert(nf[0].mangle_len == 5);
    assert(strcmp(nf[0].mangle[1], OLD_RULES[2]) == 0 && strcmp(nf[0].mangle[2], OLD_RULES[3]) == 0);
    assert(strcmp(nf[0].mangle[3], OLD_RULES[0]) == 0 && strcmp(nf[0].mangle[4], OLD_RULES[1]) == 0);
    assert(nf[1].mangle_len == 2);

    /* Still down: both policies are asked again, the cause is a WARN only once. */
    reset();
    assert(apply_unified_connmark_rules(t, 2, cfg, NULL) == -1);
    assert(kmod_calls == 0 && rci_calls == 2 && warns == 0);
    assert(restores[0][0] == 0 && restores[1][0] == 0);

    /* HydraRoute has no mark (RCI_MARK_ABSENT): its rules leave both
     * families; RU moves to R0..R3. */
    reset();
    rci_result = RCI_MARK_OK;
    rci_result_hr = RCI_MARK_ABSENT;
    assert(apply_unified_connmark_rules(t, 2, cfg, NULL) == -1);
    assert(rci_calls == 2 && warns == 1);
    assert(strstr(warn_log, "Policy HydraRoute has no mark ID yet"));
    assert(restores[0][0] == 1 && restores[1][0] == 1);
    assert(strcmp(nf[0].mangle[0], NDM_LINE) == 0);
    assert_mangle_of(0, 1, 1, 0, 0);
    assert_mangle_of(1, 0, 1, 0, 0);

    /* The same again: no WARN, nothing to change. */
    reset();
    assert(apply_unified_connmark_rules(t, 2, cfg, NULL) == -1);
    assert(rci_calls == 2 && warns == 0);
    assert(restores[0][0] == 0 && restores[1][0] == 0);

    /* HydraRoute gets its mark, which RCI spells with a leading zero and
     * capitals; RCI fails for RU, which keeps the rules of its known mark. */
    reset();
    rci_result_ru = RCI_MARK_TRANSPORT;
    rci_result_hr = RCI_MARK_OK;
    mark_hr = "0FF2";
    assert(apply_unified_connmark_rules(t, 2, cfg, NULL) == -1);
    assert(warns == 1 && strstr(warn_log, "RCI unreachable while reading policy RU"));
    assert(restores[0][0] == 1 && restores[1][0] == 1);
    assert_mangle(0, 1, 0xff2, 0);
    assert_mangle(1, 0, 0xff2, 0);

    /* Once the policy worked, a new failure is reported again. */
    reset();
    rci_result_hr = RCI_MARK_ABSENT;
    assert(apply_unified_connmark_rules(t, 2, cfg, NULL) == -1);
    assert(warns == 1 && strstr(warn_log, "Policy HydraRoute has no mark ID yet"));
    assert(restores[0][0] == 1 && restores[1][0] == 1);
    assert_mangle_of(0, 1, 1, 0, 0);
    assert_mangle_of(1, 0, 1, 0, 0);

    /* RCI answers for both: one replace per family, and the start is over. */
    reset();
    rci_result_ru = rci_result_hr = RCI_MARK_OK;
    assert(apply_unified_connmark_rules(t, 2, cfg, NULL) == 0);
    mark_hr = "ff2";
    assert(rci_calls == 2 && warns == 0);
    assert(restores[0][0] == 1 && restores[1][0] == 1);
    assert(strcmp(nf[0].mangle[0], NDM_LINE) == 0);
    assert_mangle(0, 1, 0xff2, 0);
    assert_mangle(1, 0, 0xff2, 0);
}

static void check_audit(const unified_target_t *t, config_t *cfg) {
    /* Nothing changed: no RCI, no restore. */
    reset();
    assert(apply_unified_connmark_rules(t, 2, cfg, NULL) == 0);
    assert(rci_calls == 0 && restores[0][0] == 0 && restores[1][0] == 0);

    /* NDMS rebuilt mangle without hrneo's rules: back from the known marks, no RCI. */
    reset();
    mangle_remove_matching(0, "--match-set ");
    assert(apply_unified_connmark_rules(t, 2, cfg, NULL) == 0);
    assert(rci_calls == 0 && restores[0][0] == 1 && restores[1][0] == 0);
    assert_mangle(0, 1, 0xff2, 0);

    /* One rule missing. */
    reset();
    mangle_remove_matching(1, "--ctdir REPLY -m connmark --mark 0x0 -m set --match-set RU6 dst");
    assert(apply_unified_connmark_rules(t, 2, cfg, NULL) == 0);
    assert(restores[1][0] == 1);
    assert_mangle(1, 0, 0xff2, 0);

    /* A stray old unconditional restore. */
    reset();
    lines_add(nf[0].mangle, &nf[0].mangle_len, OLD_RULES[1]);
    assert(apply_unified_connmark_rules(t, 2, cfg, NULL) == 0);
    assert(restores[0][0] == 1);
    assert_mangle(0, 1, 0xff2, 0);

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
    assert_mangle(0, 1, 0xff2, 0);
    assert_mangle(1, 0, 0xff2, 0);

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
    restore_error = NULL;
    assert(apply_unified_connmark_rules(t, 2, cfg, NULL) == 0);
    assert_mangle(0, 1, 0xff2, 0);

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
    dump_fail[0] = 0;
    assert(apply_unified_connmark_rules(t, 2, cfg, NULL) == 0);
    assert_mangle(0, 1, 0xff2, 0);

    /* IPv4 goes in, ip6tables-restore fails: the commit fails, and the next
     * one replaces IPv6 only. */
    reset();
    mangle_remove_matching(0, "--match-set HydraRoute dst ");
    mangle_remove_matching(1, "--match-set HydraRoute6 dst ");
    restore_error = "ip6tables-restore: line 2 failed";
    restore_error_family = 1;
    assert(apply_unified_connmark_rules(t, 2, cfg, NULL) == -1);
    assert(restores[0][0] == 1 && restores[1][0] == 1);
    assert(warns == 1);
    assert(strstr(warn_log, "ip6tables-restore failed (exit 1): ip6tables-restore: line 2 failed"));
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
    assert(warns == 1);
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

/* A DirectRoute interface target: its mark is its fwmark (no RCI), it has no
 * raw mark and so no R0; the stop removes its R1..R3 with the rest. */
static void check_interface_target(const unified_target_t *t, const config_t *cfg) {
    unified_target_t t3[3];
    targets_with_wg0(t3, t);

    reset();
    assert(apply_unified_connmark_rules(t3, 3, cfg, NULL) == 0);
    assert(rci_calls == 0);
    assert(restores[0][0] == 1 && restores[1][0] == 1);
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

    reset();
    assert(apply_unified_connmark_rules(t3, 3, cfg, NULL) == 0);
    assert(rci_calls == 0 && restores[0][0] == 0 && restores[1][0] == 0);

    ipset_pair_t pairs[3] = {t3[0].pair, t3[1].pair, t3[2].pair};
    reset();
    assert(cleanup_connmark_rules(pairs, 3) == 0);
    assert(restores[0][0] == 1 && restores[1][0] == 1);
    assert(nf[0].mangle_len == 1 && strcmp(nf[0].mangle[0], NDM_LINE) == 0);
    assert(nf[1].mangle_len == 0);
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
    assert(errors == 2);
    p = strstr(error_log, "mangle batch overflow (");
    assert(p && sscanf(p, "mangle batch overflow (%zu bytes needed, %zu available)", &need, &avail) == 2);
    assert(need > IPT_BATCH_SIZE && avail == IPT_BATCH_SIZE);
    assert_mangle(0, 1, 0xff2, 0);
    assert_mangle(1, 0, 0xff2, 0);
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
    check_start_and_migration(t, &cfg);
    check_audit(t, &cfg);
    check_failures(t, &cfg);
    check_l7(t, &cfg);
    check_interface_target(t, &cfg);
    check_overflow(t, &cfg);
    check_cleanup(t, &cfg);
    puts("check_connmark: OK");
    return 0;
}
