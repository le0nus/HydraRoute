#define STATUS_PATH "build/check_raw_start.status"
#include "fake_nf.h"
#include <sys/wait.h>
#include <unistd.h>

/* Paths right after hrneo starts: no policy mark known yet, nothing read from
 * raw yet. Each scenario runs in a child process, so it sees the statics of
 * iptables.c as a freshly started hrneo does. */

static const char *const OLD_RULES[] = {
    "-A PREROUTING -m mark ! --mark 0xffffaa0/0xffffff0 -m connmark --mark 0x0 -m set --match-set HydraRoute dst -j CONNMARK --set-xmark 0xff2/0xffffffff",
    "-A PREROUTING -m set --match-set HydraRoute dst -j CONNMARK --restore-mark --nfmask 0xffffffff --ctmask 0xffffffff",
    "-A PREROUTING -m mark ! --mark 0xffffaa0/0xffffff0 -m connmark --mark 0x0 -m set --match-set RU dst -j CONNMARK --set-xmark 0xff1/0xffffffff",
    "-A PREROUTING -m set --match-set RU dst -j CONNMARK --restore-mark --nfmask 0xffffffff --ctmask 0xffffffff",
};

static const char *const OLD_RULES6[] = {
    "-A PREROUTING -m mark ! --mark 0xffffaa0/0xffffff0 -m connmark --mark 0x0 -m set --match-set HydraRoute6 dst -j CONNMARK --set-xmark 0xff2/0xffffffff",
    "-A PREROUTING -m set --match-set HydraRoute6 dst -j CONNMARK --restore-mark --nfmask 0xffffffff --ctmask 0xffffffff",
    "-A PREROUTING -m mark ! --mark 0xffffaa0/0xffffff0 -m connmark --mark 0x0 -m set --match-set RU6 dst -j CONNMARK --set-xmark 0xff1/0xffffffff",
    "-A PREROUTING -m set --match-set RU6 dst -j CONNMARK --restore-mark --nfmask 0xffffffff --ctmask 0xffffffff",
};

static unified_target_t T[2];
static config_t CFG;

static void start(void) {
    setup_targets(T, &CFG);
    CFG.raw_guard = 1;
    remove(STATUS_PATH);
    guard_status_init(STATUS_PATH);
}

static int apply(void) {
    return apply_unified_connmark_rules(T, 2, &CFG, NULL);
}

static void run(const char *name, void (*scenario)(int), int arg) {
    fflush(NULL);
    pid_t pid = fork();
    assert(pid >= 0);
    if (pid == 0) {
        start();
        scenario(arg);
        _exit(0);
    }
    int st;
    assert(waitpid(pid, &st, 0) == pid);
    if (!WIFEXITED(st) || WEXITSTATUS(st) != 0) {
        fprintf(stderr, "check_raw_start: scenario %s(%d) failed\n", name, arg);
        assert(0);
    }
}

/* RCI is down at start, so no mark is known. hrneo before 1le2 left its
 * rules out of PolicyOrder in both families, and 1le2 ran before and was
 * rolled back without raw-off, so chains and jumps are there. The replace
 * only puts the old rules in PolicyOrder (unknown marks keep their lines,
 * the unconditional restores included) and goes through; then the read-back
 * of family fi fails. The danger seen before it still counts: both jumps go
 * in this call (Codex re-review, finding 1). */
static void confirm_fails(int fi) {
    lines_add(nf[0].mangle, &nf[0].mangle_len, NDM_LINE);
    for (int i = 0; i < 4; i++) {
        lines_add(nf[0].mangle, &nf[0].mangle_len, OLD_RULES[i]);
        lines_add(nf[1].mangle, &nf[1].mangle_len, OLD_RULES6[i]);
    }
    for (int f = 0; f < 2; f++) {
        nf[f].guard_exists = 1;
        lines_add(nf[f].guard, &nf[f].guard_len, f ? "-A HRNEO_GUARD -m set --match-set HydraRoute6 dst -j MARK --set-xmark 0xff2/0xffffffff"
                                                   : "-A HRNEO_GUARD -m set --match-set HydraRoute dst -j MARK --set-xmark 0xff2/0xffffffff");
        lines_add(nf[f].raw_pre, &nf[f].raw_pre_len, GUARD_JUMP);
    }
    rci_result = RCI_MARK_TRANSPORT;
    reset();
    dump_fail_at[fi] = 2;                   /* the read-back after the replace */
    assert(apply() == -1);
    assert(strcmp(calls, "m4 m6 r4 r6 ") == 0);
    for (int f = 0; f < 2; f++) {
        assert(raw_jumps(f) == 0 && nf[f].guard_len == 0);
        const char *const *old = f ? OLD_RULES6 : OLD_RULES;
        int base = f ? 0 : 1;               /* RU's old rules first now */
        assert(nf[f].mangle_len == base + 4);
        assert(strcmp(nf[f].mangle[base], old[2]) == 0 && strcmp(nf[f].mangle[base + 1], old[3]) == 0);
        assert(strcmp(nf[f].mangle[base + 2], old[0]) == 0 && strcmp(nf[f].mangle[base + 3], old[1]) == 0);
    }
    assert(strstr(warn_log, fi ? "ip6tables -t mangle -S PREROUTING failed or output truncated"
                               : "iptables -t mangle -S PREROUTING failed or output truncated"));
    assert(strstr(warn_log, "iptables: removed the jump to raw HRNEO_GUARD"));
    assert(strstr(warn_log, "ip6tables: removed the jump to raw HRNEO_GUARD"));
    assert(status_has("raw_guard=degraded:old-restore-v4"));
    assert(status_has("raw_rules_v4=0") && status_has("raw_rules_v6=0"));
}

/* The first raw read of the families in mask fails or is cut short while the
 * kernel lists raw: the table is there, so the call fails and the scheduler
 * retries it; the retry, with nothing else happening, puts the chain in
 * (Ruling 30). */
static void first_dump_listed(int mask) {
    raw_dump_fail[0] = mask & 1;
    raw_dump_fail[1] = (mask & 2) != 0;
    reset();
    assert(apply() == -1);
    assert(strcmp(calls, mask == 1 ? "m4 m6 r6 " : "m4 m6 r4 ") == 0);
    assert(proc_calls == 1);
    assert(!nf[mask == 1 ? 0 : 1].guard_exists);
    assert(status_has(mask == 1 ? "raw_guard=degraded:dump-v4" : "raw_guard=degraded:dump-v6"));
    assert(status_has(mask == 1 ? "raw_rules_v4=unknown" : "raw_rules_v6=unknown"));
    raw_dump_fail[0] = raw_dump_fail[1] = 0;
    reset();
    assert(apply() == 0);
    assert(strcmp(calls, mask == 1 ? "r4 " : "r6 ") == 0);
    assert_raw(0, 0xff2);
    assert_raw(1, 0xff2);
    assert(status_has("raw_guard=on"));
}

/* The same, but the kernel does not list raw: the table is absent, a stable
 * state with no retries of its own; the other family is not held up. Once
 * the table is there, the next commit puts the chain in. */
static void first_dump_absent(int mask) {
    int fi = mask == 1 ? 0 : 1;
    raw_dump_fail[fi] = 1;
    raw_listed[fi] = 0;
    reset();
    assert(apply() == 0);
    assert(strcmp(calls, fi ? "m4 m6 r4 " : "m4 m6 r6 ") == 0);
    assert(!nf[fi].guard_exists);
    assert(status_has(fi ? "raw_guard=degraded:raw-modules-v6" : "raw_guard=degraded:raw-modules-v4"));
    assert(status_has(fi ? "raw_rules_v6=unknown" : "raw_rules_v4=unknown"));
    raw_dump_fail[fi] = 0;
    raw_listed[fi] = 1;
    reset();
    assert(apply() == 0);
    assert(strcmp(calls, fi ? "r6 " : "r4 ") == 0);
    assert_raw(0, 0xff2);
    assert_raw(1, 0xff2);
    assert(status_has("raw_guard=on"));
}

/* The table list cannot be read either: no evidence of absence, so it is a
 * failed dump and the call is retried. */
static void first_dump_unknown(int fi) {
    raw_dump_fail[fi] = 1;
    raw_listed[fi] = -1;
    reset();
    assert(apply() == -1);
    assert(status_has(fi ? "raw_guard=degraded:dump-v6" : "raw_guard=degraded:dump-v4"));
}

/* The raw module of family fi fails to load; it is not tried again. The
 * table is absent at first: the read fails and the kernel does not list raw.
 * Then another process loads it: the next commit reads it and puts the
 * chain in, with no second load attempt (Codex re-review r2). */
static void loader_fails_then_table(int fi) {
    raw_kmod_fail[fi] = 1;
    raw_dump_fail[fi] = 1;
    raw_listed[fi] = 0;
    reset();
    assert(apply() == 0);
    assert(strcmp(calls, fi ? "m4 m6 r4 " : "m4 m6 r6 ") == 0);
    assert(raw_kmod_calls[fi] == 1 && proc_calls == 1);
    assert(strstr(warn_log, fi ? "kmod ip6table_raw: init_module failed" : "kmod iptable_raw: init_module failed"));
    assert(status_has(fi ? "raw_guard=degraded:raw-modules-v6" : "raw_guard=degraded:raw-modules-v4"));
    raw_dump_fail[fi] = 0;
    raw_listed[fi] = 1;
    reset();
    assert(apply() == 0);
    assert(strcmp(calls, fi ? "r6 " : "r4 ") == 0);
    assert(raw_kmod_calls[0] == 0 && raw_kmod_calls[1] == 0);
    assert_raw(0, 0xff2);
    assert_raw(1, 0xff2);
    assert(status_has("raw_guard=on"));
}

/* The raw module of family fi fails to load, yet its table is there with a
 * jump (loaded by someone else; 1le2 rolled back without raw-off), and that
 * family's mangle has an unconditional restore hrneo cannot replace: the
 * jump still goes (Ruling 29). */
static void loader_fails_old_restore(int fi) {
    raw_kmod_fail[fi] = 1;
    nf[fi].guard_exists = 1;
    lines_add(nf[fi].guard, &nf[fi].guard_len, fi ? "-A HRNEO_GUARD -m set --match-set HydraRoute6 dst -j MARK --set-xmark 0xff2/0xffffffff"
                                                 : "-A HRNEO_GUARD -m set --match-set HydraRoute dst -j MARK --set-xmark 0xff2/0xffffffff");
    lines_add(nf[fi].raw_pre, &nf[fi].raw_pre_len, GUARD_JUMP);
    lines_add(nf[fi].mangle, &nf[fi].mangle_len,
              fi ? "-A PREROUTING -m set --match-set Old6 dst -j CONNMARK --restore-mark --nfmask 0xffffffff --ctmask 0xffffffff"
                 : "-A PREROUTING -m set --match-set Old dst -j CONNMARK --restore-mark --nfmask 0xffffffff --ctmask 0xffffffff");
    reset();
    assert(apply() == 0);
    assert(strcmp(calls, fi ? "m4 m6 r6 " : "m4 m6 r4 ") == 0);
    assert(raw_kmod_calls[fi] == 1);
    assert(raw_jumps(fi) == 0 && nf[fi].guard_len == 0);
    assert(!nf[!fi].guard_exists);          /* the restore keeps raw out of both */
    assert(strstr(warn_log, fi ? "ip6tables: removed the jump to raw HRNEO_GUARD"
                               : "iptables: removed the jump to raw HRNEO_GUARD"));
    assert(status_has(fi ? "raw_guard=degraded:old-restore-v6" : "raw_guard=degraded:old-restore-v4"));
}

#define LOCK_PATH "build/check_raw_start.lock"

static const char *const HR_RAW[2] = {
    "-A HRNEO_GUARD -m set --match-set HydraRoute dst -j MARK --set-xmark 0xff2/0xffffffff",
    "-A HRNEO_GUARD -m set --match-set HydraRoute6 dst -j MARK --set-xmark 0xff2/0xffffffff",
};

/* What a stopped hrneo leaves in both families: the chain and its jump, a
 * foreign raw rule behind it, and NDMS's own line in mangle. */
static void leftovers(void) {
    lines_add(nf[0].mangle, &nf[0].mangle_len, NDM_LINE);
    for (int fi = 0; fi < 2; fi++) {
        nf[fi].guard_exists = 1;
        lines_add(nf[fi].guard, &nf[fi].guard_len, HR_RAW[fi]);
        lines_add(nf[fi].raw_pre, &nf[fi].raw_pre_len, GUARD_JUMP);
        lines_add(nf[fi].raw_pre, &nf[fi].raw_pre_len, FOREIGN_RAW);
    }
}

static int raw_gone(int fi) {
    return !nf[fi].guard_exists && nf[fi].guard_len == 0 && raw_jumps(fi) == 0 &&
           nf[fi].raw_pre_len == 1 && strcmp(nf[fi].raw_pre[0], FOREIGN_RAW) == 0;
}

static int raw_kept(int fi) {
    return nf[fi].guard_exists && nf[fi].guard_len == 1 && strcmp(nf[fi].guard[0], HR_RAW[fi]) == 0 &&
           nf[fi].raw_pre_len == 2 && strcmp(nf[fi].raw_pre[0], GUARD_JUMP) == 0;
}

#define OUT_PATH "build/check_raw_start.out"

/* What the command printed since the last call, as one string. */
static const char *printed(void) {
    static char buf[512];
    fflush(stdout);
    FILE *f = fopen(OUT_PATH, "r");
    assert(f);
    size_t n = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    buf[n] = '\0';
    assert(freopen(OUT_PATH, "w", stdout));
    return buf;
}

/* hrneo --raw-off is a process of its own: its first call removes, with no
 * commit before it to set the families up (Codex #2). Mangle is not read,
 * no module is loaded. */
static void raw_off_fresh(int unused) {
    (void)unused;
    leftovers();
    lines_add(nf[0].raw_pre, &nf[0].raw_pre_len, GUARD_JUMP);     /* a second jump, behind the foreign rule */
    assert(freopen(OUT_PATH, "w", stdout));
    reset();
    assert(raw_off_command(LOCK_PATH) == 0);
    assert(strcmp(printed(), "hrneo: raw guard chain HRNEO_GUARD removed; "
                             "the next start with RawGuard=true puts it back\n") == 0);
    assert(strcmp(calls, "r4 r6 ") == 0);
    assert(raw_gone(0) && raw_gone(1));
    assert(mangle_dumps[0] == 0 && mangle_dumps[1] == 0 && nf[0].mangle_len == 1);
    assert(raw_kmod_calls[0] == 0 && raw_kmod_calls[1] == 0 && kmod_calls == 0 && rci_calls == 0);
    assert(warns == 0 && errors == 0);
    /* The status the stopped daemon left (on) would be false now. */
    assert(status_has("raw_guard=off") && !status_has("last_rebuild=0"));
    /* Again on a clean system: nothing to do, still a success. */
    reset();
    assert(raw_off_command(LOCK_PATH) == 0);
    assert(calls[0] == '\0' && dumps == 2);
    assert(status_has("raw_guard=off"));
    assert(strcmp(printed(), "hrneo: no raw guard chain HRNEO_GUARD to remove; "
                             "the next start with RawGuard=true puts it back\n") == 0);
    remove(OUT_PATH);
}

/* While the daemon holds its lock nothing is read or removed and the exit
 * code is 2: the daemon would put the chain back on its next commit, or a
 * commit could run between the dump and the restore (Codex #1). */
static void raw_off_locked(int unused) {
    (void)unused;
    leftovers();
    assert(freopen("/dev/null", "w", stdout));
    remove(LOCK_PATH);
    int daemon = lock_acquire(LOCK_PATH);
    assert(daemon >= 0);
    reset();
    assert(raw_off_command(LOCK_PATH) == 2);
    assert(dumps == 0 && proc_calls == 0 && calls[0] == '\0');
    assert(raw_kept(0) && raw_kept(1));
    assert(strstr(error_log, "hrneo is running; stop it first (neo stop)"));
    assert(access(STATUS_PATH, F_OK) != 0);  /* the daemon's status is not touched */
    /* No directory for the lock: an error, still nothing touched. */
    reset();
    assert(raw_off_command("build/no-such-dir/hrneo.lock") == 1);
    assert(dumps == 0 && calls[0] == '\0' && errors == 1);
    /* The daemon is gone. */
    close(daemon);
    reset();
    assert(raw_off_command(LOCK_PATH) == 0);
    assert(strcmp(calls, "r4 r6 ") == 0 && raw_gone(0) && raw_gone(1));
    remove(LOCK_PATH);
}

/* The raw read of family fi fails: that family keeps its chain, the other
 * one is removed, exit 1. The next run removes the rest. */
static void raw_off_dump_fails(int fi) {
    leftovers();
    assert(freopen("/dev/null", "w", stdout));
    raw_dump_fail[fi] = 1;
    reset();
    assert(raw_off_command(LOCK_PATH) == 1);
    assert(strcmp(calls, fi ? "r4 " : "r6 ") == 0);
    assert(raw_kept(fi) && raw_gone(!fi));
    assert(strstr(warn_log, fi ? "ip6tables -t raw -S failed" : "iptables -t raw -S failed"));
    assert(strstr(error_log, "not fully removed"));
    assert(status_has(fi ? "raw_guard=degraded:raw-off-failed-v6" : "raw_guard=degraded:raw-off-failed-v4"));
    raw_dump_fail[fi] = 0;
    reset();
    assert(raw_off_command(LOCK_PATH) == 0);
    assert(strcmp(calls, fi ? "r6 " : "r4 ") == 0);
    assert(raw_gone(0) && raw_gone(1));
    assert(status_has("raw_guard=off"));
}

/* The removing restore of family fi fails: nothing of it changes (one
 * transaction), the other family is removed; the next run finishes. */
static void raw_off_restore_fails(int fi) {
    leftovers();
    assert(freopen("/dev/null", "w", stdout));
    restore_error = "iptables-restore: line 2 failed";
    restore_error_family = fi;
    restore_error_table = 1;
    reset();
    assert(raw_off_command(LOCK_PATH) == 1);
    assert(strcmp(calls, "r4 r6 ") == 0);
    assert(raw_kept(fi) && raw_gone(!fi));
    restore_error = NULL;
    reset();
    assert(raw_off_command(LOCK_PATH) == 0);
    assert(strcmp(calls, fi ? "r6 " : "r4 ") == 0);
    assert(raw_gone(0) && raw_gone(1));
}

/* The restore of family fi says it worked, but the read-back still shows
 * the chain: not removed, exit 1, with a WARN naming what is left. */
static void raw_off_readback(int fi) {
    leftovers();
    assert(freopen("/dev/null", "w", stdout));
    raw_restore_noop[fi] = 1;
    reset();
    assert(raw_off_command(LOCK_PATH) == 1);
    assert(raw_kept(fi) && raw_gone(!fi));
    assert(strstr(warn_log, fi ? "ip6tables: raw HRNEO_GUARD still there after removal: chain 1, jumps 1, rules 1"
                               : "iptables: raw HRNEO_GUARD still there after removal: chain 1, jumps 1, rules 1"));
    raw_restore_noop[fi] = 0;
    reset();
    assert(raw_off_command(LOCK_PATH) == 0);
    assert(raw_gone(0) && raw_gone(1));
}

/* RawGuard=false at start (§5): main() takes the chain down right after the
 * config, before anything can end the start (raw_guard_disable); the status
 * says off. The commits after it do not look at raw. */
static void raw_guard_false_start(int unused) {
    (void)unused;
    CFG.raw_guard = 0;
    leftovers();
    reset();
    assert(raw_guard_disable() == 0);
    assert(strcmp(calls, "r4 r6 ") == 0 && raw_gone(0) && raw_gone(1));
    assert(status_has("raw_guard=off"));
    assert(!status_has("last_rebuild=0"));  /* raw changed */
    assert(warns == 0);
    reset();
    assert(apply() == 0);
    assert(strcmp(calls, "m4 m6 ") == 0 && proc_calls == 0);
    assert(status_has("raw_guard=off"));
}

/* RawGuard=false and the removal of family fi fails: the other family is
 * removed, the status names the failure (never off), with a WARN; each
 * commit tries again until it works. */
static void raw_guard_false_fails(int fi) {
    CFG.raw_guard = 0;
    leftovers();
    restore_error = "iptables-restore: line 2 failed";
    restore_error_family = fi;
    restore_error_table = 1;
    reset();
    assert(raw_guard_disable() == -1);
    assert(raw_kept(fi) && raw_gone(!fi));
    assert(status_has(fi ? "raw_guard=degraded:raw-off-failed-v6" : "raw_guard=degraded:raw-off-failed-v4"));
    assert(strstr(warn_log, fi ? "raw guard degraded: raw-off-failed-v6" : "raw guard degraded: raw-off-failed-v4"));
    reset();
    assert(apply() == -1);                  /* still failing: the commit is retried */
    assert(strcmp(calls, fi ? "r6 m4 m6 " : "r4 m4 m6 ") == 0);
    assert(status_has(fi ? "raw_guard=degraded:raw-off-failed-v6" : "raw_guard=degraded:raw-off-failed-v4"));
    restore_error = NULL;
    reset();
    assert(apply() == 0);
    assert(strcmp(calls, fi ? "r6 " : "r4 ") == 0 && raw_gone(0) && raw_gone(1));
    assert(status_has("raw_guard=off"));
    reset();
    assert(apply() == 0);
    assert(calls[0] == '\0' && proc_calls == 0);
}

/* RawGuard=false, the table list cannot be read and neither can raw: no
 * evidence either way, so not off. Once raw reads, the chain goes. */
static void raw_guard_false_unknown(int unused) {
    (void)unused;
    CFG.raw_guard = 0;
    leftovers();
    raw_listed[0] = raw_listed[1] = -1;
    raw_dump_fail[0] = raw_dump_fail[1] = 1;
    reset();
    assert(raw_guard_disable() == -1);
    assert(calls[0] == '\0' && dumps == 2 && proc_calls == 2);
    assert(status_has("raw_guard=degraded:raw-off-failed-v4"));
    raw_dump_fail[0] = raw_dump_fail[1] = 0;
    reset();
    assert(apply() == 0);
    assert(strcmp(calls, "r4 r6 m4 m6 ") == 0 && raw_gone(0) && raw_gone(1));
    assert(status_has("raw_guard=off"));
}

/* RawGuard=false on a router whose kernel lists no raw table: nothing to
 * remove and nothing read, off at once. */
static void raw_guard_false_absent(int unused) {
    (void)unused;
    CFG.raw_guard = 0;
    raw_listed[0] = raw_listed[1] = 0;
    reset();
    assert(raw_guard_disable() == 0);
    assert(dumps == 0 && proc_calls == 2 && calls[0] == '\0');
    assert(status_has("raw_guard=off"));
    assert(status_has("last_rebuild=0"));   /* nothing changed */
}

/* RawGuard=false, the start's removal failed and xt_conntrack does not
 * load: the commit fails over the module, but the removal needs neither it
 * nor RCI and goes through. */
static void raw_guard_false_conntrack(int unused) {
    (void)unused;
    CFG.raw_guard = 0;
    leftovers();
    raw_dump_fail[0] = 1;
    raw_listed[0] = 1;
    reset();
    assert(raw_guard_disable() == -1);
    assert(strcmp(calls, "r6 ") == 0 && raw_kept(0) && raw_gone(1));
    raw_dump_fail[0] = 0;
    kmod_result = -1;
    reset();
    assert(apply() == -1);
    assert(strcmp(calls, "r4 ") == 0 && raw_gone(0));
    assert(rci_calls == 0 && mangle_dumps[0] == 0);
    assert(status_has("raw_guard=off"));
}

int main(void) {
    run("raw_off_fresh", raw_off_fresh, 0);
    run("raw_off_locked", raw_off_locked, 0);
    run("raw_off_dump_fails", raw_off_dump_fails, 0);
    run("raw_off_dump_fails", raw_off_dump_fails, 1);
    run("raw_off_restore_fails", raw_off_restore_fails, 0);
    run("raw_off_restore_fails", raw_off_restore_fails, 1);
    run("raw_off_readback", raw_off_readback, 0);
    run("raw_off_readback", raw_off_readback, 1);
    run("raw_guard_false_start", raw_guard_false_start, 0);
    run("raw_guard_false_fails", raw_guard_false_fails, 0);
    run("raw_guard_false_fails", raw_guard_false_fails, 1);
    run("raw_guard_false_unknown", raw_guard_false_unknown, 0);
    run("raw_guard_false_absent", raw_guard_false_absent, 0);
    run("raw_guard_false_conntrack", raw_guard_false_conntrack, 0);
    run("confirm_fails", confirm_fails, 0);
    run("confirm_fails", confirm_fails, 1);
    run("first_dump_listed", first_dump_listed, 1);
    run("first_dump_listed", first_dump_listed, 2);
    run("first_dump_absent", first_dump_absent, 1);
    run("first_dump_absent", first_dump_absent, 2);
    run("first_dump_unknown", first_dump_unknown, 0);
    run("first_dump_unknown", first_dump_unknown, 1);
    run("loader_fails_then_table", loader_fails_then_table, 0);
    run("loader_fails_then_table", loader_fails_then_table, 1);
    run("loader_fails_old_restore", loader_fails_old_restore, 0);
    run("loader_fails_old_restore", loader_fails_old_restore, 1);
    puts("check_raw_start: OK");
    return 0;
}
