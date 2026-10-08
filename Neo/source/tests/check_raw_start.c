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

int main(void) {
    run("confirm_fails", confirm_fails, 0);
    run("confirm_fails", confirm_fails, 1);
    run("first_dump_listed", first_dump_listed, 1);
    run("first_dump_listed", first_dump_listed, 2);
    run("first_dump_absent", first_dump_absent, 1);
    run("first_dump_absent", first_dump_absent, 2);
    run("first_dump_unknown", first_dump_unknown, 0);
    run("first_dump_unknown", first_dump_unknown, 1);
    puts("check_raw_start: OK");
    return 0;
}
