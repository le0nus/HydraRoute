#include "../include/guard_status.h"
#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define PATH "build/check_guard_status.status"

static int warns;
static char last_warn[256];
static int fail_write, fail_close, fail_rename;

/* The policy state is allocated per policy: calloc can fail. */
static int fail_calloc;
static size_t calloc_n;
void *__real_calloc(size_t n, size_t size);
void *__wrap_calloc(size_t n, size_t size) {
    if (fail_calloc) return NULL;
    calloc_n = n;
    return __real_calloc(n, size);
}

void __wrap_log_write(const char *fmt, ...) {
    va_list ap;
    if (strncmp(fmt, "[WARN]", 6) != 0) return;
    va_start(ap, fmt);
    vsnprintf(last_warn, sizeof(last_warn), fmt, ap);
    va_end(ap);
    warns++;
}

/* The status file goes through fwrite, fclose and rename; each can fail. */
size_t __real_fwrite(const void *p, size_t size, size_t n, FILE *f);
int __real_fclose(FILE *f);
int __real_rename(const char *from, const char *to);

static int fwrites, fail_write_at;      /* fail only the fail_write_at-th fwrite */

size_t __wrap_fwrite(const void *p, size_t size, size_t n, FILE *f) {
    if (fail_write || ++fwrites == fail_write_at) return n ? n - 1 : 0;
    return __real_fwrite(p, size, n, f);
}

int __wrap_fclose(FILE *f) {
    int r = __real_fclose(f);
    return fail_close ? EOF : r;
}

int __wrap_rename(const char *from, const char *to) {
    return fail_rename ? -1 : __real_rename(from, to);
}

static void read_file(char *buf, size_t size) {
    FILE *f = fopen(PATH, "r");
    assert(f);
    size_t n = fread(buf, 1, size - 1, f);
    buf[n] = '\0';
    fclose(f);
}

static void check_raw_state(void) {
    char buf[1024];
    remove(PATH);
    guard_status_init(PATH);
    assert(guard_status_flush() == 0);
    assert(access(PATH, F_OK) != 0);            /* nothing known yet: no file */

    guard_status_set_raw(RAW_GUARD_DEGRADED, "no-mark-v4", 0, 0);
    assert(warns == 1 && strstr(last_warn, "raw guard degraded: no-mark-v4"));
    guard_status_set_rebuild(1760000000);
    assert(guard_status_flush() == 0);
    read_file(buf, sizeof(buf));
    assert(strcmp(buf, "raw_guard=degraded:no-mark-v4\nraw_rules_v4=0\nraw_rules_v6=0\n"
                       "last_rebuild=1760000000\n") == 0);
    assert(access(PATH ".tmp", F_OK) != 0);     /* written aside, then renamed */

    /* Same state again: no log line and no write. */
    guard_status_set_raw(RAW_GUARD_DEGRADED, "no-mark-v4", 0, 0);
    remove(PATH);
    assert(guard_status_flush() == 0);
    assert(access(PATH, F_OK) != 0);
    assert(warns == 1);

    /* Another reason is a new WARN; the way back is a WARN too (log=off shows both). */
    guard_status_set_raw(RAW_GUARD_DEGRADED, "restore-v4", 0, 0);
    assert(warns == 2 && strstr(last_warn, "raw guard degraded: restore-v4"));
    guard_status_set_raw(RAW_GUARD_ON, "", 1, 1);
    assert(warns == 3 && strstr(last_warn, "raw guard on again (was degraded: restore-v4)"));
    assert(guard_status_flush() == 0);
    read_file(buf, sizeof(buf));
    assert(strcmp(buf, "raw_guard=on\nraw_rules_v4=1\nraw_rules_v6=1\n"
                       "last_rebuild=1760000000\n") == 0);

    /* A count that was not read (failed dump, raw not looked at) is unknown, not 0. */
    guard_status_set_raw(RAW_GUARD_OFF, "", -1, -1);
    assert(warns == 3);
    assert(guard_status_flush() == 0);
    read_file(buf, sizeof(buf));
    assert(strcmp(buf, "raw_guard=off\nraw_rules_v4=unknown\nraw_rules_v6=unknown\n"
                       "last_rebuild=1760000000\n") == 0);

    /* A path that cannot be written: one WARN, then quiet. */
    guard_status_init("build/no-such-dir/status");
    guard_status_set_raw(RAW_GUARD_ON, "", 1, 1);
    int before = warns;
    assert(guard_status_flush() == -1);
    guard_status_set_rebuild(1760000001);
    assert(guard_status_flush() == -1);
    assert(warns == before + 1 && strstr(last_warn, "cannot write build/no-such-dir/status"));
    remove(PATH);
}

/* A failed write, close or rename leaves the old file as it was and no
 * temporary file; the change is kept and goes out on the next flush. */
static void check_atomic(void) {
    static const char on[] = "raw_guard=on\nraw_rules_v4=2\nraw_rules_v6=2\nlast_rebuild=0\n";
    char buf[1024];
    remove(PATH);
    guard_status_init(PATH);
    guard_status_set_raw(RAW_GUARD_ON, "", 2, 2);
    assert(guard_status_flush() == 0);
    read_file(buf, sizeof(buf));
    assert(strcmp(buf, on) == 0);

    int before = warns;
    guard_status_set_raw(RAW_GUARD_DEGRADED, "audit-v4", -1, 2);
    assert(warns == before + 1);
    for (int step = 0; step < 3; step++) {
        fail_write = step == 0;
        fail_close = step == 1;
        fail_rename = step == 2;
        assert(guard_status_flush() == -1);
        fail_write = fail_close = fail_rename = 0;
        read_file(buf, sizeof(buf));
        assert(strcmp(buf, on) == 0);
        assert(access(PATH ".tmp", F_OK) != 0);
    }
    assert(warns == before + 2 && strstr(last_warn, "cannot write " PATH));

    assert(guard_status_flush() == 0);
    read_file(buf, sizeof(buf));
    assert(strcmp(buf, "raw_guard=degraded:audit-v4\nraw_rules_v4=unknown\nraw_rules_v6=2\n"
                       "last_rebuild=0\n") == 0);

    /* Once it worked, a new failure is reported again. */
    guard_status_set_rebuild(1760000002);
    fail_rename = 1;
    assert(guard_status_flush() == -1);
    fail_rename = 0;
    assert(warns == before + 3);
    remove(PATH);
}

/* The policy names are the target list's own strings. */
static const char *const NAMES[] = {"HydraRoute", "RU", "Work"};
static const char *name_of(int k) {
    return NAMES[k];
}

static int file_count(const char *buf, const char *needle) {
    int c = 0;
    for (const char *p = strstr(buf, needle); p; p = strstr(p + 1, needle)) c++;
    return c;
}

static void check_policy_events(void) {
    char buf[1024];
    remove(PATH);
    guard_status_init(PATH);
    guard_status_set_raw(RAW_GUARD_ON, "", 1, 1);
    assert(guard_status_policy_count(1, name_of) == 0 && calloc_n == 1);

    /* Nothing known before the first round. */
    assert(guard_status_flush() == 0);
    read_file(buf, sizeof(buf));
    assert(strstr(buf, "raw_rules_v6=1\npolicy.HydraRoute.v4=unknown\npolicy.HydraRoute.v6=unknown\nlast_rebuild="));

    int w = warns;
    guard_status_policy(0, PATH_OK, PATH_NA, 100, 1760000100, 30);
    assert(guard_status_flush() == 0);
    read_file(buf, sizeof(buf));
    assert(strstr(buf, "raw_rules_v6=1\npolicy.HydraRoute.v4=ok\npolicy.HydraRoute.v6=n/a\nlast_rebuild="));

    /* The same round again changes no line: no write. */
    remove(PATH);
    guard_status_policy(0, PATH_OK, PATH_NA, 110, 1760000110, 30);
    assert(guard_status_flush() == 0 && access(PATH, F_OK) != 0);

    /* Blocked for less than BlockedLogDelay: no WARN and no restored. */
    guard_status_policy(0, PATH_BLOCKED, PATH_NA, 110, 1760000110, 30);
    guard_status_policy(0, PATH_BLOCKED, PATH_NA, 130, 1760000130, 30);
    guard_status_policy(0, PATH_OK, PATH_NA, 135, 1760000135, 30);
    assert(warns == w);

    /* Blocked for 30 s: one WARN; unknown in between neither ends nor
     * restarts it, and the file keeps the time it began (Codex #4). */
    guard_status_policy(0, PATH_BLOCKED, PATH_NA, 200, 1760000200, 30);
    assert(guard_status_flush() == 0);
    read_file(buf, sizeof(buf));
    assert(strstr(buf, "policy.HydraRoute.v4=blocked:1760000200\n"));
    guard_status_policy(0, PATH_UNKNOWN, PATH_NA, 210, 1760000210, 30);
    assert(guard_status_flush() == 0);
    read_file(buf, sizeof(buf));
    assert(strstr(buf, "policy.HydraRoute.v4=unknown\npolicy.HydraRoute.v6=n/a\n"));
    guard_status_policy(0, PATH_BLOCKED, PATH_NA, 230, 1760000230, 30);
    assert(warns == w + 1 && strstr(last_warn, "guard: policy HydraRoute blocked"));
    assert(guard_status_flush() == 0);
    read_file(buf, sizeof(buf));
    assert(strstr(buf, "policy.HydraRoute.v4=blocked:1760000200\n"));
    guard_status_policy(0, PATH_BLOCKED, PATH_NA, 240, 1760000240, 30);
    assert(warns == w + 1);

    /* unknown after the WARN is no recovery either. */
    guard_status_policy(0, PATH_UNKNOWN, PATH_UNKNOWN, 250, 1760000250, 30);
    assert(warns == w + 1);
    guard_status_policy(0, PATH_OK, PATH_NA, 262, 1760000262, 30);
    assert(warns == w + 2 && strstr(last_warn, "guard: policy HydraRoute restored after 62 s"));

    /* A new run after ok starts its own time. */
    guard_status_policy(0, PATH_BLOCKED, PATH_NA, 270, 1760000270, 30);
    assert(guard_status_flush() == 0);
    read_file(buf, sizeof(buf));
    assert(strstr(buf, "policy.HydraRoute.v4=blocked:1760000270\n"));
    guard_status_policy(0, PATH_OK, PATH_NA, 275, 1760000275, 30);
    assert(warns == w + 2);

    /* The worst tracked family decides: IPv6 blocked with IPv4 ok is blocked. */
    guard_status_policy(0, PATH_OK, PATH_BLOCKED, 300, 1760000300, 0);
    assert(warns == w + 3 && strstr(last_warn, "guard: policy HydraRoute blocked"));
    assert(guard_status_flush() == 0);
    read_file(buf, sizeof(buf));
    assert(strstr(buf, "policy.HydraRoute.v4=ok\npolicy.HydraRoute.v6=blocked:1760000300\n"));
    /* ... and unknown in one family is not ok for the other's episode */
    guard_status_policy(0, PATH_UNKNOWN, PATH_OK, 301, 1760000301, 0);
    assert(warns == w + 3);
    guard_status_policy(0, PATH_OK, PATH_OK, 302, 1760000302, 0);
    assert(warns == w + 4 && strstr(last_warn, "guard: policy HydraRoute restored after 2 s"));
    assert(guard_status_flush() == 0);
    read_file(buf, sizeof(buf));
    assert(strstr(buf, "policy.HydraRoute.v4=ok\npolicy.HydraRoute.v6=ok\n"));

    /* blocked outranks unknown: a family blocked while the other is unknown
     * is blocked. */
    guard_status_policy(0, PATH_BLOCKED, PATH_UNKNOWN, 303, 1760000303, 0);
    assert(warns == w + 5 && strstr(last_warn, "guard: policy HydraRoute blocked"));
    guard_status_policy(0, PATH_OK, PATH_OK, 304, 1760000304, 0);
    assert(warns == w + 6 && strstr(last_warn, "restored after 1 s"));
    w += 2;

    /* n/a in both (IPv6 untracked, IPv4 cannot be) ends an episode as ok does. */
    guard_status_policy(0, PATH_BLOCKED, PATH_NA, 310, 1760000310, 0);
    guard_status_policy(0, PATH_NA, PATH_NA, 315, 1760000315, 0);
    assert(warns == w + 6 && strstr(last_warn, "restored after 5 s"));

    /* No policy watched: the lines leave the file. */
    guard_status_policy_count(0, name_of);
    assert(guard_status_flush() == 0);
    read_file(buf, sizeof(buf));
    assert(!strstr(buf, "policy."));
    remove(PATH);
}

/* Policies keep their index: one gone (RCI: deleted in Keenetic) leaves the
 * file and closes its episode without a false "restored"; the others keep
 * theirs; back, it starts afresh. */
static void check_policy_gone(void) {
    char buf[1024];
    remove(PATH);
    guard_status_init(PATH);
    guard_status_set_raw(RAW_GUARD_ON, "", 2, 2);
    assert(guard_status_policy_count(3, name_of) == 0 && calloc_n == 3);
    int w = warns;
    guard_status_policy(0, PATH_BLOCKED, PATH_NA, 100, 1760000100, 0);
    guard_status_policy(1, PATH_OK, PATH_NA, 100, 1760000100, 0);
    guard_status_policy(2, PATH_BLOCKED, PATH_NA, 100, 1760000100, 30);
    assert(warns == w + 1 && strstr(last_warn, "guard: policy HydraRoute blocked"));

    guard_status_policy_gone(0);
    assert(warns == w + 2 && strstr(last_warn, "guard: policy HydraRoute is gone (deleted in Keenetic), no longer watched"));
    assert(!strstr(last_warn, "restored"));
    guard_status_policy_gone(0);
    assert(warns == w + 2);
    assert(guard_status_flush() == 0);
    read_file(buf, sizeof(buf));
    assert(!strstr(buf, "policy.HydraRoute."));
    assert(strstr(buf, "raw_rules_v6=2\npolicy.RU.v4=ok\npolicy.RU.v6=n/a\n"
                       "policy.Work.v4=blocked:1760000100\npolicy.Work.v6=n/a\nlast_rebuild="));

    /* Work's episode goes on through it: its WARN comes at 30 s. */
    guard_status_policy(2, PATH_BLOCKED, PATH_NA, 130, 1760000130, 30);
    assert(warns == w + 3 && strstr(last_warn, "guard: policy Work blocked"));

    /* Back: a fresh start, no "restored" for the old episode. */
    guard_status_policy(0, PATH_OK, PATH_NA, 140, 1760000140, 0);
    assert(warns == w + 3);
    assert(guard_status_flush() == 0);
    read_file(buf, sizeof(buf));
    assert(strstr(buf, "raw_rules_v6=2\npolicy.HydraRoute.v4=ok\npolicy.HydraRoute.v6=n/a\npolicy.RU.v4=ok\n"));
    guard_status_policy(0, PATH_BLOCKED, PATH_NA, 150, 1760000150, 30);
    assert(guard_status_flush() == 0);
    read_file(buf, sizeof(buf));
    assert(strstr(buf, "policy.HydraRoute.v4=blocked:1760000150\n"));

    /* Gone with no "blocked" logged: nothing to close, no WARN. */
    guard_status_policy_gone(1);
    assert(warns == w + 3);
    remove(PATH);
}

/* calloc fails: one WARN, and every policy is written as unknown. */
static void check_policy_alloc(void) {
    char buf[1024];
    remove(PATH);
    guard_status_init(PATH);
    guard_status_set_raw(RAW_GUARD_ON, "", 1, 1);
    int w = warns;
    fail_calloc = 1;
    assert(guard_status_policy_count(2, name_of) == -1);
    fail_calloc = 0;
    assert(warns == w + 1 && strstr(last_warn, "guard: no memory for the path state of 2 policies"));
    guard_status_policy(0, PATH_BLOCKED, PATH_NA, 100, 1760000100, 0);
    guard_status_policy_gone(1);
    assert(warns == w + 1);
    assert(guard_status_flush() == 0);
    read_file(buf, sizeof(buf));
    assert(strstr(buf, "raw_rules_v6=1\npolicy.HydraRoute.v4=unknown\npolicy.HydraRoute.v6=unknown\n"
                       "policy.RU.v4=unknown\npolicy.RU.v6=unknown\nlast_rebuild="));
    remove(PATH);
}

/* A failed write, close or rename keeps the whole old file, policy lines
 * too; the next flush writes the new one. */
static void check_policy_atomic(void) {
    static const char old[] = "raw_guard=on\nraw_rules_v4=1\nraw_rules_v6=1\n"
                              "policy.HydraRoute.v4=ok\npolicy.HydraRoute.v6=n/a\nlast_rebuild=0\n";
    char buf[1024];
    remove(PATH);
    guard_status_init(PATH);
    guard_status_set_raw(RAW_GUARD_ON, "", 1, 1);
    assert(guard_status_policy_count(1, name_of) == 0);
    guard_status_policy(0, PATH_OK, PATH_NA, 100, 1760000100, 30);
    assert(guard_status_flush() == 0);
    read_file(buf, sizeof(buf));
    assert(strcmp(buf, old) == 0);

    int before = warns;
    guard_status_policy(0, PATH_BLOCKED, PATH_NA, 110, 1760000110, 30);
    for (int step = 0; step < 5; step++) {
        fail_write = step == 0;
        fail_close = step == 1;
        fail_rename = step == 2;
        fwrites = 0;
        fail_write_at = step == 3 ? 2 : step == 4 ? 3 : 0;  /* a policy line only */
        assert(guard_status_flush() == -1);
        fail_write = fail_close = fail_rename = fail_write_at = 0;
        read_file(buf, sizeof(buf));
        assert(strcmp(buf, old) == 0);
        assert(access(PATH ".tmp", F_OK) != 0);
    }
    assert(warns == before + 1 && strstr(last_warn, "cannot write " PATH));
    assert(guard_status_flush() == 0);
    read_file(buf, sizeof(buf));
    assert(strstr(buf, "policy.HydraRoute.v4=blocked:1760000110\npolicy.HydraRoute.v6=n/a\nlast_rebuild=0\n"));
    remove(PATH);
}

/* As many policies as there can be targets, with the longest names: every
 * line goes out whole, in order. */
static char many_names[128][64];
static const char *many_name(int k) {
    return many_names[k];
}

static void check_many_policies(void) {
    static char buf[65536];
    remove(PATH);
    guard_status_init(PATH);
    guard_status_set_raw(RAW_GUARD_ON, "", 128, 128);
    for (int k = 0; k < 128; k++) {
        memset(many_names[k], 'n', 63);
        snprintf(many_names[k], sizeof(many_names[k]), "%03d", k);
        many_names[k][3] = 'n';
        many_names[k][63] = '\0';
    }
    assert(guard_status_policy_count(128, many_name) == 0 && calloc_n == 128);
    for (int k = 0; k < 128; k++)
        guard_status_policy(k, PATH_BLOCKED, PATH_BLOCKED, 100, 1760000100, 30);
    assert(guard_status_flush() == 0);
    read_file(buf, sizeof(buf));
    assert(file_count(buf, "=blocked:1760000100\n") == 256);
    char want[160];
    snprintf(want, sizeof(want), "raw_rules_v6=128\npolicy.%s.v4=blocked:1760000100\n", many_names[0]);
    assert(strstr(buf, want));
    snprintf(want, sizeof(want), "policy.%s.v6=blocked:1760000100\nlast_rebuild=0\n", many_names[127]);
    assert(strstr(buf, want));
    remove(PATH);
}

int main(void) {
    check_raw_state();
    check_atomic();
    check_policy_events();
    check_policy_gone();
    check_policy_alloc();
    check_policy_atomic();
    check_many_policies();
    puts("check_guard_status: OK");
    return 0;
}
