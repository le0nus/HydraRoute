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

size_t __wrap_fwrite(const void *p, size_t size, size_t n, FILE *f) {
    if (fail_write) return n ? n - 1 : 0;
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

int main(void) {
    check_raw_state();
    check_atomic();
    puts("check_guard_status: OK");
    return 0;
}
