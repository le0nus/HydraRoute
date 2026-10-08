#include "../include/guard_monitor.h"
#include "../include/rtnl.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/timerfd.h>
#include <linux/rtnetlink.h>

#define STATUS  "build/check_guard_monitor.status"
#define RU      0xff1u
#define HR      0xffffaaau
#define TIMER_FD 77

/* --- fake kernel, per family [0 IPv4, 1 IPv6] -------------------------
 * The fwmark rule of RU points to table 4096, HydraRoute's to 4097; the
 * default route state of main and of those two tables is scripted. Each
 * dump costs dump_cost ms of the fake clock and, as rtnl_dump does under a
 * deadline, fails once it has passed (none asked) or is cut when it comes. */
static int64_t now_ms;
static int64_t dump_cost;
static int64_t deadline, deadline_log[16];
static int deadline_n;
static int rules_fail[2], routes_fail[2], rule_dumps[2], route_dumps[2];
static int has_rule[2][2];                  /* [family][0 RU, 1 HR] */
static int main_state[2];
static int table_state[2][2];               /* [family][0 table 4096, 1 table 4097] */
static uint32_t seen_tables[2][8];
static int seen_n[2];

static void kernel_reset(void) {
    for (int fi = 0; fi < 2; fi++) {
        rules_fail[fi] = routes_fail[fi] = 0;
        has_rule[fi][0] = has_rule[fi][1] = 1;
        table_state[fi][0] = table_state[fi][1] = RTNL_ROUTE_UNICAST;
    }
    main_state[0] = RTNL_ROUTE_UNICAST;
    main_state[1] = RTNL_ROUTE_NONE;        /* no IPv6 uplink */
    dump_cost = 0;
}

static void counters_reset(void) {
    memset(rule_dumps, 0, sizeof(rule_dumps));
    memset(route_dumps, 0, sizeof(route_dumps));
    deadline_n = 0;
}

int64_t rtnl_now_ms(void) {
    return now_ms;
}

void rtnl_set_deadline(int64_t d) {
    deadline = d;
    if (deadline_n < 16) deadline_log[deadline_n] = d;
    deadline_n++;
}

static int spend(void) {
    if (deadline && now_ms >= deadline) return -1;
    now_ms += dump_cost;
    if (deadline && now_ms > deadline) {
        now_ms = deadline;
        return -1;
    }
    return 0;
}

static int fi_of(int family) {
    assert(family == AF_INET || family == AF_INET6);
    return family == AF_INET6;
}

int rtnl_fwmark_rules(int family, rtnl_fwmark_rule_t *rules, int n) {
    int fi = fi_of(family), found = 0;
    rule_dumps[fi]++;
    for (int k = 0; k < n; k++) rules[k].table = 0;
    if (spend() != 0 || rules_fail[fi]) return -1;
    for (int k = 0; k < n; k++) {
        if (rules[k].mark == RU && has_rule[fi][0]) rules[k].table = 4096;
        if (rules[k].mark == HR && has_rule[fi][1]) rules[k].table = 4097;
        if (rules[k].table) found++;
    }
    return found;
}

int rtnl_default_routes(int family, const uint32_t *tables, int n, int *state) {
    int fi = fi_of(family);
    route_dumps[fi]++;
    seen_n[fi] = n;
    for (int p = 0; p < n && p < 8; p++) seen_tables[fi][p] = tables[p];
    /* as the real one, a dump that fails may have filled some states first */
    for (int p = 0; p < n; p++)
        state[p] = tables[p] == RT_TABLE_MAIN ? main_state[fi]
                 : tables[p] == 4096 ? table_state[fi][0]
                 : tables[p] == 4097 ? table_state[fi][1] : RTNL_ROUTE_NONE;
    if (spend() != 0 || routes_fail[fi]) return -1;
    return 0;
}

/* --- fake iptables: the marks the commits resolved, by target index --- */
static unified_target_t targets[3];         /* RU (policy), wg0 (interface), HydraRoute (policy) */
static uint32_t mark_of[3];
static int gone_of[3];

uint32_t connmark_target_mark(int i) {
    assert(i >= 0 && i < 3);
    return gone_of[i] ? 0 : mark_of[i];
}

int connmark_target_gone(int i) {
    assert(i >= 0 && i < 3);
    return gone_of[i];
}

/* Wall time follows the monotonic clock: mono 1000 s is unix 1760000000. */
#define UNIX(ms) ((time_t)(1760000000 + (ms) / 1000 - 1000))
time_t __wrap_time(time_t *t) {
    time_t v = UNIX(now_ms);
    if (t) *t = v;
    return v;
}

static int warns;
static char last_warn[512];

void __wrap_log_write(const char *fmt, ...) {
    va_list ap;
    if (strncmp(fmt, "[WARN]", 6) != 0) return;
    va_start(ap, fmt);
    vsnprintf(last_warn, sizeof(last_warn), fmt, ap);
    va_end(ap);
    warns++;
}

/* --- fake timer and epoll for guard_monitor_start ---------------------- */
static int fail_create, fail_settime, fail_ctl, timer_closes;
static struct itimerspec armed;
static int ctl_op, ctl_fd, ctl_epfd;
static struct epoll_event ctl_ev;

int __wrap_timerfd_create(int clockid, int flags) {
    assert(clockid == CLOCK_MONOTONIC && flags == (TFD_CLOEXEC | TFD_NONBLOCK));
    if (fail_create) {
        errno = EMFILE;
        return -1;
    }
    return TIMER_FD;
}

int __wrap_timerfd_settime(int fd, int flags, const struct itimerspec *v, struct itimerspec *old) {
    assert(fd == TIMER_FD && flags == 0 && old == NULL);
    if (fail_settime) {
        errno = EINVAL;
        return -1;
    }
    armed = *v;
    return 0;
}

int __wrap_epoll_ctl(int epfd, int op, int fd, struct epoll_event *ev) {
    if (fail_ctl) {
        errno = ENOMEM;
        return -1;
    }
    ctl_epfd = epfd;
    ctl_op = op;
    ctl_fd = fd;
    ctl_ev = *ev;
    return 0;
}

int __real_close(int fd);
int __wrap_close(int fd) {
    if (fd == TIMER_FD) {
        timer_closes++;
        return 0;
    }
    return __real_close(fd);
}

/* --- helpers ----------------------------------------------------------- */
static char text[4096];

static const char *status(void) {
    FILE *f = fopen(STATUS, "r");
    text[0] = '\0';
    if (f) {
        size_t n = fread(text, 1, sizeof(text) - 1, f);
        text[n] = '\0';
        fclose(f);
    }
    return text;
}

static int has(const char *s) {
    return strstr(status(), s) != NULL;
}

static void has_line(const char *name, int v6, const char *value) {
    char want[160];
    snprintf(want, sizeof(want), "\npolicy.%s.v%d=%s\n", name, v6 ? 6 : 4, value);
    if (!has(want)) {
        fprintf(stderr, "check_guard_monitor: no line%s in:\n%s", want, text);
        assert(0);
    }
}

static const char *blocked_since(int64_t ms) {
    static char v[32];
    snprintf(v, sizeof(v), "blocked:%ld", (long)UNIX(ms));
    return v;
}

/* Ten seconds on, then the timer's round. */
static void tick(void) {
    now_ms += GUARD_MONITOR_SEC * 1000;
    guard_monitor_tick();
}

static void restart(int delay) {
    remove(STATUS);
    guard_status_init(STATUS);
    guard_status_set_raw(RAW_GUARD_ON, "", 2, 2);
    for (int i = 0; i < 3; i++) gone_of[i] = 0;
    mark_of[0] = RU;
    mark_of[2] = HR;
    kernel_reset();
    guard_monitor_init(targets, 3, delay);
}

/* --- guard_monitor_family ---------------------------------------------- */

static path_state_t one(int family, uint32_t mark, int ret) {
    uint32_t marks[1] = {mark};
    path_state_t out[1] = {(path_state_t)99};
    assert(guard_monitor_family(family, marks, 1, out) == ret);
    return out[0];
}

static void check_family(void) {
    kernel_reset();
    deadline = 0;

    /* IPv4: a unicast default route in the policy table is a path;
     * blackhole or none is not. Main does not count for IPv4. */
    counters_reset();
    assert(one(AF_INET, RU, 0) == PATH_OK);
    assert(rule_dumps[0] == 1 && route_dumps[0] == 1 && rule_dumps[1] == 0);
    assert(seen_n[0] == 2 && seen_tables[0][0] == RT_TABLE_MAIN && seen_tables[0][1] == 4096);
    table_state[0][0] = RTNL_ROUTE_OTHER;
    assert(one(AF_INET, RU, 0) == PATH_BLOCKED);
    table_state[0][0] = RTNL_ROUTE_NONE;
    assert(one(AF_INET, RU, 0) == PATH_BLOCKED);
    table_state[0][0] = RTNL_ROUTE_UNICAST;
    main_state[0] = RTNL_ROUTE_NONE;
    assert(one(AF_INET, RU, 0) == PATH_OK);
    main_state[0] = RTNL_ROUTE_UNICAST;

    /* A failed dump, a mark without fwmark rule or a mark 0 is unknown,
     * never blocked; a failed route dump is unknown even with the states it
     * filled before failing. */
    rules_fail[0] = 1;
    counters_reset();
    assert(one(AF_INET, RU, -1) == PATH_UNKNOWN);
    assert(route_dumps[0] == 0);
    rules_fail[0] = 0;
    routes_fail[0] = 1;
    assert(one(AF_INET, RU, -1) == PATH_UNKNOWN);
    table_state[0][0] = RTNL_ROUTE_NONE;
    assert(one(AF_INET, RU, -1) == PATH_UNKNOWN);
    table_state[0][0] = RTNL_ROUTE_UNICAST;
    routes_fail[0] = 0;
    has_rule[0][0] = 0;
    assert(one(AF_INET, RU, 0) == PATH_UNKNOWN);
    has_rule[0][0] = 1;
    assert(one(AF_INET, 0, 0) == PATH_UNKNOWN);
    assert(one(AF_INET, 0xbad, 0) == PATH_UNKNOWN);

    /* IPv6 is tracked only while main has an IPv6 default route of any
     * kind (§6.1, Codex #5): none -> n/a; a blackhole default counts. */
    assert(one(AF_INET6, RU, 0) == PATH_NA);
    table_state[1][0] = RTNL_ROUTE_NONE;
    assert(one(AF_INET6, RU, 0) == PATH_NA);
    main_state[1] = RTNL_ROUTE_OTHER;
    assert(one(AF_INET6, RU, 0) == PATH_BLOCKED);
    table_state[1][0] = RTNL_ROUTE_UNICAST;
    assert(one(AF_INET6, RU, 0) == PATH_OK);
    main_state[1] = RTNL_ROUTE_UNICAST;
    table_state[1][0] = RTNL_ROUTE_OTHER;
    assert(one(AF_INET6, RU, 0) == PATH_BLOCKED);
    table_state[1][0] = RTNL_ROUTE_UNICAST;
    assert(one(AF_INET6, RU, 0) == PATH_OK);

    /* A failed IPv6 dump is unknown, not n/a, whatever main looked like. */
    main_state[1] = RTNL_ROUTE_NONE;
    routes_fail[1] = 1;
    assert(one(AF_INET6, RU, -1) == PATH_UNKNOWN);
    routes_fail[1] = 0;
    rules_fail[1] = 1;
    assert(one(AF_INET6, RU, -1) == PATH_UNKNOWN);
    rules_fail[1] = 0;

    /* Several marks, one rule dump and one route dump: each its own. */
    {
        uint32_t marks[3] = {RU, 0xbad, HR};
        path_state_t out[3];
        table_state[0][1] = RTNL_ROUTE_NONE;
        counters_reset();
        assert(guard_monitor_family(AF_INET, marks, 3, out) == 0);
        assert(out[0] == PATH_OK && out[1] == PATH_UNKNOWN && out[2] == PATH_BLOCKED);
        assert(rule_dumps[0] == 1 && route_dumps[0] == 1);
        assert(seen_n[0] == 4 && seen_tables[0][0] == RT_TABLE_MAIN && seen_tables[0][1] == 4096);
        assert(seen_tables[0][2] == 0 && seen_tables[0][3] == 4097);
    }
    kernel_reset();
}

/* --- rounds -------------------------------------------------------------- */

static void check_rounds(void) {
    now_ms = 1000000;
    restart(30);
    assert(guard_status_flush() == 0);
    assert(has("raw_rules_v6=2\npolicy.RU.v4=unknown\npolicy.RU.v6=unknown\n"
               "policy.HydraRoute.v4=unknown\npolicy.HydraRoute.v6=unknown\nlast_rebuild="));
    assert(!has("wg0"));

    /* A round: one deadline for all its dumps, cleared after them; the route
     * dump asks for main and both policy tables at once. */
    counters_reset();
    int w = warns;
    tick();
    assert(deadline_n == 2 && deadline_log[0] == now_ms + GUARD_MONITOR_DEADLINE_MS && deadline_log[1] == 0);
    assert(rule_dumps[0] == 1 && rule_dumps[1] == 1 && route_dumps[0] == 1 && route_dumps[1] == 1);
    assert(seen_n[0] == 3 && seen_tables[0][0] == RT_TABLE_MAIN);
    assert(seen_tables[0][1] == 4096 && seen_tables[0][2] == 4097);
    assert(has("raw_rules_v6=2\npolicy.RU.v4=ok\npolicy.RU.v6=n/a\n"
               "policy.HydraRoute.v4=ok\npolicy.HydraRoute.v6=n/a\nlast_rebuild="));
    assert(warns == w);

    /* An unchanged round does not write the file. */
    remove(STATUS);
    tick();
    assert(access(STATUS, F_OK) != 0);

    /* HydraRoute blocked: the WARN after BlockedLogDelay; the file says
     * since when. */
    table_state[0][1] = RTNL_ROUTE_NONE;
    tick();
    int64_t t0 = now_ms;
    has_line("HydraRoute", 0, blocked_since(t0));
    has_line("RU", 0, "ok");
    tick();
    tick();
    assert(warns == w);
    tick();
    assert(warns == w + 1 && strstr(last_warn, "guard: policy HydraRoute blocked"));

    /* RCI down: its mark unknown, not gone. The policy stays, as unknown,
     * and its episode goes on; back blocked, the file keeps t0. */
    mark_of[2] = 0;
    tick();
    has_line("HydraRoute", 0, "unknown");
    has_line("HydraRoute", 1, "unknown");
    mark_of[2] = HR;
    tick();
    has_line("HydraRoute", 0, blocked_since(t0));
    assert(warns == w + 1);

    /* A route dump fails: that family is unknown, one WARN for the episode;
     * the blocked episode goes on, and ends with the dumps back. */
    routes_fail[0] = 1;
    tick();
    assert(warns == w + 2 && strstr(last_warn, "guard monitor: IPv4 rule or route dump failed"));
    has_line("HydraRoute", 0, "unknown");
    has_line("RU", 0, "unknown");
    has_line("RU", 1, "n/a");
    tick();
    assert(warns == w + 2);
    routes_fail[0] = 0;
    table_state[0][1] = RTNL_ROUTE_UNICAST;
    tick();
    {
        char want[64];
        snprintf(want, sizeof(want), "guard: policy HydraRoute restored after %ld s",
                 (long)((now_ms - t0) / 1000));
        assert(warns == w + 3 && strstr(last_warn, want));
    }
    has_line("HydraRoute", 0, "ok");
    has_line("RU", 0, "ok");

    /* A later failure is a new episode with a new WARN. */
    rules_fail[1] = 1;
    tick();
    assert(warns == w + 4 && strstr(last_warn, "guard monitor: IPv6 rule or route dump failed"));
    has_line("RU", 1, "unknown");
    rules_fail[1] = 0;
    tick();
    has_line("RU", 1, "n/a");

    /* RU gone (deleted in Keenetic): its lines leave; HydraRoute keeps its
     * index, its lines and its episode. Back, RU starts afresh. */
    table_state[0][1] = RTNL_ROUTE_NONE;
    tick();
    int64_t t1 = now_ms;
    w = warns;
    gone_of[0] = 1;
    counters_reset();
    tick();
    assert(!has("policy.RU."));
    assert(has("raw_rules_v6=2\npolicy.HydraRoute.v4="));
    has_line("HydraRoute", 0, blocked_since(t1));
    tick();
    assert(warns == w);
    tick();
    assert(warns == w + 1 && strstr(last_warn, "guard: policy HydraRoute blocked"));
    gone_of[0] = 0;
    tick();
    has_line("RU", 0, "ok");
    has_line("HydraRoute", 0, blocked_since(t1));
    assert(warns == w + 1);

    /* No mark known at all: nothing to dump, every policy unknown. */
    mark_of[0] = mark_of[2] = 0;
    counters_reset();
    tick();
    assert(rule_dumps[0] + rule_dumps[1] + route_dumps[0] + route_dumps[1] == 0 && deadline_n == 0);
    has_line("RU", 0, "unknown");
    has_line("HydraRoute", 1, "unknown");
    assert(warns == w + 1);

    /* HydraRoute gone during its warned episode: no "restored"; back with a
     * path, nothing to restore either. */
    mark_of[0] = RU;
    mark_of[2] = HR;
    gone_of[2] = 1;
    tick();
    assert(warns == w + 2 && strstr(last_warn, "guard: policy HydraRoute is gone"));
    assert(!has("policy.HydraRoute."));
    table_state[0][1] = RTNL_ROUTE_UNICAST;
    gone_of[2] = 0;
    tick();
    has_line("HydraRoute", 0, "ok");
    assert(warns == w + 2);

    /* Both families, IPv6 tracked: IPv4 ok and IPv6 blocked is blocked. */
    main_state[1] = RTNL_ROUTE_UNICAST;
    table_state[1][1] = RTNL_ROUTE_NONE;
    tick();
    int64_t t2 = now_ms;
    has_line("HydraRoute", 0, "ok");
    has_line("HydraRoute", 1, blocked_since(t2));
    has_line("RU", 1, "ok");
    tick();
    tick();
    tick();
    assert(warns == w + 3 && strstr(last_warn, "guard: policy HydraRoute blocked"));
    table_state[1][1] = RTNL_ROUTE_UNICAST;
    tick();
    assert(warns == w + 4 && strstr(last_warn, "restored after 40 s"));

    /* Flapping: never blocked for 30 s in a row, so no WARN. */
    for (int i = 0; i < 6; i++) {
        table_state[0][1] = i % 2 ? RTNL_ROUTE_UNICAST : RTNL_ROUTE_OTHER;
        tick();
        tick();
    }
    assert(warns == w + 4);

    /* unknown before the WARN keeps the episode's start: blocked, unknown
     * twice, blocked again 30 s after the start is the WARN. */
    table_state[0][1] = RTNL_ROUTE_NONE;
    tick();
    int64_t t3 = now_ms;
    routes_fail[0] = 1;
    tick();
    tick();
    assert(warns == w + 5);                 /* the dump failure */
    routes_fail[0] = 0;
    tick();
    assert(warns == w + 6 && strstr(last_warn, "guard: policy HydraRoute blocked"));
    has_line("HydraRoute", 0, blocked_since(t3));
    table_state[0][1] = RTNL_ROUTE_UNICAST;
    main_state[1] = RTNL_ROUTE_NONE;
    tick();
    assert(warns == w + 7 && strstr(last_warn, "restored after 40 s"));
}

/* Ruling 15: a round that reaches its deadline leaves the families it did
 * not read unknown, and the next round is skipped. */
static void check_overrun(void) {
    now_ms = 2000000;
    restart(30);
    tick();
    has_line("HydraRoute", 0, "ok");

    /* HydraRoute blocked before the slow rounds. */
    table_state[0][1] = RTNL_ROUTE_NONE;
    tick();
    int64_t t0 = now_ms;
    int w = warns;

    /* Each dump takes 150 ms: the IPv4 route dump is cut at the deadline,
     * the IPv6 dumps are not even asked. */
    dump_cost = 150;
    counters_reset();
    tick();
    int64_t start = now_ms - GUARD_MONITOR_DEADLINE_MS;
    assert(deadline_n == 2 && deadline_log[0] == start + GUARD_MONITOR_DEADLINE_MS && deadline_log[1] == 0);
    assert(rule_dumps[0] == 1 && route_dumps[0] == 1 && rule_dumps[1] == 1 && route_dumps[1] == 0);
    assert(warns == w + 1 && strstr(last_warn, "guard monitor: round reached its 200 ms deadline"));
    has_line("HydraRoute", 0, "unknown");
    has_line("HydraRoute", 1, "unknown");
    has_line("RU", 0, "unknown");

    /* The next round is skipped: nothing dumped or written. */
    remove(STATUS);
    counters_reset();
    tick();
    assert(rule_dumps[0] + rule_dumps[1] + route_dumps[0] + route_dumps[1] == 0 && deadline_n == 0);
    assert(access(STATUS, F_OK) != 0);

    /* The one after runs; still slow: no second WARN, the next skipped. */
    tick();
    assert(rule_dumps[0] == 1 && warns == w + 1);
    counters_reset();
    tick();
    assert(rule_dumps[0] == 0);

    /* Fast again: the paths are back, and the episode that began before the
     * slow rounds still counts from t0. */
    dump_cost = 0;
    tick();
    has_line("HydraRoute", 0, blocked_since(t0));
    assert(warns == w + 2 && strstr(last_warn, "guard: policy HydraRoute blocked"));

    /* A round faster than the deadline is not followed by a skip. */
    counters_reset();
    tick();
    assert(rule_dumps[0] == 1);

    /* Slow again later: a new WARN. */
    dump_cost = 150;
    tick();
    assert(warns == w + 3 && strstr(last_warn, "200 ms deadline"));
    dump_cost = 0;
    tick();
    tick();
}

/* A restarted hrneo knows nothing of the last one's episodes: no false
 * "restored", and a new episode counts from its own first round. */
static void check_restart(void) {
    now_ms = 3000000;
    restart(30);
    table_state[0][1] = RTNL_ROUTE_NONE;
    for (int i = 0; i < 4; i++) tick();
    assert(strstr(last_warn, "guard: policy HydraRoute blocked"));
    int w = warns;

    restart(30);
    tick();
    assert(warns == w);
    has_line("HydraRoute", 0, "ok");
    table_state[0][1] = RTNL_ROUTE_NONE;
    tick();
    has_line("HydraRoute", 0, blocked_since(now_ms));
    tick();
    assert(warns == w);
}

/* The timer: a failure of any of its calls is one WARN naming it, the
 * monitor is off and the policies stay unknown. */
static void check_start(void) {
    now_ms = 4000000;
    restart(30);
    int w = warns;

    fail_create = 1;
    assert(guard_monitor_start(5) == -1);
    fail_create = 0;
    assert(warns == w + 1 && strstr(last_warn, "guard monitor off: timerfd_create: "));
    assert(strstr(last_warn, strerror(EMFILE)) && strstr(last_warn, "policy paths stay unknown"));
    assert(timer_closes == 0);
    has_line("RU", 0, "unknown");
    has_line("HydraRoute", 1, "unknown");

    fail_settime = 1;
    assert(guard_monitor_start(5) == -1);
    fail_settime = 0;
    assert(warns == w + 2 && strstr(last_warn, "guard monitor off: timerfd_settime: "));
    assert(strstr(last_warn, strerror(EINVAL)));
    assert(timer_closes == 1);

    fail_ctl = 1;
    assert(guard_monitor_start(5) == -1);
    fail_ctl = 0;
    assert(warns == w + 3 && strstr(last_warn, "guard monitor off: epoll_ctl: "));
    assert(strstr(last_warn, strerror(ENOMEM)));
    assert(timer_closes == 2);

    /* Off: a round does nothing. */
    counters_reset();
    guard_monitor_tick();
    assert(rule_dumps[0] == 0 && deadline_n == 0);

    /* Working: every GUARD_MONITOR_SEC, the first one GUARD_MONITOR_SEC
     * from now, readable in epfd. */
    restart(30);
    assert(guard_monitor_start(5) == TIMER_FD);
    assert(armed.it_value.tv_sec == GUARD_MONITOR_SEC && armed.it_value.tv_nsec == 0);
    assert(armed.it_interval.tv_sec == GUARD_MONITOR_SEC && armed.it_interval.tv_nsec == 0);
    assert(ctl_epfd == 5 && ctl_op == EPOLL_CTL_ADD && ctl_fd == TIMER_FD);
    assert(ctl_ev.events == EPOLLIN && ctl_ev.data.fd == TIMER_FD);
    assert(warns == w + 3 && timer_closes == 2);

    /* The timer fires: a round. A short or failed read is no expiry. */
    {
        int fds[2];
        uint64_t exp = 1;
        assert(pipe(fds) == 0 && fcntl(fds[0], F_SETFL, O_NONBLOCK) == 0);
        counters_reset();
        guard_monitor_on_timer(fds[0]);
        assert(rule_dumps[0] == 0);
        assert(write(fds[1], &exp, 4) == 4);
        guard_monitor_on_timer(fds[0]);
        assert(rule_dumps[0] == 0);
        assert(write(fds[1], &exp, sizeof(exp)) == sizeof(exp));
        now_ms += GUARD_MONITOR_SEC * 1000;
        guard_monitor_on_timer(fds[0]);
        assert(rule_dumps[0] == 1 && route_dumps[1] == 1);
        has_line("RU", 0, "ok");
        close(fds[0]);
        close(fds[1]);
    }
}

int main(void) {
    memset(targets, 0, sizeof(targets));
    strcpy(targets[0].pair.ipv4, "RU");
    strcpy(targets[0].pair.ipv6, "RU6");
    strcpy(targets[1].pair.ipv4, "wg0");
    strcpy(targets[1].pair.ipv6, "wg0v6");
    targets[1].is_interface = 1;
    targets[1].fwmark = 0x3001;
    mark_of[1] = 0x3001;
    strcpy(targets[2].pair.ipv4, "HydraRoute");
    strcpy(targets[2].pair.ipv6, "HydraRoute6");

    check_family();
    check_rounds();
    check_overrun();
    check_restart();
    check_start();
    remove(STATUS);
    puts("check_guard_monitor: OK");
    return 0;
}
