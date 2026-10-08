#include "../include/guard_monitor.h"
#include "../include/log.h"
#include "../include/rtnl.h"
#include <errno.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/timerfd.h>
#include <linux/rtnetlink.h>

/* §6.1: does each policy still have a path, that is a unicast default route
 * in the table of its "fwmark <mark> lookup <table>" rule? Not tunnel
 * health: a route NDMS keeps while the tunnel is down still reads ok
 * (Ruling 25). One round every GUARD_MONITOR_SEC in the main loop,
 * synchronous but under one deadline for all its dumps (Ruling 15). */
static struct {
    const unified_target_t *targets;    /* main.c's list: index i is target i for life */
    int count;
    int delay;              /* BlockedLogDelay */
    int off;                /* the timer could not be set up */
    int skip;               /* the last round reached its deadline: skip the next */
    int warned;             /* a failed round logged, until a round works */
} g_mon;

int guard_monitor_family(int family, const uint32_t *marks, int n, path_state_t *out) {
    rtnl_fwmark_rule_t rules[MAX_TARGETS];
    uint32_t tables[MAX_TARGETS + 1];
    int state[MAX_TARGETS + 1];

    if (n > MAX_TARGETS) n = MAX_TARGETS;
    for (int p = 0; p < n; p++) {
        out[p] = PATH_UNKNOWN;
        rules[p].mark = marks[p];           /* 0 has no rule: unknown */
    }
    if (rtnl_fwmark_rules(family, rules, n) < 0) return -1;

    /* One route dump answers for main and every policy table; a table 0
     * (no rule) matches nothing. */
    tables[0] = RT_TABLE_MAIN;
    for (int p = 0; p < n; p++) tables[p + 1] = rules[p].table;
    if (rtnl_default_routes(family, tables, n + 1, state) != 0) return -1;

    /* IPv6 counts only while main has an IPv6 default route of any kind. */
    if (family == AF_INET6 && state[0] == RTNL_ROUTE_NONE) {
        for (int p = 0; p < n; p++) out[p] = PATH_NA;
        return 0;
    }
    for (int p = 0; p < n; p++)
        if (tables[p + 1])
            out[p] = state[p + 1] == RTNL_ROUTE_UNICAST ? PATH_OK : PATH_BLOCKED;
    return 0;
}

/* The k-th policy target (interface targets are not policies). */
static int policy_target(int k) {
    for (int i = 0; i < g_mon.count; i++)
        if (!g_mon.targets[i].is_interface && k-- == 0) return i;
    return -1;
}

static const char *policy_name(int k) {
    int i = policy_target(k);
    return i < 0 ? NULL : g_mon.targets[i].pair.ipv4;
}

void guard_monitor_init(const unified_target_t *targets, int count, int delay) {
    int n = 0;
    memset(&g_mon, 0, sizeof(g_mon));
    g_mon.targets = targets;
    g_mon.count = count < 0 ? 0 : count > MAX_TARGETS ? MAX_TARGETS : count;
    g_mon.delay = delay;
    for (int i = 0; i < g_mon.count; i++)
        if (!targets[i].is_interface) n++;
    guard_status_policy_count(n, policy_name);
}

int guard_monitor_start(int epfd) {
    const char *what = "timerfd_create";
    int fd = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC | TFD_NONBLOCK);
    if (fd >= 0) {
        struct itimerspec its = {
            .it_interval = {.tv_sec = GUARD_MONITOR_SEC, .tv_nsec = 0},
            .it_value    = {.tv_sec = GUARD_MONITOR_SEC, .tv_nsec = 0},
        };
        struct epoll_event ev;
        memset(&ev, 0, sizeof(ev));
        ev.events = EPOLLIN;
        ev.data.fd = fd;
        if (timerfd_settime(fd, 0, &its, NULL) != 0) what = "timerfd_settime";
        else if (epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev) != 0) what = "epoll_ctl";
        else return fd;
        int err = errno;
        close(fd);
        errno = err;
    }
    LOG_WARN("guard monitor off: %s: %s; policy paths stay unknown", what, strerror(errno));
    g_mon.off = 1;
    guard_status_flush();
    return -1;
}

void guard_monitor_on_timer(int fd) {
    uint64_t expirations;
    if (read(fd, &expirations, sizeof(expirations)) == (ssize_t)sizeof(expirations))
        guard_monitor_tick();
}

void guard_monitor_tick(void) {
    path_state_t st[2][MAX_TARGETS];
    uint32_t marks[MAX_TARGETS];
    uint8_t gone[MAX_TARGETS];
    int n = 0, known = 0, failed[2] = {0, 0};

    if (g_mon.off) return;
    if (g_mon.skip) {
        g_mon.skip = 0;
        LOG_DEBUG("guard monitor: round skipped after one that reached its deadline");
        return;
    }
    for (int i = 0; i < g_mon.count; i++) {
        if (g_mon.targets[i].is_interface) continue;
        gone[n] = (uint8_t)connmark_target_gone(i);
        marks[n] = gone[n] ? 0 : connmark_target_mark(i);
        st[0][n] = st[1][n] = PATH_UNKNOWN;
        if (marks[n]) known = 1;
        n++;
    }

    int64_t deadline = rtnl_now_ms() + GUARD_MONITOR_DEADLINE_MS;
    if (known) {
        rtnl_set_deadline(deadline);
        failed[0] = guard_monitor_family(AF_INET, marks, n, st[0]) != 0;
        failed[1] = guard_monitor_family(AF_INET6, marks, n, st[1]) != 0;
        rtnl_set_deadline(0);
    }
    int64_t now = rtnl_now_ms();

    /* One WARN per run of failed rounds: the policies say unknown meanwhile. */
    if (known && now >= deadline) {
        g_mon.skip = 1;
        if (!g_mon.warned)
            LOG_WARN("guard monitor: round reached its %d ms deadline; policy paths unknown, next round skipped",
                     GUARD_MONITOR_DEADLINE_MS);
        g_mon.warned = 1;
    } else if (failed[0] || failed[1]) {
        if (!g_mon.warned)
            LOG_WARN("guard monitor: %s rule or route dump failed; policy paths unknown meanwhile",
                     failed[0] ? "IPv4" : "IPv6");
        g_mon.warned = 1;
    } else if (known) {
        g_mon.warned = 0;
    }

    time_t now_unix = time(NULL);
    for (int k = 0; k < n; k++) {
        if (gone[k])
            guard_status_policy_gone(k);
        else if (!marks[k])                 /* mark not known yet: no IPv6 n/a either */
            guard_status_policy(k, PATH_UNKNOWN, PATH_UNKNOWN, (long)(now / 1000), now_unix, g_mon.delay);
        else
            guard_status_policy(k, st[0][k], st[1][k], (long)(now / 1000), now_unix, g_mon.delay);
    }
    guard_status_flush();
}
