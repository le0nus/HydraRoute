#ifndef GUARD_MONITOR_H
#define GUARD_MONITOR_H

#include "guard_status.h"
#include "iptables.h"
#include <stdint.h>

#define GUARD_MONITOR_SEC          10
#define GUARD_MONITOR_DEADLINE_MS  200     /* one round, every dump of it (Ruling 15) */

/* Path state of each policy mark in one family (AF_INET or AF_INET6): the
 * table of the policy's "fwmark lookup" rule must hold a unicast default
 * route. IPv6 is tracked only while main has an IPv6 default route of any
 * kind, else every state is n/a. A failed dump, a mark 0 or a mark without
 * rule is unknown. Returns 0, or -1 if a dump failed (all unknown). */
int guard_monitor_family(int family, const uint32_t *marks, int n, path_state_t *out);

/* The targets to watch: their policies (not the interface targets), each
 * by its index in targets, which, as in iptables.c, it keeps for the life
 * of the process; the path state of exactly that many policies is
 * allocated once (guard_status_policy_count). delay: BlockedLogDelay. */
void guard_monitor_init(const unified_target_t *targets, int count, int delay);

/* Arms the GUARD_MONITOR_SEC timer and adds it to epfd. If timerfd_create,
 * timerfd_settime or epoll_ctl fails, the monitor is off: one WARN names
 * the call and its error, and the policy lines stay unknown. Returns the
 * timer fd, or -1. */
int guard_monitor_start(int epfd);

/* The timer fd is readable: one round (guard_monitor_tick). */
void guard_monitor_on_timer(int fd);

/* One round, synchronous, under one GUARD_MONITOR_DEADLINE_MS deadline for
 * all its dumps: a family not read by then is unknown, and the round after
 * one that reached its deadline is skipped. A policy whose mark is unknown
 * is unknown; a policy RCI found gone leaves the file. The status file is
 * written only if a line changed. */
void guard_monitor_tick(void);

#endif
