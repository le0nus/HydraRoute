#ifndef IPTABLES_H
#define IPTABLES_H

#include "hrneo.h"
#include "rci.h"

#define IPT_DUMP_SIZE       65536
#define IPT_BATCH_SIZE      65536
#define IPT_MAX_RULE_ARGS   64
#define IPT_MAX_OWNED       512

typedef struct {
    ipset_pair_t pair;
    int is_interface;
    int fwmark;
} unified_target_t;

int apply_unified_connmark_rules(const unified_target_t *targets, int count,
                                 const config_t *cfg, const char *l7_wan);
int cleanup_connmark_rules(const ipset_pair_t *pairs, int count);
/* Takes the raw jumps and HRNEO_GUARD out of both families, one restore per
 * family, and reads them back: 0 gone (or never there), -1 not known to be
 * gone in some family (a WARN says why). */
int raw_guard_remove(void);
/* RawGuard=false at start: raw_guard_remove() plus the status (off, or
 * degraded:raw-off-failed-v4|v6); commits retry until it works. */
int raw_guard_disable(void);
/* hrneo --raw-off: only while no process holds lock_path, which the daemon
 * holds for its whole life; the result goes to the status file as
 * raw_guard_disable() does. Returns the exit code: 0 gone, 1 not fully
 * removed, 2 hrneo is running (nothing read, changed or written). */
int raw_off_command(const char *lock_path);
void iptables_delete_rules_matching(const char *ipt_cmd, const char *chain,
                                    const char *needle1, const char *needle2);

#endif
