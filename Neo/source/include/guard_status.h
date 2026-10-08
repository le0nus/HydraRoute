#ifndef GUARD_STATUS_H
#define GUARD_STATUS_H

#include <time.h>

#define GUARD_STATUS_PATH  "/var/run/hrneo-status"
#define GUARD_REASON_MAX   32

typedef enum {
    RAW_GUARD_OFF,
    RAW_GUARD_ON,
    RAW_GUARD_DEGRADED,
} raw_guard_state_t;

/* State of the leak guard for other programs: key=value lines in a tmpfs
 * file, written aside and renamed over it, only when something changed. */
void guard_status_init(const char *path);

/* Raw guard state and the HRNEO_GUARD rule count per family as last read
 * from the table, -1 when unknown (no successful dump). A new state or
 * reason is logged: WARN for degraded and for the way back to on. */
void guard_status_set_raw(raw_guard_state_t state, const char *reason,
                          int rules_v4, int rules_v6);
void guard_status_set_rebuild(time_t when);

/* Writes the file if anything changed. Returns 0 when written or nothing to
 * write, -1 when it could not be written: the old file stays as it was, the
 * change is kept for the next flush, one WARN until a write works again. */
int guard_status_flush(void);

typedef enum {
    PATH_NA,        /* family not tracked (IPv6 without any default route in main) */
    PATH_OK,        /* unicast default route in the policy table: a path, not tunnel health */
    PATH_BLOCKED,   /* no default route there, or not unicast */
    PATH_UNKNOWN,   /* a dump failed, the policy has no fwmark rule, or its mark is unknown */
} path_state_t;

/* The policies the monitor watches: count of them, the k-th called name(k),
 * a string of the target list that outlives the status (no copies). Their
 * state is allocated here for exactly count entries, all unknown until a
 * round reports; the old state goes. If it cannot be allocated: one WARN,
 * and every policy is written as unknown. Returns 0, or -1 then. Lines go
 * in the file as policy.<name>.v4= and .v6=, ok|blocked:<unix-time>|
 * unknown|n/a, between raw_rules_v6 and last_rebuild. */
int guard_status_policy_count(int count, const char *(*name)(int k));

/* One monitor round for policy k. The worst tracked family decides
 * (blocked > unknown > ok; n/a is not tracked): blocked for delay seconds ->
 * WARN "guard: policy <name> blocked"; ok or n/a after that WARN -> WARN
 * "guard: policy <name> restored after <N> s" (WARN, so log=off shows
 * both). unknown neither ends nor restarts an episode, and a family that
 * comes back blocked from unknown keeps the blocked:<unix-time> it had; only
 * ok or n/a ends it. now_mono: CLOCK_MONOTONIC seconds; now_unix: wall time
 * written as blocked:<t>. */
void guard_status_policy(int k, path_state_t v4, path_state_t v6,
                         long now_mono, time_t now_unix, int delay);

/* Policy k is gone (RCI: deleted in Keenetic): its lines leave the file and
 * its episode ends without "restored" (a WARN says it is gone if "blocked"
 * was logged). A later round for it starts afresh. */
void guard_status_policy_gone(int k);

#endif
