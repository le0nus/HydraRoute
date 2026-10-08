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

#endif
