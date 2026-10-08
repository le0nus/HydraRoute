#ifndef COMMIT_SCHED_H
#define COMMIT_SCHED_H

/* When to run the next netfilter commit.
 *
 * Every SIGUSR1 commits at once: NDMS runs the netfilter.d hook after each
 * table it rebuilt, and the CONNMARK rules must be back before the next packet.
 * A successful signal-time commit is checked again NF_VERIFY_INTERVAL_MS later,
 * because NDMS may still be rewriting tables. A failed commit is retried after
 * 50, 100, 250, 500, 1000 ms and then every 3 s: the short delays catch a busy
 * xtables lock or a table in the middle of a rebuild, the long ones keep a
 * lasting failure (RCI down, a policy without a mark yet) from costing more
 * than upstream's 3 s cycle. A success or a new SIGUSR1 starts the delays over.
 *
 * Both calls return the timer delay in ms (0: leave the timer disarmed) and
 * set s->event when the failure state changes, so the caller can log once per
 * failure episode instead of once per attempt. */

typedef int (*commit_update_fn)(void);

typedef enum {
    COMMIT_EV_NONE,         /* no change worth a log line */
    COMMIT_EV_FAILED,       /* first failure after a success */
    COMMIT_EV_RECOVERED,    /* first success after failures */
} commit_event_t;

typedef struct {
    int failing;            /* the last commit failed */
    int failures;           /* failed commits in a row, or in the episode just ended */
    int step;               /* index of the next retry delay */
    commit_event_t event;   /* what the last call changed */
    int recheck_s;          /* seconds since the last slow re-check */
} commit_sched_t;

int commit_sched_on_signal(commit_sched_t *s, commit_update_fn update);
int commit_sched_on_timer(commit_sched_t *s, commit_update_fn update);

/* The slow re-check of policies RCI confirmed absent (Ruling 49): a commit
 * does not fail over them, so the retries above never ask about them again.
 * Called with the seconds since the last call (the guard monitor's round),
 * it returns 1 once COMMIT_RECHECK_SEC have passed, then starts over. */
#define COMMIT_RECHECK_SEC 60
int commit_sched_recheck_due(commit_sched_t *s, int elapsed_s);

#endif
