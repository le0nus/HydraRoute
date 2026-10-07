#include "../include/commit_sched.h"
#include "../include/hrneo.h"

static const int retry_ms[] = {50, 100, 250, 500, 1000, 3000};
#define RETRY_STEPS ((int)(sizeof(retry_ms) / sizeof(retry_ms[0])))

static int record(commit_sched_t *s, int result, int ok_delay) {
    if (result == 0) {
        s->event = s->failing ? COMMIT_EV_RECOVERED : COMMIT_EV_NONE;
        s->failing = 0;
        s->step = 0;
        return ok_delay;
    }
    s->event = s->failing ? COMMIT_EV_NONE : COMMIT_EV_FAILED;
    if (!s->failing) s->failures = 0;
    s->failing = 1;
    s->failures++;
    int delay = retry_ms[s->step];
    if (s->step < RETRY_STEPS - 1) s->step++;
    return delay;
}

int commit_sched_on_signal(commit_sched_t *s, commit_update_fn update) {
    s->step = 0;
    return record(s, update(), NF_VERIFY_INTERVAL_MS);
}

int commit_sched_on_timer(commit_sched_t *s, commit_update_fn update) {
    return record(s, update(), 0);
}
