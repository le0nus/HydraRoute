#include "../include/commit_sched.h"
#include "../include/hrneo.h"

int commit_sched_on_signal(commit_update_fn update) {
    update();
    return NF_VERIFY_INTERVAL_MS;
}

int commit_sched_on_timer(commit_update_fn update) {
    return update() == 0 ? 0 : NF_RETRY_INTERVAL_MS;
}
