#include "../include/commit_sched.h"
#include "../include/hrneo.h"
#include <assert.h>
#include <stdio.h>

static int calls;
static int next_result;

static int fake_update(void) {
    calls++;
    return next_result;
}

int main(void) {
    /* NDMS runs the netfilter.d hook once per rebuilt table, so SIGUSR1 comes
     * in bursts. Every signal must run an update; none may be dropped. */
    calls = 0;
    next_result = 0;
    for (int i = 0; i < 4; i++)
        assert(commit_sched_on_signal(fake_update) == NF_VERIFY_INTERVAL_MS);
    assert(calls == 4);

    calls = 0;
    next_result = 0;
    assert(commit_sched_on_timer(fake_update) == 0);
    assert(calls == 1);

    calls = 0;
    next_result = -1;
    assert(commit_sched_on_timer(fake_update) == NF_RETRY_INTERVAL_MS);
    assert(calls == 1);

    assert(NF_VERIFY_INTERVAL_MS <= 250);
    assert(NF_RETRY_INTERVAL_MS <= 500);

    puts("check_commit_sched: OK");
    return 0;
}
