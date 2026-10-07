#include "../include/commit_sched.h"
#include "../include/hrneo.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static int calls;
static int next_result;

static int fake_update(void) {
    calls++;
    return next_result;
}

static int on_signal(commit_sched_t *s, int result) {
    next_result = result;
    return commit_sched_on_signal(s, fake_update);
}

static int on_timer(commit_sched_t *s, int result) {
    next_result = result;
    return commit_sched_on_timer(s, fake_update);
}

int main(void) {
    commit_sched_t s;
    memset(&s, 0, sizeof(s));

    /* NDMS runs the netfilter.d hook once per rebuilt table, so SIGUSR1 comes
     * in bursts. Every signal must run an update; none may be dropped. */
    calls = 0;
    for (int i = 0; i < 4; i++) {
        assert(on_signal(&s, 0) == NF_VERIFY_INTERVAL_MS);
        assert(s.event == COMMIT_EV_NONE);
    }
    assert(calls == 4);

    /* The verify pass succeeds: nothing left to do. */
    calls = 0;
    assert(on_timer(&s, 0) == 0);
    assert(calls == 1 && s.event == COMMIT_EV_NONE);

    /* A commit that fails at signal time is retried soon, not after the verify interval. */
    assert(on_signal(&s, -1) == 50);
    assert(s.event == COMMIT_EV_FAILED && s.failures == 1);

    /* Lasting failures back off up to 3 s, and only the first one is reported. */
    static const int backoff[] = {100, 250, 500, 1000, 3000, 3000};
    for (int i = 0; i < 6; i++) {
        assert(on_timer(&s, -1) == backoff[i]);
        assert(s.event == COMMIT_EV_NONE);
    }
    assert(s.failures == 7);

    /* Recovery is reported once, with the number of failed attempts. */
    assert(on_timer(&s, 0) == 0);
    assert(s.event == COMMIT_EV_RECOVERED && s.failures == 7);
    assert(on_timer(&s, 0) == 0);
    assert(s.event == COMMIT_EV_NONE);

    /* After a success the delays start over. */
    assert(on_timer(&s, -1) == 50);
    assert(s.event == COMMIT_EV_FAILED && s.failures == 1);
    assert(on_timer(&s, -1) == 100);
    assert(on_timer(&s, -1) == 250);

    /* SIGUSR1 starts the delays over too, but the failure is not reported again. */
    assert(on_signal(&s, -1) == 50);
    assert(s.event == COMMIT_EV_NONE && s.failures == 4);
    assert(on_timer(&s, -1) == 100);

    /* A successful signal-time commit ends the failure and is verified as usual. */
    assert(on_signal(&s, 0) == NF_VERIFY_INTERVAL_MS);
    assert(s.event == COMMIT_EV_RECOVERED && s.failures == 5);
    assert(on_timer(&s, -1) == 50);
    assert(s.event == COMMIT_EV_FAILED);

    puts("check_commit_sched: OK");
    return 0;
}
