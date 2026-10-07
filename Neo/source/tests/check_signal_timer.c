#include "../include/signal_handler.h"
#include <assert.h>
#include <poll.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>

static long elapsed_ms(const struct timespec *since) {
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (now.tv_sec - since->tv_sec) * 1000 + (now.tv_nsec - since->tv_nsec) / 1000000;
}

int main(void) {
    signal_mgr_t m;
    assert(signal_mgr_init(&m) == 0);

    /* SIGUSR1 can re-arm the timer after it fired but before the loop read it.
     * Re-arming clears the expiration, so the read must not wait for the new one. */
    signal_mgr_arm_timer(&m, 1);
    usleep(20000);
    signal_mgr_arm_timer(&m, 300);
    struct timespec t0;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    assert(signal_mgr_read_timer(&m) <= 0);
    assert(elapsed_ms(&t0) < 100);

    /* The re-armed timer still fires and is read as one expiration. */
    struct pollfd p = { .fd = m.timer_fd, .events = POLLIN };
    assert(poll(&p, 1, 1000) == 1);
    assert(signal_mgr_read_timer(&m) == 1);

    signal_mgr_close(&m);
    puts("check_signal_timer: OK");
    return 0;
}
