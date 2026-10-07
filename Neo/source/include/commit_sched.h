#ifndef COMMIT_SCHED_H
#define COMMIT_SCHED_H

/* NDMS rewrites mangle on WAN events and runs the netfilter.d hook after each
 * rebuilt table. Dropping SIGUSR1 while a commit cycle was running left the
 * CONNMARK rules missing until the next timer tick, so every signal commits. */

typedef int (*commit_update_fn)(void);

int commit_sched_on_signal(commit_update_fn update);
int commit_sched_on_timer(commit_update_fn update);

#endif
