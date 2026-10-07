#include "../include/ipset_nl.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <linux/netlink.h>

/* Fake kernel: remembers the flags of every message and answers with a scripted errno. */
static uint16_t sent_flags[16];
static int sent_count, recv_count;
static int replies[16];

ssize_t __wrap_send(int fd, const void *buf, size_t len, int flags) {
    (void)fd; (void)flags;
    sent_flags[sent_count++] = ((const struct nlmsghdr *)buf)->nlmsg_flags;
    return (ssize_t)len;
}

ssize_t __wrap_recv(int fd, void *buf, size_t len, int flags) {
    (void)fd; (void)flags;
    memset(buf, 0, len);
    struct nlmsghdr *h = buf;
    struct nlmsgerr *e = (struct nlmsgerr *)((uint8_t *)buf + NLMSG_HDRLEN);
    h->nlmsg_type = NLMSG_ERROR;
    h->nlmsg_len = NLMSG_HDRLEN + sizeof(*e);
    e->error = -replies[recv_count++];
    return (ssize_t)h->nlmsg_len;
}

static void reset(void) {
    sent_count = recv_count = 0;
    memset(replies, 0, sizeof(replies));
}

int main(void) {
    ipset_manager_t mgr;
    memset(&mgr, 0, sizeof(mgr));
    mgr.default_timeout = 21600;

    parsed_cidr_t e;
    memset(&e, 0, sizeof(e));
    e.family = AF_INET;
    e.prefix = 32;
    e.ip[0] = 160; e.ip[1] = 79; e.ip[2] = 104; e.ip[3] = 10;

    int new_count, new_idx[1];

    /* New IP: a single exclusive ADD, reported as new (conntrack flush relies on it). */
    reset();
    assert(ipset_add_batch(&mgr, "HydraRoute", &e, 1, 1, &new_count, new_idx) == 0);
    assert(sent_count == 1 && (sent_flags[0] & NLM_F_EXCL));
    assert(new_count == 1);

    /* Known IP: EXIST must lead to a non-exclusive ADD that refreshes the timeout. */
    reset();
    replies[0] = IPSET_ERR_EXIST;
    assert(ipset_add_batch(&mgr, "HydraRoute", &e, 1, 1, &new_count, new_idx) == 0);
    assert(sent_count == 2);
    assert(sent_flags[0] & NLM_F_EXCL);
    assert(!(sent_flags[1] & NLM_F_EXCL));
    assert(new_count == 0);

    /* Entries without timeout (CIDR lists) stay single-shot. */
    reset();
    replies[0] = IPSET_ERR_EXIST;
    assert(ipset_add_batch(&mgr, "HydraRoute", &e, 1, 0, &new_count, new_idx) == 0);
    assert(sent_count == 1);

    puts("check_ipset_refresh: OK");
    return 0;
}
