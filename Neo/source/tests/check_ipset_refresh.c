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

    /* A host entry from a CIDR list is permanent. A DNS answer for the same IP
     * must not refresh it, or it would expire IpsetTimeout later. */
    parsed_cidr_t host = e;
    host.ip[0] = 198; host.ip[1] = 51; host.ip[2] = 100; host.ip[3] = 7;
    reset();
    assert(ipset_add_batch(&mgr, "HydraRoute", &host, 1, 0, &new_count, new_idx) == 0);
    assert(sent_count == 1 && !(sent_flags[0] & NLM_F_EXCL));
    reset();
    replies[0] = IPSET_ERR_EXIST;
    assert(ipset_add_batch(&mgr, "HydraRoute", &host, 1, 1, &new_count, new_idx) == 0);
    assert(sent_count == 1 && new_count == 0);

    /* In a set where the IP was learned from DNS it is still refreshed. */
    reset();
    replies[0] = IPSET_ERR_EXIST;
    assert(ipset_add_batch(&mgr, "Other", &host, 1, 1, &new_count, new_idx) == 0);
    assert(sent_count == 2);

    /* A permanent network is a different element than a host inside it. */
    parsed_cidr_t net = host, inside = host;
    net.prefix = 24; net.ip[3] = 0;
    inside.ip[3] = 8;
    reset();
    assert(ipset_add_batch(&mgr, "HydraRoute", &net, 1, 0, &new_count, new_idx) == 0);
    reset();
    replies[0] = IPSET_ERR_EXIST;
    assert(ipset_add_batch(&mgr, "HydraRoute", &inside, 1, 1, &new_count, new_idx) == 0);
    assert(sent_count == 2);

    /* Same for IPv6 hosts. */
    parsed_cidr_t host6;
    memset(&host6, 0, sizeof(host6));
    host6.family = AF_INET6;
    host6.prefix = 128;
    host6.ip[0] = 0x20; host6.ip[1] = 0x01; host6.ip[2] = 0x0d; host6.ip[3] = 0xb8; host6.ip[15] = 7;
    reset();
    assert(ipset_add_batch(&mgr, "HydraRoutev6", &host6, 1, 0, &new_count, new_idx) == 0);
    reset();
    replies[0] = IPSET_ERR_EXIST;
    assert(ipset_add_batch(&mgr, "HydraRoutev6", &host6, 1, 1, &new_count, new_idx) == 0);
    assert(sent_count == 1);

    /* Without IpsetTimeout nothing is refreshed, so nothing is remembered. */
    ipset_manager_t plain;
    memset(&plain, 0, sizeof(plain));
    reset();
    assert(ipset_add_batch(&plain, "HydraRoute", &host, 1, 0, &new_count, new_idx) == 0);
    assert(plain.permanent == NULL);

    mgr.fd = -1;
    ipset_manager_close(&mgr);
    assert(mgr.permanent == NULL);

    puts("check_ipset_refresh: OK");
    return 0;
}
