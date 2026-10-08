#include "../include/ipset_nl.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdint.h>

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

/* realloc fails on demand: the next realloc_fail calls return NULL. */
static int realloc_fail, realloc_calls;
void *__real_realloc(void *p, size_t n);
void *__wrap_realloc(void *p, size_t n) {
    realloc_calls++;
    if (realloc_fail > 0) {
        realloc_fail--;
        return NULL;
    }
    return __real_realloc(p, n);
}

static char log_buf[2048];
void __wrap_log_write(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(log_buf + strlen(log_buf), sizeof(log_buf) - strlen(log_buf), fmt, ap);
    va_end(ap);
}

static int count_of(const char *needle) {
    int n = 0;
    for (const char *p = log_buf; (p = strstr(p, needle)); p += strlen(needle)) n++;
    return n;
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
    e.ip[0] = 203; e.ip[1] = 0; e.ip[2] = 113; e.ip[3] = 10;

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
    assert(plain.permanent.count == 0 && plain.permanent.keys == NULL);

    mgr.fd = -1;
    ipset_manager_close(&mgr);
    assert(mgr.permanent.keys == NULL && mgr.permanent.count == 0);

    /* Many permanent hosts loaded in any order: each is found after the one
     * sort, its neighbours (DNS entries) are not, and a host added after a
     * lookup is found too. RFC 5737 addresses only. */
    static const uint8_t doc[3][3] = {{192, 0, 2}, {198, 51, 100}, {203, 0, 113}};
    ipset_manager_t big;
    memset(&big, 0, sizeof(big));
    big.default_timeout = 21600;
    for (int i = 299; i >= 0; i--) {
        parsed_cidr_t h = host;
        memcpy(h.ip, doc[i / 100], 3);
        h.ip[3] = (uint8_t)(i % 100 * 2 + 1);
        reset();
        assert(ipset_add_batch(&big, "HydraRoute", &h, 1, 0, &new_count, new_idx) == 0);
    }
    assert(big.permanent.count == 300 && big.permanent.cap == 512 && !big.permanent.sorted);
    for (int i = 0; i < 300; i++) {
        parsed_cidr_t h = host, gap = host;
        memcpy(h.ip, doc[i / 100], 3);
        memcpy(gap.ip, doc[i / 100], 3);
        h.ip[3] = (uint8_t)(i % 100 * 2 + 1);
        gap.ip[3] = (uint8_t)(i % 100 * 2 + 2);
        reset();
        replies[0] = IPSET_ERR_EXIST;
        assert(ipset_add_batch(&big, "HydraRoute", &h, 1, 1, &new_count, new_idx) == 0);
        assert(sent_count == 1);
        reset();
        replies[0] = IPSET_ERR_EXIST;
        assert(ipset_add_batch(&big, "HydraRoute", &gap, 1, 1, &new_count, new_idx) == 0);
        assert(sent_count == 2);
    }
    assert(big.permanent.sorted);
    parsed_cidr_t late = host;
    memcpy(late.ip, doc[0], 3);
    late.ip[3] = 250;
    reset();
    assert(ipset_add_batch(&big, "HydraRoute", &late, 1, 0, &new_count, new_idx) == 0);
    assert(!big.permanent.sorted);
    reset();
    replies[0] = IPSET_ERR_EXIST;
    assert(ipset_add_batch(&big, "HydraRoute", &late, 1, 1, &new_count, new_idx) == 0);
    assert(sent_count == 1 && big.permanent.sorted && big.permanent.count == 301);
    /* Below the smallest and above the largest key. */
    parsed_cidr_t lo = host, hi = host;
    memcpy(lo.ip, doc[0], 3); lo.ip[3] = 0;
    memcpy(hi.ip, doc[2], 3); hi.ip[3] = 255;
    reset();
    replies[0] = IPSET_ERR_EXIST;
    assert(ipset_add_batch(&big, "HydraRoute", &lo, 1, 1, &new_count, new_idx) == 0);
    assert(sent_count == 2);
    reset();
    replies[0] = IPSET_ERR_EXIST;
    assert(ipset_add_batch(&big, "HydraRoute", &hi, 1, 1, &new_count, new_idx) == 0);
    assert(sent_count == 2);
    big.fd = -1;
    ipset_manager_close(&big);
    assert(big.permanent.keys == NULL);

    /* An empty array finds nothing and a lookup does not sort anything. */
    ipset_manager_t one;
    memset(&one, 0, sizeof(one));
    one.default_timeout = 21600;
    reset();
    replies[0] = IPSET_ERR_EXIST;
    assert(ipset_add_batch(&one, "HydraRoute", &host, 1, 1, &new_count, new_idx) == 0);
    assert(sent_count == 2 && one.permanent.count == 0 && one.permanent.keys == NULL);
    /* One element: found, its neighbours below and above are not. The flag
     * goes 0 (append), 1 (first lookup), stays 1 (next lookups), 0 (append). */
    reset();
    assert(ipset_add_batch(&one, "HydraRoute", &host, 1, 0, &new_count, new_idx) == 0);
    assert(one.permanent.count == 1 && one.permanent.cap == 4 && !one.permanent.sorted);
    parsed_cidr_t below = host, above = host;
    below.ip[3] = 6; above.ip[3] = 8;
    for (int round = 0; round < 2; round++) {
        reset();
        replies[0] = IPSET_ERR_EXIST;
        assert(ipset_add_batch(&one, "HydraRoute", &host, 1, 1, &new_count, new_idx) == 0);
        assert(sent_count == 1 && one.permanent.sorted);
        reset();
        replies[0] = IPSET_ERR_EXIST;
        assert(ipset_add_batch(&one, "HydraRoute", &below, 1, 1, &new_count, new_idx) == 0);
        assert(sent_count == 2 && one.permanent.sorted);
        reset();
        replies[0] = IPSET_ERR_EXIST;
        assert(ipset_add_batch(&one, "HydraRoute", &above, 1, 1, &new_count, new_idx) == 0);
        assert(sent_count == 2 && one.permanent.sorted);
    }
    reset();
    assert(ipset_add_batch(&one, "HydraRoute", &above, 1, 0, &new_count, new_idx) == 0);
    assert(!one.permanent.sorted);

    /* A set loaded after the first lookup is found as well. */
    reset();
    assert(ipset_add_batch(&one, "Late", &host, 1, 0, &new_count, new_idx) == 0);
    for (int k = 0; k < 2; k++) {
        reset();
        replies[0] = IPSET_ERR_EXIST;
        assert(ipset_add_batch(&one, k ? "Late" : "HydraRoute", &host, 1, 1, &new_count, new_idx) == 0);
        assert(sent_count == 1);
    }
    /* The same address bytes in another family are another key. */
    parsed_cidr_t v6same;
    memset(&v6same, 0, sizeof(v6same));
    v6same.family = AF_INET6;
    v6same.prefix = 128;
    memcpy(v6same.ip, host.ip, 4);
    reset();
    replies[0] = IPSET_ERR_EXIST;
    assert(ipset_add_batch(&one, "HydraRoute", &v6same, 1, 1, &new_count, new_idx) == 0);
    assert(sent_count == 2);
    reset();
    assert(ipset_add_batch(&one, "Fam", &v6same, 1, 0, &new_count, new_idx) == 0);
    parsed_cidr_t v4same = host;
    memset(v4same.ip, 0, 16);
    memcpy(v4same.ip, v6same.ip, 4);
    reset();
    replies[0] = IPSET_ERR_EXIST;
    assert(ipset_add_batch(&one, "Fam", &v4same, 1, 1, &new_count, new_idx) == 0);
    assert(sent_count == 2);
    reset();
    replies[0] = IPSET_ERR_EXIST;
    assert(ipset_add_batch(&one, "Fam", &v6same, 1, 1, &new_count, new_idx) == 0);
    assert(sent_count == 1);
    one.fd = -1;
    ipset_manager_close(&one);

    /* Repeated keys: the same host twice before the first lookup, the same
     * list loaded again after it, a repeat after the dedupe. One key each. */
    ipset_manager_t dup;
    memset(&dup, 0, sizeof(dup));
    dup.default_timeout = 21600;
    for (int round = 0; round < 2; round++)
        for (int i = 0; i < 5; i++) {
            parsed_cidr_t h = host;
            h.ip[3] = (uint8_t)(100 + i);
            reset();
            assert(ipset_add_batch(&dup, "HydraRoute", &h, 1, 0, &new_count, new_idx) == 0);
        }
    assert(dup.permanent.count == 10);
    reset();
    replies[0] = IPSET_ERR_EXIST;
    assert(ipset_add_batch(&dup, "HydraRoute", &host, 1, 1, &new_count, new_idx) == 0);
    assert(sent_count == 2 && dup.permanent.count == 5 && dup.permanent.cap == 16);
    for (int i = 0; i < 5; i++) {
        parsed_cidr_t h = host;
        h.ip[3] = (uint8_t)(100 + i);
        reset();
        assert(ipset_add_batch(&dup, "HydraRoute", &h, 1, 0, &new_count, new_idx) == 0);
    }
    assert(dup.permanent.count == 10 && !dup.permanent.sorted);
    for (int i = 0; i < 5; i++) {
        parsed_cidr_t h = host;
        h.ip[3] = (uint8_t)(100 + i);
        reset();
        replies[0] = IPSET_ERR_EXIST;
        assert(ipset_add_batch(&dup, "HydraRoute", &h, 1, 1, &new_count, new_idx) == 0);
        assert(sent_count == 1);
    }
    assert(dup.permanent.count == 5);
    dup.fd = -1;
    ipset_manager_close(&dup);

    /* A restart: the kernel keeps what the last run loaded, the new manager
     * knows only the current list. A host still listed stays permanent, one
     * removed from the list but left in the kernel is a plain entry again. */
    ipset_manager_t run2;
    memset(&run2, 0, sizeof(run2));
    run2.default_timeout = 21600;
    parsed_cidr_t kept = host, dropped = host;
    kept.ip[3] = 21; dropped.ip[3] = 22;
    reset();    /* already in the kernel from the last run: the list's ADD is not exclusive */
    assert(ipset_add_batch(&run2, "HydraRoute", &kept, 1, 0, &new_count, new_idx) == 0);
    reset();
    replies[0] = IPSET_ERR_EXIST;
    assert(ipset_add_batch(&run2, "HydraRoute", &kept, 1, 1, &new_count, new_idx) == 0);
    assert(sent_count == 1);
    reset();
    replies[0] = IPSET_ERR_EXIST;
    assert(ipset_add_batch(&run2, "HydraRoute", &dropped, 1, 1, &new_count, new_idx) == 0);
    assert(sent_count == 2 && !(sent_flags[1] & NLM_F_EXCL));
    run2.fd = -1;
    ipset_manager_close(&run2);

    /* The first allocation fails: the set is marked, its existing entries are
     * not refreshed (even DNS ones), one WARN, new addresses still go in, and
     * another set is not touched. */
    ipset_manager_t oom;
    memset(&oom, 0, sizeof(oom));
    oom.default_timeout = 21600;
    log_buf[0] = '\0';
    realloc_fail = 1;
    reset();
    assert(ipset_add_batch(&oom, "A", &host, 1, 0, &new_count, new_idx) == 0);
    assert(oom.permanent.keys == NULL && oom.permanent.count == 0);
    assert(ipset_perm_incomplete(&oom, "A") && !ipset_perm_incomplete(&oom, "B"));
    assert(count_of("permanent-host index incomplete for A: refresh disabled") == 1);
    reset();
    replies[0] = IPSET_ERR_EXIST;
    assert(ipset_add_batch(&oom, "A", &host, 1, 1, &new_count, new_idx) == 0);
    assert(sent_count == 1);
    reset();
    assert(ipset_add_batch(&oom, "A", &above, 1, 1, &new_count, new_idx) == 0);
    assert(sent_count == 1 && new_count == 1);
    reset();
    replies[0] = IPSET_ERR_EXIST;
    assert(ipset_add_batch(&oom, "B", &host, 1, 1, &new_count, new_idx) == 0);
    assert(sent_count == 2);
    reset();
    assert(ipset_add_batch(&oom, "B", &host, 1, 0, &new_count, new_idx) == 0);
    reset();
    replies[0] = IPSET_ERR_EXIST;
    assert(ipset_add_batch(&oom, "B", &host, 1, 1, &new_count, new_idx) == 0);
    assert(sent_count == 1);
    assert(count_of("incomplete") == 1);
    oom.fd = -1;
    ipset_manager_close(&oom);

    /* A later growth fails: the four keys stay, the set stops refreshing, the
     * second failure of the same set says nothing more. */
    memset(&oom, 0, sizeof(oom));
    oom.default_timeout = 21600;
    log_buf[0] = '\0';
    for (int i = 0; i < 4; i++) {
        parsed_cidr_t h = host;
        h.ip[3] = (uint8_t)(50 + i);
        reset();
        assert(ipset_add_batch(&oom, "A", &h, 1, 0, &new_count, new_idx) == 0);
    }
    assert(oom.permanent.cap == 4 && !ipset_perm_incomplete(&oom, "A"));
    realloc_fail = 1;
    parsed_cidr_t fifth = host;
    fifth.ip[3] = 54;
    reset();
    assert(ipset_add_batch(&oom, "A", &fifth, 1, 0, &new_count, new_idx) == 0);
    assert(oom.permanent.count == 4 && ipset_perm_incomplete(&oom, "A"));
    assert(!ipset_perm_incomplete(&oom, "B"));
    realloc_fail = 1;
    reset();
    assert(ipset_add_batch(&oom, "A", &fifth, 1, 0, &new_count, new_idx) == 0);
    assert(count_of("incomplete for A") == 1);
    for (int i = 0; i < 5; i++) {
        parsed_cidr_t h = host;
        h.ip[3] = (uint8_t)(50 + i);
        reset();
        replies[0] = IPSET_ERR_EXIST;
        assert(ipset_add_batch(&oom, "A", &h, 1, 1, &new_count, new_idx) == 0);
        assert(sent_count == 1);
    }
    reset();
    replies[0] = IPSET_ERR_EXIST;
    assert(ipset_add_batch(&oom, "B", &above, 1, 1, &new_count, new_idx) == 0);
    assert(sent_count == 2);
    oom.fd = -1;
    ipset_manager_close(&oom);

    /* No memory even for the name: the safe side is every set. */
    memset(&oom, 0, sizeof(oom));
    oom.default_timeout = 21600;
    log_buf[0] = '\0';
    realloc_fail = 2;
    reset();
    assert(ipset_add_batch(&oom, "A", &host, 1, 0, &new_count, new_idx) == 0);
    assert(ipset_perm_incomplete(&oom, "A") && ipset_perm_incomplete(&oom, "Z"));
    assert(count_of("incomplete for all sets") == 1);
    oom.fd = -1;
    ipset_manager_close(&oom);

    /* Capacity that cannot double (or be multiplied by the key size) is a
     * failed allocation, without calling realloc for the keys. */
    memset(&oom, 0, sizeof(oom));
    oom.default_timeout = 21600;
    oom.permanent.keys = malloc(1);
    oom.permanent.count = oom.permanent.cap = SIZE_MAX / sizeof(ipset_perm_key_t);
    realloc_calls = 0;
    reset();
    assert(ipset_add_batch(&oom, "A", &host, 1, 0, &new_count, new_idx) == 0);
    assert(realloc_calls == 1);                       /* only the set name */
    assert(ipset_perm_incomplete(&oom, "A") && oom.permanent.count == oom.permanent.cap);
    oom.permanent.cap = SIZE_MAX / 2 + 1;
    oom.permanent.count = oom.permanent.cap;
    realloc_calls = 0;
    assert(ipset_add_batch(&oom, "C", &host, 1, 0, &new_count, new_idx) == 0);
    assert(realloc_calls == 1 && ipset_perm_incomplete(&oom, "C"));
    oom.fd = -1;
    ipset_manager_close(&oom);

    puts("check_ipset_refresh: OK");
    return 0;
}
