#include "../include/ipset_nl.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <linux/netlink.h>
#include <errno.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>

/* Fake kernel. Every fake socket keeps its own receive queue between calls,
 * as a real one does: a send is processed at once and queues its answer (an
 * NLMSG_ERROR with the request's sequence and the scripted errno; a TYPE
 * reply for IPSET_CMD_TYPE); a recv takes the oldest answer, or fails with
 * EAGAIN when there is none, which is what SO_RCVTIMEO gives when it runs
 * out. A closed socket drops what it holds and what still comes for it. */
#define FD_BASE 100
#define NSOCK   4
#define QMAX    64
typedef struct {
    int      open;
    long     timeo_ms;              /* SO_RCVTIMEO, -1 while not set */
    uint32_t seq[QMAX];
    int      err[QMAX];
    int      type_reply[QMAX];
    int      head, len;
    int      gen;                   /* which socket this is: fd numbers are reused */
} fsock_t;
static fsock_t socks[NSOCK];
static int sockets_opened, sockets_closed, gen_counter;

static uint16_t sent_flags[64];
static uint32_t sent_seq[64];
static uint8_t last_msg[256];       /* the last message sent */
static int sent_count, send_calls, recv_count;
static int replies[64];             /* the answer (errno) to the n-th message sent since reset() */
static int send_fail_at = -1, send_errno;   /* the n-th send since reset() fails: not processed */
static int drop_at = -1;            /* the answer to the n-th message is lost (see deliver_late) */
static int recv_errno, recv_fail_at = -1, recv_short_at = -1, recv_seq_off_at = -1, recv_eintr_at = -1;
static int recv_noop_at = -1;       /* the n-th recv gets a message of its sequence that is no ACK */
static int socket_fail;             /* the next socket_fail socket() calls fail */
static int lost_fd = -1, lost_gen, lost_err;
static uint32_t lost_seq;
static long clock_ms, clock_step_ms;        /* CLOCK_MONOTONIC: + clock_step_ms per read */

static fsock_t *sock_of(int fd) {
    assert(fd >= FD_BASE && fd < FD_BASE + NSOCK && socks[fd - FD_BASE].open);
    return &socks[fd - FD_BASE];
}

static void push(fsock_t *s, uint32_t seq, int err, int type_reply) {
    assert(s->len < QMAX);
    int at = (s->head + s->len++) % QMAX;
    s->seq[at] = seq;
    s->err[at] = err;
    s->type_reply[at] = type_reply;
}

/* An answer to an older request, already queued (left by a call before). */
static void queue_stale(int fd, uint32_t seq, int err) {
    push(sock_of(fd), seq, err, 0);
}

/* The lost answer turns up late: on its socket, if that one is still open
 * (not a new socket that got the same fd number). */
static void deliver_late(void) {
    fsock_t *s = lost_fd >= 0 ? &socks[lost_fd - FD_BASE] : NULL;
    if (s && s->open && s->gen == lost_gen) push(s, lost_seq, lost_err, 0);
    lost_fd = -1;
}

static int queued(int fd) {
    return sock_of(fd)->len;
}

static int gen_of(int fd) {
    return sock_of(fd)->gen;
}

int __wrap_socket(int domain, int type, int protocol) {
    assert(domain == AF_NETLINK && type == (SOCK_RAW | SOCK_CLOEXEC) && protocol == NETLINK_NETFILTER);
    if (socket_fail > 0) {
        socket_fail--;
        errno = ENOMEM;
        return -1;
    }
    for (int i = 0; i < NSOCK; i++) {
        if (socks[i].open) continue;
        memset(&socks[i], 0, sizeof(socks[i]));
        socks[i].open = 1;
        socks[i].timeo_ms = -1;
        socks[i].gen = ++gen_counter;
        sockets_opened++;
        return FD_BASE + i;
    }
    errno = EMFILE;
    return -1;
}

int __wrap_bind(int fd, const struct sockaddr *sa, socklen_t len) {
    sock_of(fd);
    assert(len == sizeof(struct sockaddr_nl) && sa->sa_family == AF_NETLINK);
    assert(((const struct sockaddr_nl *)(const void *)sa)->nl_pid == 0);
    return 0;
}

int __wrap_setsockopt(int fd, int level, int name, const void *val, socklen_t len) {
    fsock_t *s = sock_of(fd);
    const struct timeval *tv = val;
    assert(level == SOL_SOCKET && name == SO_RCVTIMEO && len == sizeof(*tv));
    s->timeo_ms = tv->tv_sec * 1000L + tv->tv_usec / 1000L;
    return 0;
}

int __real_close(int fd);
int __wrap_close(int fd) {
    if (fd < FD_BASE || fd >= FD_BASE + NSOCK) return __real_close(fd);
    sock_of(fd)->open = 0;              /* also: no second close */
    sockets_closed++;
    return 0;
}

ssize_t __wrap_send(int fd, const void *buf, size_t len, int flags) {
    fsock_t *s = sock_of(fd);
    const struct nlmsghdr *h = buf;
    assert(flags == 0 && len >= NLMSG_HDRLEN && h->nlmsg_len == len);
    if (send_calls++ == send_fail_at) {
        errno = send_errno;
        return -1;
    }
    int k = sent_count++;
    if (k < 64) {
        sent_seq[k] = h->nlmsg_seq;
        sent_flags[k] = h->nlmsg_flags;
    }
    memcpy(last_msg, buf, len < sizeof(last_msg) ? len : sizeof(last_msg));
    int type_reply = (h->nlmsg_type & 0xff) == IPSET_CMD_TYPE;
    if (k == drop_at) {
        lost_fd = fd;
        lost_gen = s->gen;
        lost_seq = h->nlmsg_seq;
        lost_err = replies[k];
        return (ssize_t)len;
    }
    push(s, h->nlmsg_seq, replies[k], type_reply);
    return (ssize_t)len;
}

ssize_t __wrap_recv(int fd, void *buf, size_t len, int flags) {
    fsock_t *s = sock_of(fd);
    assert(flags == 0);
    if (recv_count == recv_eintr_at) {
        recv_eintr_at = -1;
        errno = EINTR;
        return -1;
    }
    int r = recv_count++;
    if (r == recv_fail_at) {
        errno = recv_errno;
        return -1;
    }
    if (s->len == 0) {
        errno = EAGAIN;
        return -1;
    }
    int at = s->head;
    s->head = (s->head + 1) % QMAX;
    s->len--;
    uint8_t msg[64];
    struct nlmsghdr *h = (struct nlmsghdr *)msg;
    memset(msg, 0, sizeof(msg));
    h->nlmsg_seq = s->seq[at] + (r == recv_seq_off_at);
    if (s->type_reply[at]) {
        /* nfgenmsg, then IPSET_ATTR_REVISION = 3 */
        h->nlmsg_type = (NFNL_SUBSYS_IPSET << 8) | IPSET_CMD_TYPE;
        uint16_t alen = NLA_HDRLEN + 1, atype = IPSET_ATTR_REVISION;
        memcpy(msg + NLMSG_HDRLEN + 4, &alen, 2);
        memcpy(msg + NLMSG_HDRLEN + 6, &atype, 2);
        msg[NLMSG_HDRLEN + 4 + NLA_HDRLEN] = 3;
        h->nlmsg_len = NLMSG_HDRLEN + 4 + NLA_ALIGN(alen);
    } else {
        struct nlmsgerr *e = (struct nlmsgerr *)(msg + NLMSG_HDRLEN);
        h->nlmsg_type = NLMSG_ERROR;
        h->nlmsg_len = NLMSG_HDRLEN + sizeof(*e);
        e->error = -s->err[at];
        e->msg.nlmsg_seq = s->seq[at];
    }
    if (r == recv_noop_at) h->nlmsg_type = NLMSG_NOOP;
    size_t n = r == recv_short_at ? NLMSG_HDRLEN : h->nlmsg_len;     /* a cut answer */
    if (n > len) n = len;
    memcpy(buf, msg, n);
    return (ssize_t)n;
}

int __real_clock_gettime(clockid_t clk, struct timespec *ts);
int __wrap_clock_gettime(clockid_t clk, struct timespec *ts) {
    if (clk != CLOCK_MONOTONIC) return __real_clock_gettime(clk, ts);
    clock_ms += clock_step_ms;
    ts->tv_sec = clock_ms / 1000;
    ts->tv_nsec = clock_ms % 1000 * 1000000L;
    return 0;
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

/* Scripts and counters start over; the queues of open sockets stay. */
static void reset(void) {
    sent_count = send_calls = recv_count = 0;
    memset(replies, 0, sizeof(replies));
    send_fail_at = drop_at = -1;
    recv_fail_at = recv_short_at = recv_seq_off_at = recv_eintr_at = recv_noop_at = -1;
    socket_fail = 0;
    clock_step_ms = 0;
}

/* IPSET_ATTR_REVISION of the last message sent (a CREATE), -1 if none. */
static int last_revision(void) {
    const struct nlmsghdr *h = (const struct nlmsghdr *)last_msg;
    size_t pos = NLMSG_HDRLEN + 4;
    while (pos + NLA_HDRLEN <= h->nlmsg_len && pos + NLA_HDRLEN <= sizeof(last_msg)) {
        uint16_t alen, atype;
        memcpy(&alen, last_msg + pos, 2);
        memcpy(&atype, last_msg + pos + 2, 2);
        if (alen < NLA_HDRLEN) break;
        if (atype == IPSET_ATTR_REVISION) return last_msg[pos + NLA_HDRLEN];
        pos += NLA_ALIGN(alen);
    }
    return -1;
}

static void new_mgr(ipset_manager_t *m, uint32_t timeout) {
    assert(ipset_manager_init(m) == 0);
    m->default_timeout = timeout;
}

int main(void) {
    ipset_manager_t mgr;
    new_mgr(&mgr, 21600);

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
    new_mgr(&plain, 0);
    reset();
    assert(ipset_add_batch(&plain, "HydraRoute", &host, 1, 0, &new_count, new_idx) == 0);
    assert(plain.permanent.count == 0 && plain.permanent.keys == NULL);
    ipset_manager_close(&plain);

    ipset_manager_close(&mgr);
    assert(mgr.permanent.keys == NULL && mgr.permanent.count == 0);

    /* Many permanent hosts loaded in any order: each is found after the one
     * sort, its neighbours (DNS entries) are not, and a host added after a
     * lookup is found too. RFC 5737 addresses only. */
    static const uint8_t doc[3][3] = {{192, 0, 2}, {198, 51, 100}, {203, 0, 113}};
    ipset_manager_t big;
    new_mgr(&big, 21600);
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
    ipset_manager_close(&big);
    assert(big.permanent.keys == NULL);

    /* An empty array finds nothing and a lookup does not sort anything. */
    ipset_manager_t one;
    new_mgr(&one, 21600);
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
    ipset_manager_close(&one);

    /* Repeated keys: the same host twice before the first lookup, the same
     * list loaded again after it, a repeat after the dedupe. One key each. */
    ipset_manager_t dup;
    new_mgr(&dup, 21600);
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
    ipset_manager_close(&dup);

    /* A restart: the kernel keeps what the last run loaded, the new manager
     * knows only the current list. A host still listed stays permanent, one
     * removed from the list but left in the kernel is a plain entry again. */
    ipset_manager_t run2;
    new_mgr(&run2, 21600);
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
    ipset_manager_close(&run2);

    /* The first allocation fails: the set is marked, its existing entries are
     * not refreshed (even DNS ones), one WARN, new addresses still go in, and
     * another set is not touched. */
    ipset_manager_t oom;
    new_mgr(&oom, 21600);
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
    ipset_manager_close(&oom);

    /* A later growth fails: the four keys stay, the set stops refreshing, the
     * second failure of the same set says nothing more. */
    new_mgr(&oom, 21600);
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
    ipset_manager_close(&oom);

    /* No memory even for the name: the safe side is every set. */
    new_mgr(&oom, 21600);
    log_buf[0] = '\0';
    realloc_fail = 2;
    reset();
    assert(ipset_add_batch(&oom, "A", &host, 1, 0, &new_count, new_idx) == 0);
    assert(ipset_perm_incomplete(&oom, "A") && ipset_perm_incomplete(&oom, "Z"));
    assert(count_of("incomplete for all sets") == 1);
    ipset_manager_close(&oom);

    /* Capacity that cannot double (or be multiplied by the key size) is a
     * failed allocation, without calling realloc for the keys. */
    new_mgr(&oom, 21600);
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
    ipset_manager_close(&oom);

    /* Ruling 50: every answer is matched to its own request, also across
     * calls. The fake keeps each socket's queue between calls, as the kernel
     * does, so an answer left behind by one call would reach the next. */
    parsed_cidr_t dns_a = e, dns_b = e;
    dns_a.ip[3] = 20;
    dns_b.ip[3] = 21;
    ipset_manager_t q;
    int pair_idx[2], g0;

    /* The first ADD of a DNS answer is sent, the second send fails. The
     * answer to the first is still read: dns_a went in and is reported new
     * (ConntrackFlush relies on it); dns_b is not in. The socket is then
     * replaced, so nothing queued on it can shift a later call. */
    new_mgr(&q, 21600);
    g0 = gen_of(q.fd);
    parsed_cidr_t pair[2] = {dns_a, dns_b};
    reset();
    send_fail_at = 1;
    send_errno = ENOBUFS;
    assert(ipset_add_batch(&q, "HydraRoute", pair, 2, 1, &new_count, pair_idx) == -1);
    assert(sent_count == 1 && new_count == 1 && pair_idx[0] == 0);
    assert(gen_of(q.fd) != g0 && queued(q.fd) == 0);
    /* Several DNS answers after it: a known IP is refreshed, a new one is
     * reported new, every time. */
    for (int round = 0; round < 3; round++) {
        reset();
        replies[0] = IPSET_ERR_EXIST;
        assert(ipset_add_batch(&q, "HydraRoute", &dns_a, 1, 1, &new_count, new_idx) == 0);
        assert(sent_count == 2 && (sent_flags[0] & NLM_F_EXCL) && !(sent_flags[1] & NLM_F_EXCL));
        assert(new_count == 0);
        parsed_cidr_t fresh = dns_b;
        fresh.ip[3] = (uint8_t)(30 + round);
        reset();
        assert(ipset_add_batch(&q, "HydraRoute", &fresh, 1, 1, &new_count, new_idx) == 0);
        assert(sent_count == 1 && new_count == 1 && new_idx[0] == 0);
        assert(queued(q.fd) == 0);
    }
    /* A send that fails ends the batch: the next chunk is not tried. */
    static parsed_cidr_t many[IPSET_CHUNK_SIZE + 2];
    for (int i = 0; i < IPSET_CHUNK_SIZE + 2; i++) {
        many[i] = host;
        many[i].ip[2] = (uint8_t)(i / 200);
        many[i].ip[3] = (uint8_t)(i % 200 + 1);
    }
    reset();
    send_fail_at = 5;
    send_errno = ENOBUFS;
    assert(ipset_add_batch(&q, "M", many, IPSET_CHUNK_SIZE + 2, 0, &new_count, new_idx) == -1);
    assert(send_calls == 6 && sent_count == 5 && ipset_perm_incomplete(&q, "M"));
    assert(queued(q.fd) == 0);
    /* The first one was known: its refresh still goes out, on the new socket. */
    g0 = gen_of(q.fd);
    reset();
    replies[0] = IPSET_ERR_EXIST;
    send_fail_at = 1;
    send_errno = ENOBUFS;
    assert(ipset_add_batch(&q, "HydraRoute", pair, 2, 1, &new_count, pair_idx) == -1);
    assert(sent_count == 2 && !(sent_flags[1] & NLM_F_EXCL) && sent_seq[1] != sent_seq[0]);
    assert(new_count == 0 && gen_of(q.fd) != g0 && queued(q.fd) == 0);
    /* The same on the permanent path: the host that went in is remembered,
     * the set whose ADD was not sent stops refreshing, another set does not. */
    parsed_cidr_t perm2[2] = {host, host};
    perm2[1].ip[3] = 9;
    size_t kept_before = q.permanent.count;
    g0 = gen_of(q.fd);
    reset();
    send_fail_at = 1;
    send_errno = ENOBUFS;
    assert(ipset_add_batch(&q, "P", perm2, 2, 0, &new_count, new_idx) == -1);
    assert(ipset_perm_incomplete(&q, "P") && q.permanent.count == kept_before + 1);
    assert(gen_of(q.fd) != g0 && queued(q.fd) == 0);
    reset();
    replies[0] = IPSET_ERR_EXIST;
    assert(ipset_add_batch(&q, "Other", &dns_a, 1, 1, &new_count, new_idx) == 0);
    assert(sent_count == 2 && new_count == 0);

    /* Every socket has a 1 s receive timeout, the first one and each that
     * replaces it: a lost answer cannot hold up the main loop. */
    assert(sock_of(q.fd)->timeo_ms == 1000);
    ipset_manager_close(&q);
    new_mgr(&q, 21600);
    assert(sock_of(q.fd)->timeo_ms == 1000);

    /* The answer to a DNS ADD is lost: one recv, which times out, then the
     * call returns. The answer turns up later, on the replaced socket, and
     * does not reach the next calls. */
    g0 = gen_of(q.fd);
    reset();
    drop_at = 0;
    assert(ipset_add_batch(&q, "HydraRoute", &dns_a, 1, 1, &new_count, new_idx) == -1);
    assert(recv_count == 1 && new_count == 0);
    assert(gen_of(q.fd) != g0 && sock_of(q.fd)->timeo_ms == 1000);
    deliver_late();
    for (int round = 0; round < 2; round++) {
        reset();
        replies[0] = IPSET_ERR_EXIST;
        assert(ipset_add_batch(&q, "HydraRoute", &dns_a, 1, 1, &new_count, new_idx) == 0);
        assert(sent_count == 2 && new_count == 0);
        reset();
        assert(ipset_add_batch(&q, "HydraRoute", &dns_b, 1, 1, &new_count, new_idx) == 0);
        assert(new_count == 1);
    }
    /* Lost on a permanent ADD: the result is unknown, so the set's index
     * may lack the host. */
    reset();
    drop_at = 0;
    assert(ipset_add_batch(&q, "L", &host, 1, 0, &new_count, new_idx) == -1);
    assert(recv_count == 1 && ipset_perm_incomplete(&q, "L"));
    deliver_late();
    assert(queued(q.fd) == 0);
    /* Lost on the refresh of an EXIST: the next call is not shifted either. */
    g0 = gen_of(q.fd);
    reset();
    replies[0] = IPSET_ERR_EXIST;
    drop_at = 1;
    assert(ipset_add_batch(&q, "HydraRoute", &dns_a, 1, 1, &new_count, new_idx) == 0);
    assert(sent_count == 2 && gen_of(q.fd) != g0);
    deliver_late();
    reset();
    replies[0] = IPSET_ERR_EXIST;
    assert(ipset_add_batch(&q, "HydraRoute", &dns_a, 1, 1, &new_count, new_idx) == 0);
    assert(sent_count == 2 && queued(q.fd) == 0);

    /* Answers to older requests already queued are skipped, wherever they
     * came from: the call reads its own and keeps its socket. */
    g0 = gen_of(q.fd);
    reset();
    queue_stale(q.fd, q.seq - 3, 0);
    queue_stale(q.fd, q.seq - 1, IPSET_ERR_EXIST);
    replies[0] = IPSET_ERR_EXIST;
    assert(ipset_add_batch(&q, "HydraRoute", &dns_a, 1, 1, &new_count, new_idx) == 0);
    assert(sent_count == 2 && new_count == 0 && recv_count == 4);
    assert(gen_of(q.fd) == g0 && queued(q.fd) == 0);
    reset();
    queue_stale(q.fd, q.seq - 2, 0);
    assert(ipset_add_batch(&q, "HydraRoute", &dns_b, 1, 1, &new_count, new_idx) == 0);
    assert(new_count == 1 && gen_of(q.fd) == g0);
    reset();
    queue_stale(q.fd, q.seq - 1, 1);            /* an EPERM of someone else's */
    assert(ipset_add_batch(&q, "S", &host, 1, 0, &new_count, new_idx) == 0);
    assert(!ipset_perm_incomplete(&q, "S") && gen_of(q.fd) == g0);
    /* The other requests on this socket match their answers the same way. */
    reset();
    queue_stale(q.fd, q.seq - 1, 1);
    assert(ipset_flush(&q, "S") == 0);
    assert(gen_of(q.fd) == g0 && queued(q.fd) == 0);
    reset();
    queue_stale(q.fd, q.seq - 1, 1);
    assert(ipset_create(&q, "C", IPSET_HASH_TYPE, AF_INET, 21600, 1024) == 0);
    assert(sent_count == 2 && gen_of(q.fd) == g0 && queued(q.fd) == 0);
    assert(last_revision() == 3);               /* from the TYPE reply, not the stale answer */
    /* Skipping old answers counts against the same 1 s: a stream of them
     * ends in a timeout, a reopened socket and, for a permanent ADD, an
     * incomplete index. */
    reset();
    for (int i = 0; i < 40; i++) queue_stale(q.fd, q.seq - 100 + (uint32_t)i, 0);
    clock_step_ms = 100;
    assert(ipset_add_batch(&q, "T", &host, 1, 0, &new_count, new_idx) == -1);
    assert(recv_count >= 5 && recv_count <= 12);
    assert(ipset_perm_incomplete(&q, "T") && gen_of(q.fd) != g0 && queued(q.fd) == 0);
    clock_step_ms = 0;

    /* The new socket cannot be had at once (socket() fails): the manager is
     * left without one, and the next call opens it. Until it can, a call
     * fails; a permanent ADD then leaves its set incomplete. */
    reset();
    log_buf[0] = '\0';
    drop_at = 0;
    socket_fail = 1;
    assert(ipset_add_batch(&q, "HydraRoute", &dns_a, 1, 1, &new_count, new_idx) == -1);
    assert(q.fd == -1 && count_of("netlink socket: ") == 1);
    reset();
    socket_fail = 2;
    assert(ipset_add_batch(&q, "U", &host, 1, 0, &new_count, new_idx) == -1);
    assert(sent_count == 0 && q.fd == -1 && ipset_perm_incomplete(&q, "U"));
    assert(ipset_flush(&q, "U") == -1 && q.fd == -1);
    reset();
    replies[0] = IPSET_ERR_EXIST;
    assert(ipset_add_batch(&q, "HydraRoute", &dns_a, 1, 1, &new_count, new_idx) == 0);
    assert(q.fd >= 0 && sent_count == 2 && sock_of(q.fd)->timeo_ms == 1000);
    ipset_manager_close(&q);
    assert(!socks[0].open && !socks[1].open && !socks[2].open && !socks[3].open);

    /* The answer to a permanent ADD is lost or wrong: the host may be in the
     * set without being in the index. The load says so, the set stops
     * refreshing, and the DNS answer for the kept host leaves it alone. */
    static const struct { const char *what; int *at; int val; int err; } bad[] = {
        {"recv error", &recv_fail_at, 0, ENOBUFS},
        {"short answer", &recv_short_at, 0, 0},
        {"foreign sequence", &recv_seq_off_at, 0, 0},
        {"not an ACK", &recv_noop_at, 0, 0},
    };
    for (size_t b = 0; b < sizeof(bad) / sizeof(bad[0]); b++) {
        ipset_manager_t lost;
        new_mgr(&lost, 21600);
        parsed_cidr_t two[2] = {host, host};
        two[1].ip[3] = 9;
        int gen_before = gen_of(lost.fd);
        reset();
        *bad[b].at = bad[b].val;
        recv_errno = bad[b].err;
        assert(ipset_add_batch(&lost, "K", two, 2, 0, &new_count, new_idx) == -1);
        assert(ipset_perm_incomplete(&lost, "K") && !ipset_perm_incomplete(&lost, "Other"));
        /* Out of step from here on: no answer after it is read, the socket
         * is replaced. */
        assert(recv_count == 1 && gen_of(lost.fd) != gen_before && queued(lost.fd) == 0);
        reset();
        replies[0] = IPSET_ERR_EXIST;
        assert(ipset_add_batch(&lost, "K", &host, 1, 1, &new_count, new_idx) == 0);
        assert(sent_count == 1);
        reset();
        replies[0] = IPSET_ERR_EXIST;
        assert(ipset_add_batch(&lost, "Other", &host, 1, 1, &new_count, new_idx) == 0);
        assert(sent_count == 2);
        ipset_manager_close(&lost);
    }
    /* EINTR is retried and is no failure; a kernel error on a permanent ADD is. */
    ipset_manager_t intr;
    new_mgr(&intr, 21600);
    reset();
    recv_eintr_at = 0;
    assert(ipset_add_batch(&intr, "K", &host, 1, 0, &new_count, new_idx) == 0);
    assert(!ipset_perm_incomplete(&intr, "K") && intr.permanent.count == 1);
    reset();
    replies[0] = 1;    /* EPERM */
    assert(ipset_add_batch(&intr, "E", &host, 1, 0, &new_count, new_idx) == -1);
    assert(ipset_perm_incomplete(&intr, "E"));
    /* Set full and an entry that already exists are no loss of the index. */
    reset();
    replies[0] = IPSET_ERR_HASH_FULL;
    assert(ipset_add_batch(&intr, "F", &host, 1, 0, &new_count, new_idx) == 0);
    assert(!ipset_perm_incomplete(&intr, "F"));
    reset();
    replies[0] = IPSET_ERR_EXIST;
    assert(ipset_add_batch(&intr, "X", &host, 1, 0, &new_count, new_idx) == 0);
    assert(!ipset_perm_incomplete(&intr, "X"));
    reset();
    replies[0] = IPSET_ERR_EXIST;
    assert(ipset_add_batch(&intr, "X", &host, 1, 1, &new_count, new_idx) == 0);
    assert(sent_count == 1);
    ipset_manager_close(&intr);

    puts("check_ipset_refresh: OK");
    return 0;
}
