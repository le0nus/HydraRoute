#include "../include/rtnl.h"
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <linux/fib_rules.h>
#include <linux/rtnetlink.h>

/* Fake NETLINK_ROUTE socket. The kernel's answer is scripted as datagrams,
 * or errors, that recv hands out in order; SEQ_REQ in them becomes the
 * sequence number of the request when it is sent. */
#define SEQ_REQ     0xfffffff0u
#define SEQ_OTHER   0xdead0000u
#define FAKE_FD     99
#define MAX_DGRAMS  8
#define DGRAM_SIZE  (2 * RTNL_BUF_SIZE)
#define RULE_MAX    128
#define RULE_MSG    68                  /* an NDMS rule message, as put_rule builds it */

_Static_assert(RTNL_TIMEOUT_MS == 1000, "the fake expects a 1 s receive timeout");

static uint8_t dgram[MAX_DGRAMS][DGRAM_SIZE] __attribute__((aligned(4)));
static size_t dgram_len[MAX_DGRAMS];
static int dgram_errno[MAX_DGRAMS];     /* recv fails with this errno instead */
static int dgram_count, dgram_next;
static struct nlmsghdr *last;           /* the message put last */

static int open_fds, closes, sends, timeout_set;
static int fail_socket, fail_bind, fail_setsockopt, fail_send;
static int sent_type, sent_family;
static uint32_t sent_seq;

/* The clock (CLOCK_MONOTONIC, ms) moves only as the fake kernel takes time:
 * datagram d comes dgram_delay[d] ms after recv asks for it, and a recv with
 * nothing in time waits its whole SO_RCVTIMEO. Without a deadline every
 * SO_RCVTIMEO is RTNL_TIMEOUT_MS (expect_1s); with one, each is kept. */
static int64_t fake_ms = 100000;
static int dgram_delay[MAX_DGRAMS];
static int dgram_late;                  /* kernel rounding: an answer may come this much after
                                         * SO_RCVTIMEO and still be returned */
static int send_delay, bind_delay;      /* ms the request takes (rtnl_lock), and bind */
static int expect_1s = 1, clock_calls, recvs;
static long rcvtimeo_us[16];            /* each SO_RCVTIMEO set, in order */
static long sndtimeo_us;                /* SO_SNDTIMEO of this socket, 0 none */
static int rcvtimeo_n, setsockopts, fail_setsockopt_from;   /* the n-th and later setsockopt fail */

int __wrap_clock_gettime(clockid_t id, struct timespec *ts) {
    assert(id == CLOCK_MONOTONIC);
    clock_calls++;
    ts->tv_sec = (time_t)(fake_ms / 1000);
    ts->tv_nsec = (long)(fake_ms % 1000) * 1000000L;
    return 0;
}

static void patch_seq(void) {
    for (int d = 0; d < dgram_count; d++)
        for (size_t off = 0; off + NLMSG_HDRLEN <= dgram_len[d]; ) {
            struct nlmsghdr *h = (struct nlmsghdr *)(dgram[d] + off);
            if (h->nlmsg_len < NLMSG_HDRLEN) break;
            if (h->nlmsg_seq == SEQ_REQ) h->nlmsg_seq = sent_seq;
            off += NLMSG_ALIGN(h->nlmsg_len);
        }
}

int __wrap_socket(int domain, int type, int protocol) {
    assert(domain == AF_NETLINK && type == (SOCK_RAW | SOCK_CLOEXEC) && protocol == NETLINK_ROUTE);
    assert(open_fds == 0);
    if (fail_socket) {
        errno = EMFILE;
        return -1;
    }
    open_fds++;
    timeout_set = 0;
    sndtimeo_us = 0;
    return FAKE_FD;
}

int __wrap_bind(int fd, const struct sockaddr *addr, socklen_t len) {
    const struct sockaddr_nl *sa = (const struct sockaddr_nl *)addr;
    assert(fd == FAKE_FD && len == sizeof(*sa));
    assert(sa->nl_family == AF_NETLINK && sa->nl_pid == 0 && sa->nl_groups == 0);
    fake_ms += bind_delay;
    if (fail_bind) {
        errno = EADDRINUSE;
        return -1;
    }
    return 0;
}

int __wrap_setsockopt(int fd, int level, int name, const void *val, socklen_t len) {
    const struct timeval *tv = val;
    long us = (long)tv->tv_sec * 1000000L + tv->tv_usec;
    assert(fd == FAKE_FD && level == SOL_SOCKET && len == sizeof(*tv));
    assert(name == SO_RCVTIMEO || name == SO_SNDTIMEO);
    assert(tv->tv_usec >= 0 && tv->tv_usec < 1000000L);
    assert(us > 0 && us <= 1000000L);           /* 0 would mean no timeout at all */
    if (expect_1s) assert(us == 1000000L && name == SO_RCVTIMEO);   /* Task 3's dump, as it was */
    setsockopts++;
    if (fail_setsockopt || (fail_setsockopt_from && setsockopts >= fail_setsockopt_from)) {
        errno = ENOPROTOOPT;
        return -1;
    }
    if (name == SO_SNDTIMEO) {
        sndtimeo_us = us;
        return 0;
    }
    assert(rcvtimeo_n < 16);
    rcvtimeo_us[rcvtimeo_n++] = us;
    timeout_set = 1;
    return 0;
}

int __wrap_close(int fd) {
    assert(fd == FAKE_FD && open_fds == 1);
    open_fds--;
    closes++;
    return 0;
}

/* The request: a dump of one table of one family, nothing else. */
ssize_t __wrap_send(int fd, const void *buf, size_t len, int flags) {
    const struct nlmsghdr *h = buf;
    assert(fd == FAKE_FD && (timeout_set || sndtimeo_us) && flags == 0);
    assert(len == NLMSG_LENGTH(sizeof(struct rtmsg)) && h->nlmsg_len == len);
    assert(h->nlmsg_flags == (NLM_F_REQUEST | NLM_F_DUMP));
    sends++;
    sent_type = h->nlmsg_type;
    sent_seq = h->nlmsg_seq;
    sent_family = ((const struct rtmsg *)NLMSG_DATA(h))->rtm_family;
    if (sndtimeo_us && send_delay > sndtimeo_us / 1000) {
        fake_ms += sndtimeo_us / 1000;          /* SO_SNDTIMEO expired */
        errno = EAGAIN;
        return -1;
    }
    fake_ms += send_delay;
    if (fail_send) {
        errno = ECONNREFUSED;
        return -1;
    }
    patch_seq();
    return (ssize_t)len;
}

/* As netlink_recvmsg: at most len bytes are copied and the rest of the
 * datagram is lost; MSG_TRUNC returns its real length, MSG_PEEK leaves it
 * queued. Nothing queued: SO_RCVTIMEO expired. */
ssize_t __wrap_recv(int fd, void *buf, size_t len, int flags) {
    assert(fd == FAKE_FD && timeout_set);
    assert((flags & ~(MSG_TRUNC | MSG_PEEK)) == 0);
    long wait_ms = rcvtimeo_us[rcvtimeo_n - 1] / 1000;
    recvs++;
    if (dgram_next == dgram_count || dgram_delay[dgram_next] > wait_ms + dgram_late) {
        fake_ms += wait_ms;
        errno = EAGAIN;
        return -1;
    }
    int d = dgram_next;
    fake_ms += dgram_delay[d];
    if (dgram_errno[d]) {
        dgram_next++;
        errno = dgram_errno[d];
        return -1;
    }
    if (!(flags & MSG_PEEK)) dgram_next++;
    size_t n = dgram_len[d], copied = n < len ? n : len;
    memcpy(buf, dgram[d], copied);
    return (ssize_t)((flags & MSG_TRUNC) ? n : copied);
}

static void script_reset(void) {
    memset(dgram_len, 0, sizeof(dgram_len));
    memset(dgram_errno, 0, sizeof(dgram_errno));
    memset(dgram_delay, 0, sizeof(dgram_delay));
    dgram_count = dgram_next = 0;
    closes = sends = recvs = rcvtimeo_n = setsockopts = 0;
    dgram_late = send_delay = bind_delay = 0;
}

static void put_msg(int d, uint16_t type, uint16_t flags, uint32_t seq, const void *payload, size_t plen) {
    assert(d < MAX_DGRAMS && dgram_len[d] + NLMSG_SPACE(plen) <= DGRAM_SIZE);
    struct nlmsghdr *h = (struct nlmsghdr *)(dgram[d] + dgram_len[d]);
    memset(h, 0, NLMSG_SPACE(plen));
    h->nlmsg_len = (uint32_t)NLMSG_LENGTH(plen);
    h->nlmsg_type = type;
    h->nlmsg_flags = flags;
    h->nlmsg_seq = seq;
    if (plen) memcpy(NLMSG_DATA(h), payload, plen);
    dgram_len[d] += NLMSG_ALIGN(h->nlmsg_len);
    if (d >= dgram_count) dgram_count = d + 1;
    last = h;
}

static void put_errno(int d, int err) {
    dgram_errno[d] = err;
    if (d >= dgram_count) dgram_count = d + 1;
}

/* NLMSG_DONE carries the result of the dump: 0, or a negative errno. */
static void put_done(int d, uint32_t seq, int result) {
    put_msg(d, NLMSG_DONE, NLM_F_MULTI, seq, &result, sizeof(result));
}

static void put_error(int d, uint32_t seq, int error) {
    struct nlmsgerr e;
    memset(&e, 0, sizeof(e));
    e.error = error;
    put_msg(d, NLMSG_ERROR, 0, seq, &e, sizeof(e));
}

/* A rule as kernel 4.9 dumps it (fib_nl_fill_rule, fib4_rule_fill,
 * fib6_rule_fill): the header holds the low byte of the table, FRA_TABLE all
 * of it; FRA_SUPPRESS_PREFIXLEN always (-1 unless set); FRA_FWMASK whenever
 * there is a mark. */
typedef struct {
    uint8_t  family;            /* 0: AF_INET */
    uint8_t  action;            /* 0: FR_ACT_TO_TBL */
    uint8_t  dst_len, src_len, tos;
    uint32_t flags, mark, mask, table;
    int      mask_absent;       /* no FRA_FWMASK, which 4.9 never sends with a mark */
    int      suppress_set;      /* suppress_prefixlength <suppress> */
    uint32_t suppress;
    uint16_t extra, extra_len;  /* one more attribute: its type and payload length */
    uint16_t bad;               /* this u32 attribute gets a 2-byte payload */
    int      trailer;           /* after the attributes, 4 bytes that are none:
                                 * 1 a header shorter than itself, 2 longer than what is left */
} rule_t;

#define NDMS(m, t) ((rule_t){.mark = (m), .mask = 0xffffffffu, .table = (t)})

static size_t put_attr(uint8_t *p, size_t off, uint16_t type, const void *data, size_t len) {
    struct rtattr *a = (struct rtattr *)(p + off);
    a->rta_type = type;
    a->rta_len = (unsigned short)RTA_LENGTH(len);
    memset(RTA_DATA(a), 0, RTA_ALIGN(len));
    if (data) memcpy(RTA_DATA(a), data, len);
    return off + RTA_SPACE(len);
}

static size_t put_u32(uint8_t *p, size_t off, uint16_t type, uint32_t v, const rule_t *r) {
    return put_attr(p, off, type, &v, r->bad == type ? 2 : 4);
}

static size_t rule_payload(uint8_t *p, const rule_t *r) {
    struct fib_rule_hdr *frh = (struct fib_rule_hdr *)p;
    size_t off = NLMSG_ALIGN(sizeof(*frh));
    memset(p, 0, RULE_MAX);
    frh->family = r->family ? r->family : AF_INET;
    frh->dst_len = r->dst_len;
    frh->src_len = r->src_len;
    frh->tos = r->tos;
    frh->table = (uint8_t)r->table;
    frh->action = r->action ? r->action : FR_ACT_TO_TBL;
    frh->flags = r->flags;
    off = put_u32(p, off, FRA_TABLE, r->table, r);
    off = put_u32(p, off, FRA_SUPPRESS_PREFIXLEN, r->suppress_set ? r->suppress : 0xffffffffu, r);
    off = put_u32(p, off, FRA_PRIORITY, 1150, r);
    if (r->mark) off = put_u32(p, off, FRA_FWMARK, r->mark, r);
    if ((r->mark || r->mask) && !r->mask_absent) off = put_u32(p, off, FRA_FWMASK, r->mask, r);
    if (r->extra) off = put_attr(p, off, r->extra, NULL, r->extra_len);
    if (r->trailer) {
        struct rtattr *a = (struct rtattr *)(p + off);
        a->rta_len = r->trailer == 1 ? 2 : 64;
        a->rta_type = FRA_FLOW;
        off += 4;
    }
    assert(off <= RULE_MAX);
    return off;
}

static void put_rule(int d, uint32_t seq, rule_t r) {
    uint8_t p[RULE_MAX] __attribute__((aligned(4)));
    put_msg(d, RTM_NEWRULE, NLM_F_MULTI, seq, p, rule_payload(p, &r));
}

/* --- rtnl_parse on one datagram --------------------------------------- */

static int counted, cb_result;

static int count_msg(const struct nlmsghdr *h, void *ctx) {
    (void)h; (void)ctx;
    counted++;
    return cb_result;
}

static int parse(int d, size_t len) {
    return rtnl_parse(dgram[d], len, 42, count_msg, NULL);
}

static void check_parse(void) {
    /* A multipart reply over two datagrams. Messages of another request
     * (its end too), an ACK and a NOOP are skipped. */
    script_reset();
    put_rule(0, 42, NDMS(0xffffaaa, 4096));
    put_rule(0, SEQ_OTHER, NDMS(0xffffaaa, 4096));
    put_done(0, SEQ_OTHER, 0);
    put_error(0, 42, 0);
    put_msg(0, NLMSG_NOOP, 0, 42, NULL, 0);
    put_rule(1, 42, NDMS(0xffffaaa, 4096));
    put_done(1, 42, 0);
    counted = cb_result = 0;
    assert(parse(0, dgram_len[0]) == RTNL_MORE);
    assert(parse(1, dgram_len[1]) == RTNL_DONE);
    assert(counted == 2);

    /* Each of these fails the dump. */
    script_reset();
    put_error(0, 42, -EINVAL);
    assert(parse(0, dgram_len[0]) == RTNL_FAIL);

    script_reset();
    {
        int e = 0;                      /* an ACK cut to its error code */
        put_msg(0, NLMSG_ERROR, 0, 42, &e, sizeof(e));
    }
    assert(parse(0, dgram_len[0]) == RTNL_FAIL);

    script_reset();
    put_done(0, 42, -ENOBUFS);          /* the dump itself failed */
    assert(parse(0, dgram_len[0]) == RTNL_FAIL);

    script_reset();
    put_msg(0, NLMSG_DONE, NLM_F_MULTI, 42, NULL, 0);   /* no result */
    assert(parse(0, dgram_len[0]) == RTNL_FAIL);

    script_reset();
    put_done(0, 42, 0);
    last->nlmsg_flags |= NLM_F_DUMP_INTR;
    assert(parse(0, dgram_len[0]) == RTNL_FAIL);

    script_reset();
    put_msg(0, NLMSG_OVERRUN, 0, 42, NULL, 0);
    assert(parse(0, dgram_len[0]) == RTNL_FAIL);

    script_reset();
    put_msg(0, NLMSG_MIN_TYPE - 1, 0, 42, NULL, 0);    /* a reserved control type */
    assert(parse(0, dgram_len[0]) == RTNL_FAIL);

    script_reset();
    put_rule(0, 42, NDMS(0xffffaaa, 4096));
    last->nlmsg_flags |= NLM_F_DUMP_INTR;               /* the rules changed meanwhile */
    assert(parse(0, dgram_len[0]) == RTNL_FAIL);

    script_reset();
    put_rule(0, 42, NDMS(0xffffaaa, 4096));
    assert(parse(0, dgram_len[0] - 4) == RTNL_FAIL);    /* cut message */

    script_reset();
    put_rule(0, 42, NDMS(0xffffaaa, 4096));
    assert(parse(0, dgram_len[0] + 8) == RTNL_FAIL);    /* bytes after it that are no message */

    script_reset();
    put_rule(0, 42, NDMS(0xffffaaa, 4096));
    last->nlmsg_len = NLMSG_HDRLEN - 4;
    assert(parse(0, dgram_len[0]) == RTNL_FAIL);

    script_reset();
    put_rule(0, 42, NDMS(0xffffaaa, 4096));
    put_done(0, 42, 0);
    counted = 0;
    cb_result = -1;
    assert(parse(0, dgram_len[0]) == RTNL_FAIL && counted == 1);
    cb_result = 0;

    /* NLMSG_DONE ends the dump only once the rest of its datagram is
     * checked: bytes that are no message, a broken header, or anything of
     * this dump after it (an overrun, an error, a rule) fail the dump. A
     * message of another request may still follow. */
    script_reset();
    put_rule(0, 42, NDMS(0xffffaaa, 4096));
    put_done(0, 42, 0);
    assert(parse(0, dgram_len[0] + 8) == RTNL_FAIL);
    script_reset();
    put_done(0, 42, 0);
    put_rule(0, 42, NDMS(0xffffaaa, 4096));
    last->nlmsg_len = NLMSG_HDRLEN - 8;
    assert(parse(0, dgram_len[0]) == RTNL_FAIL);
    script_reset();
    put_done(0, 42, 0);
    put_msg(0, NLMSG_OVERRUN, 0, 42, NULL, 0);
    assert(parse(0, dgram_len[0]) == RTNL_FAIL);
    script_reset();
    put_done(0, 42, 0);
    put_error(0, 42, -EINVAL);
    assert(parse(0, dgram_len[0]) == RTNL_FAIL);
    script_reset();
    put_done(0, 42, 0);
    put_rule(0, 42, NDMS(0xffffaaa, 4096));
    assert(parse(0, dgram_len[0]) == RTNL_FAIL);
    script_reset();
    put_done(0, 42, 0);
    put_rule(0, SEQ_OTHER, NDMS(0xffffaaa, 4096));
    assert(parse(0, dgram_len[0]) == RTNL_DONE);
}

/* --- rtnl_dump and rtnl_fwmark_rules through the fake socket ---------- */

static rtnl_fwmark_rule_t want[3];

/* Looks up marks a, b, c (n of them); the tables start as garbage. */
static int lookup(int family, int n, uint32_t a, uint32_t b, uint32_t c) {
    uint32_t m[3] = {a, b, c};
    for (int k = 0; k < 3; k++) {
        want[k].mark = m[k];
        want[k].table = 0xdeadbeef;
    }
    int r = rtnl_fwmark_rules(family, want, n);
    assert(open_fds == 0);              /* the socket is closed on every path */
    return r;
}

static void check_dump(void) {
    /* What NDMS has: lookup local, the policy rule 1150 and the blackhole
     * 1151 behind it, a rule with a partial mask, and one whose mask was left
     * out (a full mask for a non-zero mark: see on_rule). Over two datagrams;
     * a mark twice in the request gets its table twice. */
    script_reset();
    put_rule(0, SEQ_REQ, (rule_t){.table = 255});
    put_rule(0, SEQ_REQ, NDMS(0xffffaaa, 4096));
    put_rule(0, SEQ_REQ, (rule_t){.action = FR_ACT_BLACKHOLE, .mark = 0xffffaaa, .mask = 0xffffffffu});
    put_rule(1, SEQ_REQ, (rule_t){.mark = 0x10000, .mask = 0x10000, .table = 300});
    put_rule(1, SEQ_REQ, (rule_t){.mark = 0x3001, .table = 301, .mask_absent = 1});
    put_done(1, SEQ_REQ, 0);
    assert(lookup(AF_INET, 3, 0xffffaaa, 0x3001, 0x10000) == 2);
    assert(want[0].table == 4096 && want[1].table == 301 && want[2].table == 0);
    assert(sends == 1 && closes == 1);
    assert(sent_type == RTM_GETRULE && sent_family == AF_INET);
    script_reset();
    put_rule(0, SEQ_REQ, NDMS(0xffffaaa, 4096));
    put_done(0, SEQ_REQ, 0);
    assert(lookup(AF_INET, 2, 0xffffaaa, 0xffffaaa, 0) == 2);
    assert(want[0].table == 4096 && want[1].table == 4096);

    /* Messages of another request are skipped, its end too. */
    script_reset();
    put_done(0, SEQ_OTHER, 0);
    put_rule(0, SEQ_OTHER, NDMS(0xff3, 4098));
    put_rule(1, SEQ_REQ, NDMS(0xff2, 4097));
    put_done(1, SEQ_REQ, 0);
    assert(lookup(AF_INET, 2, 0xff2, 0xff3, 0) == 1);
    assert(want[0].table == 4097 && want[1].table == 0);

    /* No NLMSG_DONE within RTNL_TIMEOUT_MS: the dump fails. */
    script_reset();
    put_rule(0, SEQ_REQ, NDMS(0xff2, 4097));
    assert(lookup(AF_INET, 1, 0xff2, 0, 0) == -1 && closes == 1);

    /* A signal interrupts recv: it is called again. */
    script_reset();
    put_errno(0, EINTR);
    put_rule(1, SEQ_REQ, NDMS(0xff2, 4097));
    put_done(1, SEQ_REQ, 0);
    assert(lookup(AF_INET, 1, 0xff2, 0, 0) == 1 && want[0].table == 4097);

    /* recv fails in the middle (the socket overran its buffer). */
    script_reset();
    put_rule(0, SEQ_REQ, NDMS(0xff2, 4097));
    put_errno(1, ENOBUFS);
    put_done(2, SEQ_REQ, 0);
    assert(lookup(AF_INET, 1, 0xff2, 0, 0) == -1);

    /* A datagram larger than the buffer fails, even when the part that
     * fits ends on a message boundary: without MSG_TRUNC recv would say
     * RTNL_BUF_SIZE, every message in it whole, and the dump would end with
     * the rule after them missing. */
    script_reset();
    put_rule(0, SEQ_REQ, NDMS(0x1000, 5000));
    assert(dgram_len[0] == RULE_MSG);
    for (uint32_t i = 1; RTNL_BUF_SIZE - dgram_len[0] >= 2 * RULE_MSG; i++)
        put_rule(0, SEQ_REQ, NDMS(0x1000 + i, 5000));
    /* one more rule, as long as the room left: an extra attribute fills it */
    put_rule(0, SEQ_REQ, (rule_t){.mark = 0xfff, .mask = 0xffffffffu, .table = 5000, .extra = 20,
                                  .extra_len = (uint16_t)(RTNL_BUF_SIZE - dgram_len[0] - RULE_MSG - 4)});
    assert(dgram_len[0] == RTNL_BUF_SIZE);
    put_rule(0, SEQ_REQ, NDMS(0xff2, 4097));
    put_done(1, SEQ_REQ, 0);
    assert(lookup(AF_INET, 1, 0xff2, 0, 0) == -1);

    /* Each step that fails ends the dump and closes the socket. */
    script_reset();
    fail_socket = 1;
    assert(lookup(AF_INET, 1, 0xff2, 0, 0) == -1 && closes == 0 && sends == 0);
    fail_socket = 0;
    fail_bind = 1;
    assert(lookup(AF_INET, 1, 0xff2, 0, 0) == -1 && closes == 1 && sends == 0);
    fail_bind = 0;
    script_reset();
    fail_setsockopt = 1;
    assert(lookup(AF_INET, 1, 0xff2, 0, 0) == -1 && closes == 1 && sends == 0);
    fail_setsockopt = 0;
    script_reset();
    fail_send = 1;
    put_rule(0, SEQ_REQ, NDMS(0xff2, 4097));
    put_done(0, SEQ_REQ, 0);
    assert(lookup(AF_INET, 1, 0xff2, 0, 0) == -1 && closes == 1 && dgram_next == 0);
    fail_send = 0;

    /* Every request gets its own sequence number. */
    {
        uint32_t seq;
        script_reset();
        put_done(0, SEQ_REQ, 0);
        assert(lookup(AF_INET, 1, 0xff2, 0, 0) == 0);
        seq = sent_seq;
        script_reset();
        put_done(0, SEQ_REQ, 0);
        assert(lookup(AF_INET, 1, 0xff2, 0, 0) == 0 && sent_seq != seq);
    }
}

/* The rule alone in a dump of the family. */
static int one_rule(int family, rule_t r) {
    script_reset();
    put_rule(0, SEQ_REQ, r);
    put_done(0, SEQ_REQ, 0);
    return lookup(family, 1, 0xff2, 0, 0);
}

/* Only NDMS's plain "fwmark M lookup T" counts as the policy's rule. */
static void check_profile(void) {
    static const struct {
        const char *what;
        rule_t r;
    } other[] = {
        {"partial mask",            {.mark = 0xff2, .mask = 0xff0, .table = 4097}},
        {"zero mask",               {.mark = 0xff2, .mask = 0, .table = 4097}},
        {"blackhole",               {.action = FR_ACT_BLACKHOLE, .mark = 0xff2, .mask = 0xffffffffu, .table = 4097}},
        {"unreachable",             {.action = FR_ACT_UNREACHABLE, .mark = 0xff2, .mask = 0xffffffffu, .table = 4097}},
        {"goto",                    {.action = FR_ACT_GOTO, .mark = 0xff2, .mask = 0xffffffffu, .table = 4097,
                                     .extra = FRA_GOTO, .extra_len = 4}},
        {"not fwmark",              {.flags = FIB_RULE_INVERT, .mark = 0xff2, .mask = 0xffffffffu, .table = 4097}},
        {"from",                    {.src_len = 24, .mark = 0xff2, .mask = 0xffffffffu, .table = 4097,
                                     .extra = FRA_SRC, .extra_len = 4}},
        {"to",                      {.dst_len = 24, .mark = 0xff2, .mask = 0xffffffffu, .table = 4097,
                                     .extra = FRA_DST, .extra_len = 4}},
        {"iif",                     {.mark = 0xff2, .mask = 0xffffffffu, .table = 4097,
                                     .extra = FRA_IIFNAME, .extra_len = 5}},
        {"oif",                     {.mark = 0xff2, .mask = 0xffffffffu, .table = 4097,
                                     .extra = FRA_OIFNAME, .extra_len = 5}},
        {"tos",                     {.tos = 0x10, .mark = 0xff2, .mask = 0xffffffffu, .table = 4097}},
        {"suppress_prefixlength",   {.mark = 0xff2, .mask = 0xffffffffu, .table = 4097,
                                     .suppress_set = 1, .suppress = 0}},
        {"suppress_ifgroup",        {.mark = 0xff2, .mask = 0xffffffffu, .table = 4097,
                                     .extra = FRA_SUPPRESS_IFGROUP, .extra_len = 4}},
        {"tun_id",                  {.mark = 0xff2, .mask = 0xffffffffu, .table = 4097,
                                     .extra = FRA_TUN_ID, .extra_len = 8}},
        {"l3mdev",                  {.mark = 0xff2, .mask = 0xffffffffu, .table = 4097,
                                     .extra = FRA_L3MDEV, .extra_len = 1}},
        {"uidrange (newer kernel)", {.mark = 0xff2, .mask = 0xffffffffu, .table = 4097,
                                     .extra = 20, .extra_len = 8}},
        {"IPv6 rule",               {.family = AF_INET6, .mark = 0xff2, .mask = 0xffffffffu, .table = 4097}},
        {"table 0",                 {.mark = 0xff2, .mask = 0xffffffffu, .table = 0}},
        {"another mark",            NDMS(0xff9, 4097)},
    };
    for (size_t i = 0; i < sizeof(other) / sizeof(other[0]); i++) {
        if (one_rule(AF_INET, other[i].r) != 0 || want[0].table != 0) {
            fprintf(stderr, "check_rtnl: %s counted as the policy rule\n", other[i].what);
            assert(0);
        }
    }

    /* Attributes that select nothing: realms, and the protocol that newer
     * kernels add to every rule. */
    assert(one_rule(AF_INET, NDMS(0xff2, 4097)) == 1 && want[0].table == 4097);
    assert(one_rule(AF_INET, (rule_t){.mark = 0xff2, .mask = 0xffffffffu, .table = 4097,
                                      .extra = FRA_FLOW, .extra_len = 4}) == 1);
    assert(one_rule(AF_INET, (rule_t){.mark = 0xff2, .mask = 0xffffffffu, .table = 4097,
                                      .extra = 21, .extra_len = 1}) == 1);

    /* The first rule of a mark that counts gives the table; a rule that does
     * not count takes nothing. */
    script_reset();
    put_rule(0, SEQ_REQ, (rule_t){.flags = FIB_RULE_INVERT, .mark = 0xff2, .mask = 0xffffffffu, .table = 6000});
    put_rule(0, SEQ_REQ, NDMS(0xff2, 4097));
    put_rule(0, SEQ_REQ, NDMS(0xff2, 5000));
    put_done(0, SEQ_REQ, 0);
    assert(lookup(AF_INET, 1, 0xff2, 0, 0) == 1 && want[0].table == 4097);

    /* IPv6: the same, with 16-byte addresses; an IPv4 rule does not count. */
    script_reset();
    put_rule(0, SEQ_REQ, (rule_t){.family = AF_INET6, .mark = 0xff2, .mask = 0xffffffffu, .table = 4097});
    put_rule(0, SEQ_REQ, (rule_t){.family = AF_INET6, .src_len = 64, .mark = 0xff1, .mask = 0xffffffffu,
                                  .table = 4096, .extra = FRA_SRC, .extra_len = 16});
    put_rule(0, SEQ_REQ, NDMS(0xff3, 4098));
    put_done(0, SEQ_REQ, 0);
    assert(lookup(AF_INET6, 3, 0xff2, 0xff1, 0xff3) == 1);
    assert(sent_family == AF_INET6);
    assert(want[0].table == 4097 && want[1].table == 0 && want[2].table == 0);
}

/* A broken or failed dump is -1 as a whole, whatever was found before:
 * "no rule" must come only from a dump read to its end. */
static void check_strict(void) {
    static const rule_t broken[] = {
        {.mark = 0xff2, .mask = 0xffffffffu, .table = 4097, .bad = FRA_FWMARK},
        {.mark = 0xff2, .mask = 0xffffffffu, .table = 4097, .bad = FRA_FWMASK},
        {.mark = 0xff2, .mask = 0xffffffffu, .table = 4097, .bad = FRA_TABLE},
        {.mark = 0xff2, .mask = 0xffffffffu, .table = 4097, .bad = FRA_SUPPRESS_PREFIXLEN},
        {.mark = 0xff2, .mask = 0xffffffffu, .table = 4097, .trailer = 1},
        {.mark = 0xff2, .mask = 0xffffffffu, .table = 4097, .trailer = 2},
        {.mark = 0xff7, .mask = 0xffffffffu, .table = 4097, .bad = FRA_FWMARK},   /* not even ours */
    };
    for (int c = 0; c < 15; c++) {
        script_reset();
        put_rule(0, SEQ_REQ, NDMS(0xff1, 4096));
        put_rule(0, SEQ_REQ, NDMS(0xff2, 4097));
        if (c < 7) {
            put_rule(0, SEQ_REQ, broken[c]);
        } else if (c == 7) {
            uint8_t shortrule[8] = {AF_INET};            /* shorter than fib_rule_hdr */
            put_msg(0, RTM_NEWRULE, NLM_F_MULTI, SEQ_REQ, shortrule, sizeof(shortrule));
        } else if (c == 8) {
            put_error(0, SEQ_REQ, -EBUSY);
        } else if (c == 9) {
            put_msg(0, NLMSG_OVERRUN, 0, SEQ_REQ, NULL, 0);
        } else if (c == 10) {
            put_rule(0, SEQ_REQ, NDMS(0xff3, 4098));
            last->nlmsg_flags |= NLM_F_DUMP_INTR;
        } else if (c == 11) {
            uint8_t p[RULE_MAX] __attribute__((aligned(4)));
            rule_t r = NDMS(0xff3, 4098);
            put_msg(0, RTM_NEWROUTE, NLM_F_MULTI, SEQ_REQ, p, rule_payload(p, &r));
        }
        if (c == 13 || c == 14) {
            /* the end of the dump, then in the same datagram an error or
             * bytes that are no message: not a complete dump either */
            put_done(0, SEQ_REQ, 0);
            if (c == 13) put_error(0, SEQ_REQ, -EBUSY);
            else dgram_len[0] += 8;
        }
        put_done(1, SEQ_REQ, c == 12 ? -EMSGSIZE : 0);
        if (lookup(AF_INET, 2, 0xff1, 0xff2, 0) != -1) {
            fprintf(stderr, "check_rtnl: broken dump %d taken as complete\n", c);
            assert(0);
        }
    }
}

/* No cap on the rules: a policy rule after 130 others is still found. */
static void check_many(void) {
    script_reset();
    for (int i = 0; i < 130; i++)
        put_rule(i < 100 ? 0 : 1, SEQ_REQ, NDMS(0x1000 + (uint32_t)i, 5000 + (uint32_t)i));
    put_rule(1, SEQ_REQ, NDMS(0xff2, 4097));
    put_done(1, SEQ_REQ, 0);
    assert(dgram_len[0] <= RTNL_BUF_SIZE && dgram_len[1] <= RTNL_BUF_SIZE);
    assert(lookup(AF_INET, 3, 0xff2, 0x1000 + 129, 0xff1) == 2);
    assert(want[0].table == 4097 && want[1].table == 5129 && want[2].table == 0);
}

/* --- rtnl_default_routes ---------------------------------------------- */

#define ROUTE_MAX 192

/* A route as kernel 4.9 dumps it. IPv4 (fib_dump_info): the header holds
 * the table, or RT_TABLE_COMPAT above 255; RTA_TABLE all of it; RTA_OIF
 * only with a device, none for blackhole/unreachable/prohibit; a multipath
 * route has RTA_MULTIPATH instead. IPv6 (rt6_fill_node): the header holds
 * the low byte of the table, RTA_OIF always (lo for a reject route),
 * RTA_PRIORITY always, and RTA_CACHEINFO and RTA_PREF, which say nothing
 * here. */
typedef struct {
    uint8_t  family;            /* 0: AF_INET */
    uint8_t  dst_len;
    uint8_t  type;              /* 0: RTN_UNICAST */
    uint32_t table;
    uint32_t oif;               /* RTA_OIF when not 0 */
    int      cloned;            /* RTM_F_CLONED: a cached clone */
    int      no_table;          /* no RTA_TABLE, only the header */
    int      hops;              /* RTA_MULTIPATH with this many nexthops (ifindex 7, 8, ...) */
    uint16_t bad;               /* this u32 attribute (RTA_TABLE, RTA_OIF, RTA_PRIORITY) gets 2 bytes */
    int      oif_zero;          /* RTA_OIF 0 */
    int      trailer;           /* as rule_t */
    int      mp_broken;         /* RTA_MULTIPATH: 1 empty; 2 rtnh_len < 8; 3 rtnh_len past the
                                 * attribute; 4 a nexthop attribute cut; 5 ifindex 0; 6 bytes after
                                 * the last nexthop that are none */
} route_t;

static size_t put_route_u32(uint8_t *p, size_t off, uint16_t type, uint32_t v, const route_t *r) {
    return put_attr(p, off, type, &v, r->bad == type ? 2 : 4);
}

static size_t put_multipath(uint8_t *p, size_t off, const route_t *r) {
    size_t alen = r->family == AF_INET6 ? 16 : 4, start = off;
    struct rtattr *mp = (struct rtattr *)(p + off);
    mp->rta_type = RTA_MULTIPATH;
    off += RTA_LENGTH(0);
    for (int h = 0; h < r->hops && r->mp_broken != 1; h++) {
        struct rtnexthop *nh = (struct rtnexthop *)(p + off);
        size_t hop = off;
        memset(nh, 0, sizeof(*nh));
        nh->rtnh_ifindex = r->mp_broken == 5 && h == 1 ? 0 : 7 + h;
        off = put_attr(p, off + sizeof(*nh), RTA_GATEWAY, NULL, alen);
        nh->rtnh_len = (unsigned short)(off - hop);
        if (r->mp_broken == 2 && h == 0) nh->rtnh_len = 4;
        if (r->mp_broken == 3 && h == r->hops - 1) nh->rtnh_len += 8;
        if (r->mp_broken == 4 && h == 0) ((struct rtattr *)(p + hop + sizeof(*nh)))->rta_len += 4;
    }
    if (r->mp_broken == 6) {
        memset(p + off, 0, 4);
        off += 4;
    }
    mp->rta_len = (unsigned short)(off - start);
    return off;
}

static size_t route_payload(uint8_t *p, const route_t *r) {
    struct rtmsg *rt = (struct rtmsg *)p;
    uint8_t family = r->family ? r->family : AF_INET;
    size_t alen = family == AF_INET6 ? 16 : 4;
    size_t off = NLMSG_ALIGN(sizeof(*rt));
    memset(p, 0, ROUTE_MAX);
    rt->rtm_family = family;
    rt->rtm_dst_len = r->dst_len;
    rt->rtm_type = r->type ? r->type : RTN_UNICAST;
    if (family == AF_INET6) rt->rtm_table = (uint8_t)r->table;
    else rt->rtm_table = r->table > 255 ? RT_TABLE_COMPAT : (uint8_t)r->table;
    rt->rtm_protocol = RTPROT_STATIC;
    rt->rtm_scope = RT_SCOPE_UNIVERSE;
    rt->rtm_flags = r->cloned ? RTM_F_CLONED : 0;
    if (!r->no_table) off = put_route_u32(p, off, RTA_TABLE, r->table, r);
    if (r->dst_len) off = put_attr(p, off, RTA_DST, NULL, alen);
    off = put_route_u32(p, off, RTA_PRIORITY, family == AF_INET6 ? 1024 : 100, r);
    if (r->hops || r->mp_broken) {
        off = put_multipath(p, off, r);
        /* a valid attribute right after it, so a nexthop running past the
         * multipath attribute would still parse */
        if (r->mp_broken == 3) off = put_route_u32(p, off, RTA_FLOW, 0, r);
    } else {
        if (rt->rtm_type == RTN_UNICAST && r->oif) off = put_attr(p, off, RTA_GATEWAY, NULL, alen);
        if (r->oif || r->oif_zero) off = put_route_u32(p, off, RTA_OIF, r->oif_zero ? 0 : r->oif, r);
    }
    if (family == AF_INET6) {
        uint8_t pref = 0;
        off = put_attr(p, off, RTA_CACHEINFO, NULL, sizeof(struct rta_cacheinfo));
        off = put_attr(p, off, RTA_PREF, &pref, 1);
    }
    if (r->trailer) {
        struct rtattr *a = (struct rtattr *)(p + off);
        a->rta_len = r->trailer == 1 ? 2 : 64;
        a->rta_type = RTA_FLOW;
        off += 4;
    }
    assert(off <= ROUTE_MAX);
    return off;
}

static void put_route(int d, uint32_t seq, route_t r) {
    uint8_t p[ROUTE_MAX] __attribute__((aligned(4)));
    put_msg(d, RTM_NEWROUTE, NLM_F_MULTI, seq, p, route_payload(p, &r));
}

static int st[8];

/* Default route states of n tables; the states start as garbage. */
static int defaults(int family, int n, const uint32_t *tables) {
    for (int p = 0; p < 8; p++) st[p] = 0x5a5a;
    int r = rtnl_default_routes(family, tables, n, st);
    assert(open_fds == 0);              /* the socket is closed on every path */
    return r;
}

static void check_default_routes(void) {
    /* main, HydraRoute's table (4096, above 255: the header says
     * RT_TABLE_COMPAT), a table with only a /24, a blackhole default, and a
     * table 0 that matches nothing. A cached clone is skipped. Over two
     * datagrams, in one dump of the family. */
    static const uint32_t tables[5] = {RT_TABLE_MAIN, 4096, 4097, 4098, 0};
    script_reset();
    put_route(0, SEQ_REQ, (route_t){.table = RT_TABLE_MAIN, .oif = 5});
    put_route(0, SEQ_REQ, (route_t){.dst_len = 24, .table = 4097, .oif = 9});
    put_route(0, SEQ_REQ, (route_t){.table = 4096, .oif = 9});
    put_route(1, SEQ_REQ, (route_t){.type = RTN_BLACKHOLE, .table = 4098});
    put_route(1, SEQ_REQ, (route_t){.table = 4097, .oif = 9, .cloned = 1});
    put_route(1, SEQ_REQ, (route_t){.type = RTN_LOCAL, .dst_len = 32, .table = RT_TABLE_LOCAL, .oif = 1});
    put_done(1, SEQ_REQ, 0);
    assert(defaults(AF_INET, 5, tables) == 0);
    assert(sends == 1 && closes == 1);
    assert(sent_type == RTM_GETROUTE && sent_family == AF_INET);
    assert(st[0] == RTNL_ROUTE_UNICAST && st[1] == RTNL_ROUTE_UNICAST);
    assert(st[2] == RTNL_ROUTE_NONE && st[3] == RTNL_ROUTE_OTHER && st[4] == RTNL_ROUTE_NONE);

    /* Every kind of default. Only unicast through an interface is a path:
     * unreachable, prohibit and a unicast default without a device are not;
     * multipath is. A unicast default wins over a blackhole fallback of its
     * table in either order. A route without RTA_TABLE has its table in the
     * header. */
    {
        static const uint32_t kinds[8] = {RT_TABLE_MAIN, 4096, 4097, 4098, 4099, 4100, 4101, RT_TABLE_COMPAT};
        script_reset();
        put_route(0, SEQ_REQ, (route_t){.type = RTN_UNREACHABLE, .table = 4096});
        put_route(0, SEQ_REQ, (route_t){.type = RTN_PROHIBIT, .table = 4097});
        put_route(0, SEQ_REQ, (route_t){.table = 4098});
        put_route(0, SEQ_REQ, (route_t){.table = 4099, .hops = 2});
        put_route(0, SEQ_REQ, (route_t){.type = RTN_BLACKHOLE, .table = 4100});
        put_route(0, SEQ_REQ, (route_t){.table = 4100, .oif = 9});
        put_route(0, SEQ_REQ, (route_t){.table = 4101, .oif = 9});
        put_route(0, SEQ_REQ, (route_t){.type = RTN_BLACKHOLE, .table = 4101});
        put_route(0, SEQ_REQ, (route_t){.table = RT_TABLE_MAIN, .oif = 5, .no_table = 1});
        put_done(0, SEQ_REQ, 0);
        assert(defaults(AF_INET, 8, kinds) == 0);
        assert(st[0] == RTNL_ROUTE_UNICAST);
        assert(st[1] == RTNL_ROUTE_OTHER && st[2] == RTNL_ROUTE_OTHER && st[3] == RTNL_ROUTE_OTHER);
        assert(st[4] == RTNL_ROUTE_UNICAST && st[5] == RTNL_ROUTE_UNICAST && st[6] == RTNL_ROUTE_UNICAST);
        assert(st[7] == RTNL_ROUTE_NONE);   /* the header of 4096..4101 says 252: not a table of its own */
    }

    /* IPv6 4.9: the header has the low byte of the table, so 4096 says 0 and
     * 4350 says 254, main's id; only RTA_TABLE tells them apart. An empty
     * table dumps its root, "unreachable default dev lo" of table 0 (unspec):
     * not main's. */
    {
        static const uint32_t t6[4] = {RT_TABLE_MAIN, 4096, 4350, 0};
        script_reset();
        put_route(0, SEQ_REQ, (route_t){.family = AF_INET6, .type = RTN_UNREACHABLE, .table = 0, .oif = 1});
        put_route(0, SEQ_REQ, (route_t){.family = AF_INET6, .table = 4096, .oif = 9});
        put_route(0, SEQ_REQ, (route_t){.family = AF_INET6, .table = 4350, .oif = 9});
        put_route(0, SEQ_REQ, (route_t){.family = AF_INET6, .dst_len = 64, .table = RT_TABLE_MAIN, .oif = 3});
        put_route(0, SEQ_REQ, (route_t){.family = AF_INET6, .dst_len = 128, .table = RT_TABLE_MAIN,
                                        .oif = 3, .cloned = 1});
        put_done(0, SEQ_REQ, 0);
        assert(defaults(AF_INET6, 4, t6) == 0);
        assert(sent_type == RTM_GETROUTE && sent_family == AF_INET6);
        assert(st[0] == RTNL_ROUTE_NONE && st[1] == RTNL_ROUTE_UNICAST);
        assert(st[2] == RTNL_ROUTE_UNICAST && st[3] == RTNL_ROUTE_NONE);

        /* A blackhole default in main is a default route (dev lo); a default
         * via the uplink is a path. */
        script_reset();
        put_route(0, SEQ_REQ, (route_t){.family = AF_INET6, .type = RTN_BLACKHOLE, .table = RT_TABLE_MAIN, .oif = 1});
        put_done(0, SEQ_REQ, 0);
        assert(defaults(AF_INET6, 2, t6) == 0 && st[0] == RTNL_ROUTE_OTHER && st[1] == RTNL_ROUTE_NONE);
        script_reset();
        put_route(0, SEQ_REQ, (route_t){.family = AF_INET6, .table = RT_TABLE_MAIN, .oif = 3});
        put_done(0, SEQ_REQ, 0);
        assert(defaults(AF_INET6, 2, t6) == 0 && st[0] == RTNL_ROUTE_UNICAST);
    }

    /* No answer within RTNL_TIMEOUT_MS. */
    script_reset();
    assert(defaults(AF_INET, 5, tables) == -1);
}

/* A broken or failed route dump is -1 as a whole, whatever was found before
 * it, and whether or not the broken route is a default of a table asked for. */
static void check_routes_strict(void) {
    static const uint32_t tables[2] = {RT_TABLE_MAIN, 4096};
    static const struct {
        const char *what;
        route_t r;
    } broken[] = {
        {"IPv6 route in an IPv4 dump",   {.family = AF_INET6, .table = 4096, .oif = 9}},
        {"RTA_TABLE of 2 bytes",         {.table = 4096, .oif = 9, .bad = RTA_TABLE}},
        {"RTA_OIF of 2 bytes",           {.table = 4096, .oif = 9, .bad = RTA_OIF}},
        {"RTA_PRIORITY of 2 bytes",      {.table = 4096, .oif = 9, .bad = RTA_PRIORITY}},
        {"RTA_OIF 0",                    {.table = 4096, .oif_zero = 1}},
        {"attribute shorter than itself", {.table = 4096, .oif = 9, .trailer = 1}},
        {"attribute past the message",   {.table = 4096, .oif = 9, .trailer = 2}},
        {"empty multipath",              {.table = 4096, .mp_broken = 1}},
        {"nexthop shorter than itself",  {.table = 4096, .hops = 2, .mp_broken = 2}},
        {"nexthop past the attribute",   {.table = 4096, .hops = 2, .mp_broken = 3}},
        {"nexthop attribute cut",        {.table = 4096, .hops = 2, .mp_broken = 4}},
        {"nexthop without interface",    {.table = 4096, .hops = 2, .mp_broken = 5}},
        {"bytes after the last nexthop", {.table = 4096, .hops = 1, .mp_broken = 6}},
        {"broken, not a default",        {.dst_len = 24, .table = 4097, .oif = 9, .bad = RTA_OIF}},
        {"broken, another table",        {.table = 5000, .oif = 9, .trailer = 1}},
    };
    const int nb = (int)(sizeof(broken) / sizeof(broken[0]));
    for (int c = 0; c < nb + 7; c++) {
        script_reset();
        /* found before the break: main and 4096 have a path */
        put_route(0, SEQ_REQ, (route_t){.table = RT_TABLE_MAIN, .oif = 5});
        put_route(0, SEQ_REQ, (route_t){.table = 4096, .oif = 9});
        if (c < nb) {
            put_route(0, SEQ_REQ, broken[c].r);
        } else if (c == nb) {
            uint8_t shortroute[8] = {AF_INET};          /* shorter than rtmsg */
            put_msg(0, RTM_NEWROUTE, NLM_F_MULTI, SEQ_REQ, shortroute, sizeof(shortroute));
        } else if (c == nb + 1) {
            put_rule(0, SEQ_REQ, NDMS(0xff2, 4096));    /* a rule in a route dump */
        } else if (c == nb + 2) {
            put_error(0, SEQ_REQ, -EBUSY);
        } else if (c == nb + 3) {
            put_msg(0, NLMSG_OVERRUN, 0, SEQ_REQ, NULL, 0);
        } else if (c == nb + 4) {
            put_route(0, SEQ_REQ, (route_t){.table = 4097, .oif = 9});
            last->nlmsg_flags |= NLM_F_DUMP_INTR;       /* the routes changed meanwhile */
        } else if (c == nb + 5) {
            put_done(0, SEQ_REQ, 0);                    /* bytes after the end */
            dgram_len[0] += 8;
        }
        put_done(1, SEQ_REQ, c == nb + 6 ? -EMSGSIZE : 0);
        if (defaults(AF_INET, 2, tables) != -1) {
            fprintf(stderr, "check_rtnl: broken route dump %d (%s) taken as complete\n",
                    c, c < nb ? broken[c].what : "envelope");
            assert(0);
        }
    }

    /* IPv6 the same: an IPv4 route, or a broken one, in an IPv6 dump. */
    for (int c = 0; c < 2; c++) {
        script_reset();
        put_route(0, SEQ_REQ, (route_t){.family = AF_INET6, .table = RT_TABLE_MAIN, .oif = 3});
        if (c == 0) put_route(0, SEQ_REQ, (route_t){.table = 4096, .oif = 9});
        else put_route(0, SEQ_REQ, (route_t){.family = AF_INET6, .table = 4096, .oif = 9, .bad = RTA_TABLE});
        put_done(0, SEQ_REQ, 0);
        assert(defaults(AF_INET6, 2, tables) == -1);
    }

    /* The control: the same valid routes alone are a complete dump. */
    script_reset();
    put_route(0, SEQ_REQ, (route_t){.table = RT_TABLE_MAIN, .oif = 5});
    put_route(0, SEQ_REQ, (route_t){.table = 4096, .oif = 9});
    put_route(0, SEQ_REQ, (route_t){.table = 4097, .hops = 3});
    put_done(1, SEQ_REQ, 0);
    assert(defaults(AF_INET, 2, tables) == 0);
    assert(st[0] == RTNL_ROUTE_UNICAST && st[1] == RTNL_ROUTE_UNICAST);
}

/* Ruling 15: one deadline for a monitor round. Each recv waits for what is
 * left of it (1 s at most); a dump not done by then fails, at the deadline
 * and not later; one asked for after it fails without a request. The clock
 * is the fake's: nothing really waits. */
static void check_deadline(void) {
    static const uint32_t tables[2] = {RT_TABLE_MAIN, 4096};
    expect_1s = 0;
    fake_ms = 100000;
    assert(rtnl_now_ms() == 100000);

    /* Done in time: each wait is what is left. */
    script_reset();
    put_route(0, SEQ_REQ, (route_t){.table = RT_TABLE_MAIN, .oif = 5});
    dgram_delay[0] = 50;
    put_route(1, SEQ_REQ, (route_t){.table = 4096, .oif = 9});
    put_done(1, SEQ_REQ, 0);
    dgram_delay[1] = 30;
    rtnl_set_deadline(100200);
    assert(defaults(AF_INET, 2, tables) == 0);
    assert(st[0] == RTNL_ROUTE_UNICAST && st[1] == RTNL_ROUTE_UNICAST);
    assert(rcvtimeo_n == 2 && rcvtimeo_us[0] == 200000 && rcvtimeo_us[1] == 150000);
    assert(sndtimeo_us == 200000 && fake_ms == 100080);

    /* A multipart dump cut by the deadline: -1 when it comes. */
    script_reset();
    fake_ms = 100000;
    put_route(0, SEQ_REQ, (route_t){.table = RT_TABLE_MAIN, .oif = 5});
    dgram_delay[0] = 120;
    put_route(1, SEQ_REQ, (route_t){.table = 4096, .oif = 9});
    put_done(1, SEQ_REQ, 0);
    dgram_delay[1] = 100;
    assert(defaults(AF_INET, 2, tables) == -1);
    assert(recvs == 2 && rcvtimeo_us[1] == 80000 && fake_ms == 100200 && closes == 1);

    /* A part that comes just at the deadline, not the end: no more waiting. */
    script_reset();
    fake_ms = 100000;
    put_route(0, SEQ_REQ, (route_t){.table = RT_TABLE_MAIN, .oif = 5});
    dgram_delay[0] = 200;
    put_done(1, SEQ_REQ, 0);
    assert(defaults(AF_INET, 2, tables) == -1);
    assert(recvs == 1 && fake_ms == 100200);

    /* A whole answer counts only before the deadline (Ruling 39): at it, or
     * later by the kernel's rounding of SO_RCVTIMEO, it is not published. */
    script_reset();
    fake_ms = 100000;
    put_route(0, SEQ_REQ, (route_t){.table = RT_TABLE_MAIN, .oif = 5});
    put_done(0, SEQ_REQ, 0);
    dgram_delay[0] = 199;
    assert(defaults(AF_INET, 2, tables) == 0 && st[0] == RTNL_ROUTE_UNICAST);
    for (int late = 0; late < 2; late++) {
        script_reset();
        fake_ms = 100000;
        put_route(0, SEQ_REQ, (route_t){.table = RT_TABLE_MAIN, .oif = 5});
        put_done(0, SEQ_REQ, 0);
        dgram_delay[0] = late ? 203 : 200;
        dgram_late = 5;
        assert(defaults(AF_INET, 2, tables) == -1);
        assert(recvs == 1 && fake_ms == (late ? 100203 : 100200) && closes == 1);
    }
    script_reset();
    fake_ms = 100000;
    put_rule(0, SEQ_REQ, NDMS(0xff2, 4097));
    put_done(0, SEQ_REQ, 0);
    dgram_delay[0] = 203;
    dgram_late = 5;
    assert(lookup(AF_INET, 1, 0xff2, 0, 0) == -1);

    /* The request itself takes time (rtnl_lock): the first recv waits only
     * for what is left after it, and the send is bounded too. */
    script_reset();
    fake_ms = 100000;
    send_delay = 150;
    put_route(0, SEQ_REQ, (route_t){.table = RT_TABLE_MAIN, .oif = 5});
    put_done(0, SEQ_REQ, 0);
    dgram_delay[0] = 30;
    assert(defaults(AF_INET, 2, tables) == 0);
    assert(sndtimeo_us == 200000 && rcvtimeo_n == 1 && rcvtimeo_us[0] == 50000 && fake_ms == 100180);
    script_reset();
    fake_ms = 100000;
    send_delay = 150;
    put_route(0, SEQ_REQ, (route_t){.table = RT_TABLE_MAIN, .oif = 5});
    put_done(0, SEQ_REQ, 0);
    dgram_delay[0] = 60;
    assert(defaults(AF_INET, 2, tables) == -1);
    assert(rcvtimeo_us[0] == 50000 && fake_ms == 100200 && closes == 1);
    script_reset();
    fake_ms = 100000;
    send_delay = 250;                       /* SO_SNDTIMEO expires */
    put_route(0, SEQ_REQ, (route_t){.table = RT_TABLE_MAIN, .oif = 5});
    put_done(0, SEQ_REQ, 0);
    assert(defaults(AF_INET, 2, tables) == -1);
    assert(sends == 1 && recvs == 0 && fake_ms == 100200 && closes == 1);

    /* The deadline runs out before the request: nothing is sent. */
    script_reset();
    fake_ms = 100000;
    bind_delay = 200;
    put_route(0, SEQ_REQ, (route_t){.table = RT_TABLE_MAIN, .oif = 5});
    put_done(0, SEQ_REQ, 0);
    assert(defaults(AF_INET, 2, tables) == -1);
    assert(sends == 0 && recvs == 0 && closes == 1);

    /* A signal: recv again, for what is left. */
    script_reset();
    fake_ms = 100000;
    put_errno(0, EINTR);
    dgram_delay[0] = 40;
    put_route(1, SEQ_REQ, (route_t){.table = RT_TABLE_MAIN, .oif = 5});
    put_done(1, SEQ_REQ, 0);
    dgram_delay[1] = 10;
    assert(defaults(AF_INET, 2, tables) == 0);
    assert(rcvtimeo_n == 2 && rcvtimeo_us[1] == 160000);

    /* A wait that cannot be set fails the dump and closes the socket: the
     * send's (1st setsockopt), the first recv's (2nd), a later one (3rd). */
    for (int at = 1; at <= 3; at++) {
        script_reset();
        fake_ms = 100000;
        put_route(0, SEQ_REQ, (route_t){.table = RT_TABLE_MAIN, .oif = 5});
        put_done(1, SEQ_REQ, 0);
        fail_setsockopt_from = at;
        assert(defaults(AF_INET, 2, tables) == -1 && closes == 1);
        assert(sends == (at > 1) && recvs == (at > 2));
        fail_setsockopt_from = 0;
    }

    /* Past the deadline: no socket, no request, for routes and rules. */
    script_reset();
    fake_ms = 100200;
    put_route(0, SEQ_REQ, (route_t){.table = RT_TABLE_MAIN, .oif = 5});
    put_done(0, SEQ_REQ, 0);
    assert(defaults(AF_INET, 2, tables) == -1);
    assert(lookup(AF_INET, 1, 0xff2, 0, 0) == -1);
    assert(sends == 0 && closes == 0 && rcvtimeo_n == 0);

    /* More than RTNL_TIMEOUT_MS left: a recv still waits 1 s at most. */
    script_reset();
    fake_ms = 100000;
    rtnl_set_deadline(105000);
    assert(defaults(AF_INET, 2, tables) == -1);
    assert(rcvtimeo_n == 1 && rcvtimeo_us[0] == 1000000 && fake_ms == 101000);

    /* No deadline again: 1 s per recv, and the clock is not read. */
    rtnl_set_deadline(0);
    expect_1s = 1;
    clock_calls = 0;
    script_reset();
    put_route(0, SEQ_REQ, (route_t){.table = RT_TABLE_MAIN, .oif = 5});
    put_done(1, SEQ_REQ, 0);
    dgram_delay[1] = 900;
    assert(defaults(AF_INET, 2, tables) == 0 && clock_calls == 0);
    script_reset();
    put_rule(0, SEQ_REQ, NDMS(0xff2, 4097));
    put_done(0, SEQ_REQ, 0);
    assert(lookup(AF_INET, 1, 0xff2, 0, 0) == 1 && clock_calls == 0);
}

int main(void) {
    check_parse();
    check_dump();
    check_profile();
    check_strict();
    check_many();
    check_default_routes();
    check_routes_strict();
    check_deadline();
    puts("check_rtnl: OK");
    return 0;
}
