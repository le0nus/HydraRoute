#include "../include/rtnl.h"
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
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
    return FAKE_FD;
}

int __wrap_bind(int fd, const struct sockaddr *addr, socklen_t len) {
    const struct sockaddr_nl *sa = (const struct sockaddr_nl *)addr;
    assert(fd == FAKE_FD && len == sizeof(*sa));
    assert(sa->nl_family == AF_NETLINK && sa->nl_pid == 0 && sa->nl_groups == 0);
    if (fail_bind) {
        errno = EADDRINUSE;
        return -1;
    }
    return 0;
}

int __wrap_setsockopt(int fd, int level, int name, const void *val, socklen_t len) {
    const struct timeval *tv = val;
    assert(fd == FAKE_FD && level == SOL_SOCKET && name == SO_RCVTIMEO && len == sizeof(*tv));
    assert(tv->tv_sec == 1 && tv->tv_usec == 0);
    if (fail_setsockopt) {
        errno = ENOPROTOOPT;
        return -1;
    }
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
    assert(fd == FAKE_FD && timeout_set && flags == 0);
    assert(len == NLMSG_LENGTH(sizeof(struct rtmsg)) && h->nlmsg_len == len);
    assert(h->nlmsg_flags == (NLM_F_REQUEST | NLM_F_DUMP));
    sends++;
    sent_type = h->nlmsg_type;
    sent_seq = h->nlmsg_seq;
    sent_family = ((const struct rtmsg *)NLMSG_DATA(h))->rtm_family;
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
    if (dgram_next == dgram_count) {
        errno = EAGAIN;
        return -1;
    }
    int d = dgram_next;
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
    dgram_count = dgram_next = 0;
    closes = sends = 0;
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

int main(void) {
    check_parse();
    check_dump();
    check_profile();
    check_strict();
    check_many();
    puts("check_rtnl: OK");
    return 0;
}
