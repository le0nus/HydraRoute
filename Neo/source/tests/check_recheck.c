#define STATUS_PATH "build/check_recheck.status"
#define FAKE_NF_REAL_RCI_RTNL
#include "fake_nf.h"
#include <errno.h>
#include <linux/fib_rules.h>
#include <linux/rtnetlink.h>

/* The whole recheck path on real bytes: the ip rule dump goes through
 * src/rtnl.c, the RCI answer through src/rci.c, the result into mangle and
 * raw (fake_nf.h). Only the sockets are fake: one NETLINK_ROUTE socket per
 * dump, one TCP connection per RCI request. */

#define NL_FD   90
#define RCI_FD  91

enum { TAIL_NONE, TAIL_BYTES, TAIL_OVERRUN, TAIL_ERROR };

static int hr_rule = 1;                 /* HydraRoute's ip rule is in the dump */
static int tail;                        /* what follows NLMSG_DONE in its datagram */
static uint8_t dump[1024] __attribute__((aligned(4)));
static size_t dump_len;
static int dump_sent;

#define HTTP_FF1 "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n\"ff1\""
#define HTTP_FF2 "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n\"ff2\""

#define BYTES(s) s, sizeof(s) - 1

static const char *hr_reply = HTTP_FF2; /* RCI's answer for HydraRoute (any bytes); RU has 0xff1 */
static size_t hr_len = sizeof(HTTP_FF2) - 1;
static int hr_err;                      /* errno of the recv after it, 0: EOF */
static int hr_open;                     /* the peer keeps the connection open after it */
static const char *reply;
static size_t reply_len, reply_off;
static int reply_err, reply_open, late_recvs;
static size_t chunk;                    /* bytes per recv of an RCI reply, 0: all that fits */

static size_t put_msg(size_t off, uint16_t type, uint32_t seq, const void *payload, size_t plen) {
    struct nlmsghdr *h = (struct nlmsghdr *)(dump + off);
    assert(off + NLMSG_SPACE(plen) <= sizeof(dump));
    memset(h, 0, NLMSG_SPACE(plen));
    h->nlmsg_len = (uint32_t)NLMSG_LENGTH(plen);
    h->nlmsg_type = type;
    h->nlmsg_flags = NLM_F_MULTI;
    h->nlmsg_seq = seq;
    if (plen) memcpy(NLMSG_DATA(h), payload, plen);
    return off + NLMSG_ALIGN(h->nlmsg_len);
}

static size_t put_u32(uint8_t *p, size_t off, uint16_t type, uint32_t v) {
    struct rtattr *a = (struct rtattr *)(p + off);
    a->rta_type = type;
    a->rta_len = RTA_LENGTH(4);
    memcpy(RTA_DATA(a), &v, 4);
    return off + RTA_SPACE(4);
}

/* "fwmark <mark> lookup <table>" as Linux 4.9 dumps it. */
static size_t put_rule(size_t off, uint32_t seq, uint32_t mark, uint32_t table) {
    uint8_t p[64] __attribute__((aligned(4)));
    struct fib_rule_hdr *frh = (struct fib_rule_hdr *)p;
    size_t n = NLMSG_ALIGN(sizeof(*frh));
    memset(p, 0, sizeof(p));
    frh->family = AF_INET;
    frh->table = (uint8_t)table;
    frh->action = FR_ACT_TO_TBL;
    n = put_u32(p, n, FRA_TABLE, table);
    n = put_u32(p, n, FRA_SUPPRESS_PREFIXLEN, 0xffffffffu);
    n = put_u32(p, n, FRA_PRIORITY, 1150);
    n = put_u32(p, n, FRA_FWMARK, mark);
    n = put_u32(p, n, FRA_FWMASK, 0xffffffffu);
    return put_msg(off, RTM_NEWRULE, seq, p, n);
}

static void build_dump(uint32_t seq) {
    int zero = 0;
    dump_len = put_rule(0, seq, 0xff1, 4096);
    if (hr_rule) dump_len = put_rule(dump_len, seq, 0xff2, 4097);
    dump_len = put_msg(dump_len, NLMSG_DONE, seq, &zero, sizeof(zero));
    if (tail == TAIL_BYTES) {
        memset(dump + dump_len, 0xa5, 8);
        dump_len += 8;
    } else if (tail == TAIL_OVERRUN) {
        dump_len = put_msg(dump_len, NLMSG_OVERRUN, seq, NULL, 0);
    } else if (tail == TAIL_ERROR) {
        struct nlmsgerr e;
        memset(&e, 0, sizeof(e));
        e.error = -EBUSY;
        dump_len = put_msg(dump_len, NLMSG_ERROR, seq, &e, sizeof(e));
    }
}

int __wrap_socket(int domain, int type, int protocol) {
    (void)type;
    if (domain == AF_NETLINK) {
        assert(protocol == NETLINK_ROUTE);
        rule_dumps++;
        dump_sent = 0;
        return NL_FD;
    }
    assert(domain == AF_INET);
    rci_calls++;
    reply = "";
    reply_len = reply_off = 0;
    return RCI_FD;
}

int __wrap_bind(int fd, const struct sockaddr *addr, socklen_t len) {
    (void)addr; (void)len;
    assert(fd == NL_FD);
    return 0;
}

int __wrap_setsockopt(int fd, int level, int name, const void *val, socklen_t len) {
    (void)level; (void)name; (void)val; (void)len;
    assert(fd == NL_FD || fd == RCI_FD);
    return 0;
}

int __wrap_connect(int fd, const struct sockaddr *addr, socklen_t len) {
    (void)addr; (void)len;
    assert(fd == RCI_FD);
    return 0;
}

int __wrap_close(int fd) {
    assert(fd == NL_FD || fd == RCI_FD);
    return 0;
}

ssize_t __wrap_send(int fd, const void *buf, size_t len, int flags) {
    (void)flags;
    if (fd == NL_FD) {
        const struct nlmsghdr *h = buf;
        assert(h->nlmsg_type == RTM_GETRULE);
        build_dump(h->nlmsg_seq);
        return (ssize_t)len;
    }
    assert(fd == RCI_FD);
    if (strstr(buf, "GET /rci/show/ip/policy/RU/mark ")) {
        reply = HTTP_FF1;
        reply_len = sizeof(HTTP_FF1) - 1;
        reply_err = reply_open = 0;
    } else {
        assert(strstr(buf, "GET /rci/show/ip/policy/HydraRoute/mark "));
        reply = hr_reply;
        reply_len = hr_len;
        reply_err = hr_err;
        reply_open = hr_open;
    }
    return (ssize_t)len;
}

/* Netlink: the dump in one datagram, then the receive timeout. TCP: the
 * reply, then EOF, the scripted error, or a peer that keeps the connection
 * open (a recv would wait out the timeout; counted in late_recvs). */
ssize_t __wrap_recv(int fd, void *buf, size_t len, int flags) {
    if (fd == NL_FD) {
        size_t n = dump_len < len ? dump_len : len;
        if (dump_sent) {
            errno = EAGAIN;
            return -1;
        }
        dump_sent = 1;
        memcpy(buf, dump, n);
        return (ssize_t)((flags & MSG_TRUNC) ? dump_len : n);
    }
    size_t left = reply_len - reply_off, n = chunk && left > chunk ? chunk : left;
    if (n > len) n = len;
    if (n == 0) {
        if (reply_open) {
            late_recvs++;
            errno = EAGAIN;
            return -1;
        }
        if (!reply_err) return 0;
        errno = reply_err;
        return -1;
    }
    memcpy(buf, reply + reply_off, n);
    reply_off += n;
    return (ssize_t)n;
}

static void assert_kept(void) {
    assert(calls[0] == '\0');
    assert_mangle(0, 0, 0xff2, 0);
    assert_mangle(1, 0, 0xff2, 0);
    assert_raw(0, 0xff2);
    assert_raw(1, 0xff2);
    assert(status_has("raw_guard=on"));
}

int main(void) {
    static const struct {
        const char *what, *reply;
        size_t len;
        int err;
    } failed[] = {
        {"HTTP 500",                BYTES("HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n"), 0},
        {"200 cut, length says 9",  BYTES("HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\n\"ffff"), 0},
        {"200 cut, no length",      BYTES("HTTP/1.0 200 OK\r\n\r\n\"ffff"), 0},
        {"200, then a reset",       BYTES("HTTP/1.1 200 OK\r\n\r\n\"ff3\""), ECONNRESET},
        {"200 garbage",             BYTES("HTTP/1.1 200 OK\r\n\r\n<html>busy</html>"), 0},
        {"404 chunked, cut",        BYTES("HTTP/1.1 404 Not Found\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nab"), 0},
        {"200 chunked, cut",        BYTES("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\n\"ff3"), 0},
        {"200 \"\" NUL x",          BYTES("HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\n\"\"\0x"), 0},
        {"404 LF before length",    BYTES("HTTP/1.1 404 Not Found\nContent-Length: 9\r\n\r\nab"), 0},
        {"200 LF before length",    BYTES("HTTP/1.1 200 OK\nContent-Length: 20\r\n\r\n\"\""), 0},
        {"404 LF before chunked",   BYTES("HTTP/1.1 404 Not Found\nTransfer-Encoding: chunked\r\n\r\n"), 0},
        {"200 LF before chunked",   BYTES("HTTP/1.1 200 OK\r\nServer: ndm\nTransfer-Encoding: chunked\r\n\r\n\"\""), 0},
    };
    static const size_t splits[] = {0, 1, 5, 7};
    config_t cfg;
    unified_target_t t[2];
    setup_targets(t, &cfg);
    cfg.raw_guard = 1;
    remove(STATUS_PATH);
    guard_status_init(STATUS_PATH);
    rci_set_token("");

    /* Start: RCI gives both marks; no ip rule dump yet. */
    reset();
    assert(apply_unified_connmark_rules(t, 2, &cfg, NULL) == 0);
    assert(rci_calls == 2 && rule_dumps == 0);
    assert(strcmp(calls, "m4 m6 r4 r6 ") == 0);
    assert_mangle(0, 0, 0xff2, 0);
    assert_raw(0, 0xff2);

    /* Both rules in the dump: no RCI. */
    reset();
    assert(apply_unified_connmark_rules(t, 2, &cfg, NULL) == 0);
    assert(rule_dumps == 1 && rci_calls == 0);
    assert_kept();

    /* HydraRoute's rule is missing before NLMSG_DONE, and after it in the
     * same datagram come bytes that are no message, an overrun or an error:
     * the dump is broken as a whole. No RCI, nothing removed. */
    hr_rule = 0;
    for (tail = TAIL_BYTES; tail <= TAIL_ERROR; tail++) {
        reset();
        assert(apply_unified_connmark_rules(t, 2, &cfg, NULL) == 0);
        assert(rule_dumps == 1 && rci_calls == 0);
        assert(warns == (tail == TAIL_BYTES));  /* "ip rule dump failed", once */
        assert_kept();
    }
    tail = TAIL_NONE;

    /* The rule is really gone, and RCI fails in ways that are not "no such
     * policy": the known mark and its rules stay, the commit is retried
     * (Ruling 33). One WARN for the rule, one for the cause. */
    for (size_t i = 0; i < sizeof(failed) / sizeof(failed[0]) * 4; i++) {
        size_t k = i / 4;
        chunk = splits[i % 4];
        hr_reply = failed[k].reply;
        hr_len = failed[k].len;
        hr_err = failed[k].err;
        reset();
        if (apply_unified_connmark_rules(t, 2, &cfg, NULL) != -1 || rci_calls != 1) {
            fprintf(stderr, "check_recheck: %s (recv by %zu) taken as an answer\n",
                    failed[k].what, chunk);
            assert(0);
        }
        assert(warns == (i == 0 ? 2 : 0));
        assert_kept();
    }
    chunk = 0;
    hr_err = 0;

    /* A whole 200 with the known mark from a peer that keeps the connection
     * open: taken at once, no wait for the close; nothing changes. */
    hr_reply = HTTP_FF2;
    hr_len = sizeof(HTTP_FF2) - 1;
    hr_open = 1;
    reset();
    assert(apply_unified_connmark_rules(t, 2, &cfg, NULL) == 0);
    assert(rci_calls == 1 && late_recvs == 0);
    assert_kept();

    /* 404 is RCI's answer for a policy that does not exist (Ruling 34),
     * here too from a peer that keeps the connection open: its rules leave
     * mangle and raw. */
    hr_reply = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
    hr_len = strlen(hr_reply);
    reset();
    assert(apply_unified_connmark_rules(t, 2, &cfg, NULL) == -1);
    assert(rci_calls == 1 && late_recvs == 0 && strcmp(calls, "m4 m6 r4 r6 ") == 0);
    assert(strstr(warn_log, "Policy HydraRoute has no mark ID yet"));
    assert_mangle_of(0, 0, 1, 0, 0);
    assert_mangle_of(1, 0, 1, 0, 0);
    assert_raw_of(0, 1, 0);
    assert_raw_of(1, 1, 0);

    puts("check_recheck: OK");
    return 0;
}
