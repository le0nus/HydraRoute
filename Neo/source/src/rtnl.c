#include "../include/rtnl.h"
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#include <linux/fib_rules.h>
#include <linux/rtnetlink.h>

/* Linux 4.17+ puts FRA_PROTOCOL (who installed the rule) in every rule it
 * dumps; it selects nothing. Numbered here for older headers. */
#define RTNL_FRA_PROTOCOL 21

static uint32_t g_seq;

/* One message of our request. */
static int rtnl_msg(const struct nlmsghdr *h, rtnl_msg_fn fn, void *ctx) {
    int code;
    if (h->nlmsg_flags & NLM_F_DUMP_INTR) return RTNL_FAIL;    /* the table changed meanwhile */
    switch (h->nlmsg_type) {
    case NLMSG_NOOP:
        return RTNL_MORE;
    case NLMSG_DONE:
        /* Carries the result of the dump: 0, or the error that ended it. */
        if (h->nlmsg_len < NLMSG_LENGTH(sizeof(code))) return RTNL_FAIL;
        memcpy(&code, NLMSG_DATA(h), sizeof(code));
        return code == 0 ? RTNL_DONE : RTNL_FAIL;
    case NLMSG_ERROR:
        /* An error, or an ACK (error 0) that changes nothing. */
        if (h->nlmsg_len < NLMSG_LENGTH(sizeof(struct nlmsgerr))) return RTNL_FAIL;
        memcpy(&code, NLMSG_DATA(h), sizeof(code));
        return code == 0 ? RTNL_MORE : RTNL_FAIL;
    case NLMSG_OVERRUN:
        return RTNL_FAIL;
    }
    if (h->nlmsg_type < NLMSG_MIN_TYPE) return RTNL_FAIL;      /* a reserved control message */
    return fn(h, ctx) == 0 ? RTNL_MORE : RTNL_FAIL;
}

int rtnl_parse(const void *buf, size_t len, uint32_t seq, rtnl_msg_fn fn, void *ctx) {
    const char *p = buf;
    while (len > 0) {
        const struct nlmsghdr *h = (const struct nlmsghdr *)p;
        if (len < NLMSG_HDRLEN || h->nlmsg_len < NLMSG_HDRLEN || h->nlmsg_len > len)
            return RTNL_FAIL;                   /* a cut or broken message */
        if (h->nlmsg_seq == seq) {
            int st = rtnl_msg(h, fn, ctx);
            if (st != RTNL_MORE) return st;
        }
        size_t step = NLMSG_ALIGN(h->nlmsg_len);
        if (step > len) step = len;             /* the last message may go unpadded */
        p += step;
        len -= step;
    }
    return RTNL_MORE;
}

int rtnl_dump(uint16_t type, uint8_t family, rtnl_msg_fn fn, void *ctx) {
    int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (fd < 0) return -1;

    struct sockaddr_nl sa;
    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;
    struct timeval tv;
    tv.tv_sec = RTNL_TIMEOUT_MS / 1000;
    tv.tv_usec = (RTNL_TIMEOUT_MS % 1000) * 1000;
    if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0 ||
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) != 0) {
        close(fd);
        return -1;
    }

    /* struct rtmsg and struct fib_rule_hdr are both 12 bytes and start with
     * the family, all a dump request needs. */
    struct {
        struct nlmsghdr h;
        struct rtmsg r;
    } req;
    memset(&req, 0, sizeof(req));
    req.h.nlmsg_len = NLMSG_LENGTH(sizeof(req.r));
    req.h.nlmsg_type = type;
    req.h.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    req.h.nlmsg_seq = ++g_seq;
    req.r.rtm_family = family;
    if (send(fd, &req, req.h.nlmsg_len, 0) < 0) {
        close(fd);
        return -1;
    }

    /* The kernel sizes dump datagrams by the receive buffer it saw last;
     * MSG_TRUNC reports a bigger one instead of cutting it silently. */
    uint32_t buf[RTNL_BUF_SIZE / 4];
    int ret = -1;
    for (;;) {
        ssize_t n = recv(fd, buf, sizeof(buf), MSG_TRUNC);
        if (n < 0 && errno == EINTR) continue;
        if (n < 0 || (size_t)n > sizeof(buf)) break;
        int st = rtnl_parse(buf, (size_t)n, req.h.nlmsg_seq, fn, ctx);
        if (st == RTNL_MORE) continue;
        ret = st == RTNL_DONE ? 0 : -1;
        break;
    }
    close(fd);
    return ret;
}

typedef struct {
    rtnl_fwmark_rule_t *rules;
    int n;
    uint8_t family;
} rules_ctx_t;

/* A u32 attribute must be 4 bytes: anything else is a broken dump. */
static int attr_u32(const struct rtattr *a, uint32_t *v) {
    if (RTA_PAYLOAD(a) != sizeof(*v)) return -1;
    memcpy(v, RTA_DATA(a), sizeof(*v));
    return 0;
}

/* NDMS's rule for a policy is "fwmark <mark> lookup <table>" and nothing
 * else. On Linux 4.9 (fib_nl_newrule) a rule given a non-zero mark without a
 * mask compares all bits ("compatibility: if the mark value is non-zero all
 * bits are compared unless a mask is explicitly specified"), and
 * fib_nl_fill_rule dumps FRA_FWMASK whenever the mark is non-zero; so a
 * missing FRA_FWMASK is read as the full mask, and an explicit 0 mask (it
 * matches every mark) does not count. "not" (FIB_RULE_INVERT), any address,
 * tos, interface or other selector, and a suppressor, make it another rule.
 * The table is FRA_TABLE: the header holds only its low byte. A table 0
 * leaves the mark as one without a rule. */
static int on_rule(const struct nlmsghdr *h, void *arg) {
    rules_ctx_t *c = arg;
    if (h->nlmsg_type != RTM_NEWRULE || h->nlmsg_len < NLMSG_LENGTH(sizeof(struct fib_rule_hdr)))
        return -1;
    const struct fib_rule_hdr *frh = NLMSG_DATA(h);
    uint32_t mark = 0, mask = 0xffffffffu, table = frh->table, v;
    int selects = frh->src_len || frh->dst_len || frh->tos || (frh->flags & FIB_RULE_INVERT);
    int alen = (int)(h->nlmsg_len - NLMSG_LENGTH(sizeof(*frh)));
    const struct rtattr *a = (const struct rtattr *)((const char *)frh + NLMSG_ALIGN(sizeof(*frh)));
    for (; RTA_OK(a, alen); a = RTA_NEXT(a, alen)) {
        switch (a->rta_type) {
        case FRA_FWMARK:
            if (attr_u32(a, &mark) != 0) return -1;
            break;
        case FRA_FWMASK:
            if (attr_u32(a, &mask) != 0) return -1;
            break;
        case FRA_TABLE:
            if (attr_u32(a, &table) != 0) return -1;
            break;
        case FRA_SUPPRESS_PREFIXLEN:
            if (attr_u32(a, &v) != 0) return -1;
            if (v != 0xffffffffu) selects = 1;  /* -1: none, dumped for every rule */
            break;
        case FRA_PRIORITY:
        case FRA_FLOW:
        case RTNL_FRA_PROTOCOL:
            break;
        default:
            selects = 1;                        /* iif, oif, from, to, tun_id, l3mdev, goto, newer ones */
        }
    }
    if (alen != 0) return -1;                   /* bytes left that are no attribute */
    if (frh->family != c->family || frh->action != FR_ACT_TO_TBL || selects ||
        mark == 0 || mask != 0xffffffffu)
        return 0;
    for (int k = 0; k < c->n; k++)
        if (c->rules[k].mark == mark && c->rules[k].table == 0) c->rules[k].table = table;
    return 0;
}

int rtnl_fwmark_rules(int family, rtnl_fwmark_rule_t *rules, int n) {
    rules_ctx_t c = {rules, n, (uint8_t)family};
    int found = 0;
    for (int k = 0; k < n; k++) rules[k].table = 0;
    if (rtnl_dump(RTM_GETRULE, (uint8_t)family, on_rule, &c) != 0) return -1;
    for (int k = 0; k < n; k++)
        if (rules[k].table) found++;
    return found;
}
