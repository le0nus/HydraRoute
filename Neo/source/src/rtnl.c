#include "../include/rtnl.h"
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include <linux/fib_rules.h>
#include <linux/rtnetlink.h>

/* Linux 4.17+ puts FRA_PROTOCOL (who installed the rule) in every rule it
 * dumps; it selects nothing. Numbered here for older headers. */
#define RTNL_FRA_PROTOCOL 21

static uint32_t g_seq;
static int64_t g_deadline_ms;           /* rtnl_set_deadline; 0: none */

int64_t rtnl_now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

void rtnl_set_deadline(int64_t deadline_ms) {
    g_deadline_ms = deadline_ms;
}

/* How long the next recv may wait: RTNL_TIMEOUT_MS, or less to keep to the
 * deadline; 0 once it has passed. */
static int64_t wait_ms(void) {
    if (!g_deadline_ms) return RTNL_TIMEOUT_MS;
    int64_t left = g_deadline_ms - rtnl_now_ms();
    if (left <= 0) return 0;
    return left < RTNL_TIMEOUT_MS ? left : RTNL_TIMEOUT_MS;
}

/* SO_RCVTIMEO; ms > 0, since 0 would mean no timeout at all. */
static int set_wait(int fd, int64_t ms) {
    struct timeval tv;
    tv.tv_sec = (time_t)(ms / 1000);
    tv.tv_usec = (suseconds_t)(ms % 1000) * 1000;
    return setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
}

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
    int done = 0;
    while (len > 0) {
        const struct nlmsghdr *h = (const struct nlmsghdr *)p;
        if (len < NLMSG_HDRLEN || h->nlmsg_len < NLMSG_HDRLEN || h->nlmsg_len > len)
            return RTNL_FAIL;                   /* a cut or broken message */
        if (h->nlmsg_seq == seq) {
            if (done) return RTNL_FAIL;         /* nothing of the dump comes after its end */
            int st = rtnl_msg(h, fn, ctx);
            if (st == RTNL_FAIL) return RTNL_FAIL;
            done = st == RTNL_DONE;
        }
        size_t step = NLMSG_ALIGN(h->nlmsg_len);
        if (step > len) step = len;             /* the last message may go unpadded */
        p += step;
        len -= step;
    }
    /* The end counts only once the whole datagram it came in is checked. */
    return done ? RTNL_DONE : RTNL_MORE;
}

int rtnl_dump(uint16_t type, uint8_t family, rtnl_msg_fn fn, void *ctx) {
    int64_t wait = wait_ms();
    if (wait == 0) return -1;               /* past the deadline: nothing is asked */
    int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (fd < 0) return -1;

    struct sockaddr_nl sa;
    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;
    if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0 || set_wait(fd, wait) != 0) {
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
        int st = RTNL_MORE;                 /* EINTR: recv again */
        if (n < 0 && errno != EINTR) break;
        if (n >= 0) {
            if ((size_t)n > sizeof(buf)) break;
            st = rtnl_parse(buf, (size_t)n, req.h.nlmsg_seq, fn, ctx);
        }
        if (st != RTNL_MORE) {
            ret = st == RTNL_DONE ? 0 : -1;
            break;
        }
        /* A dump not done by the deadline fails; until then each recv waits
         * only for what is left of it. */
        if (g_deadline_ms && ((wait = wait_ms()) == 0 || set_wait(fd, wait) != 0)) break;
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

typedef struct {
    const uint32_t *tables;
    int n;
    int *state;
    uint8_t family;
} routes_ctx_t;

/* RTA_MULTIPATH: one or more struct rtnexthop, each with an interface and
 * its own attributes inside rtnh_len. 1 if it is that, else 0. */
static int multipath_ok(const struct rtattr *mp) {
    const char *p = RTA_DATA(mp);
    int len = (int)RTA_PAYLOAD(mp);
    if (len <= 0) return 0;
    while (len > 0) {
        const struct rtnexthop *nh = (const struct rtnexthop *)p;
        if (len < (int)sizeof(*nh) || nh->rtnh_len < sizeof(*nh) || nh->rtnh_len > len ||
            nh->rtnh_ifindex == 0)
            return 0;
        int alen = nh->rtnh_len - (int)RTNH_LENGTH(0);
        const struct rtattr *a = (const struct rtattr *)((const char *)nh + RTNH_LENGTH(0));
        while (RTA_OK(a, alen)) a = RTA_NEXT(a, alen);
        if (alen != 0) return 0;            /* bytes left that are no attribute */
        int step = (int)RTNH_ALIGN(nh->rtnh_len);
        if (step > len) step = len;         /* the last one may go unpadded */
        p += step;
        len -= step;
    }
    return 1;
}

/* A default route (dst_len 0) of a table asked for: unicast through an
 * interface (RTA_OIF or RTA_MULTIPATH) is a path, anything else (blackhole,
 * unreachable, prohibit, unicast without a device) is not, and a path wins
 * over another default of its table. The table is RTA_TABLE: the 4.9
 * header holds RT_TABLE_COMPAT (IPv4) or the low byte (IPv6) above 255.
 * Every route is checked, ours or not: a short message, another family, a
 * u32 attribute that is not 4 bytes, an interface 0, a broken multipath or
 * bytes left after the attributes fail the dump. Cached clones are skipped. */
static int on_route(const struct nlmsghdr *h, void *arg) {
    routes_ctx_t *c = arg;
    if (h->nlmsg_type != RTM_NEWROUTE || h->nlmsg_len < NLMSG_LENGTH(sizeof(struct rtmsg)))
        return -1;
    const struct rtmsg *r = NLMSG_DATA(h);
    if (r->rtm_family != c->family) return -1;
    uint32_t table = r->rtm_table, v;
    int dev = 0;
    int alen = (int)(h->nlmsg_len - NLMSG_LENGTH(sizeof(*r)));
    const struct rtattr *a = (const struct rtattr *)((const char *)r + NLMSG_ALIGN(sizeof(*r)));
    for (; RTA_OK(a, alen); a = RTA_NEXT(a, alen)) {
        switch (a->rta_type) {
        case RTA_TABLE:
            if (attr_u32(a, &table) != 0) return -1;
            break;
        case RTA_PRIORITY:
            if (attr_u32(a, &v) != 0) return -1;
            break;
        case RTA_OIF:
            if (attr_u32(a, &v) != 0 || v == 0) return -1;
            dev = 1;
            break;
        case RTA_MULTIPATH:
            if (!multipath_ok(a)) return -1;
            dev = 1;
            break;
        }
    }
    if (alen != 0) return -1;                   /* bytes left that are no attribute */
    if (r->rtm_dst_len != 0 || (r->rtm_flags & RTM_F_CLONED)) return 0;
    int s = (r->rtm_type == RTN_UNICAST && dev) ? RTNL_ROUTE_UNICAST : RTNL_ROUTE_OTHER;
    for (int p = 0; p < c->n; p++)
        if (c->tables[p] != 0 && c->tables[p] == table && c->state[p] != RTNL_ROUTE_UNICAST)
            c->state[p] = s;
    return 0;
}

int rtnl_default_routes(int family, const uint32_t *tables, int n, int *state) {
    routes_ctx_t c = {tables, n, state, (uint8_t)family};
    for (int p = 0; p < n; p++) state[p] = RTNL_ROUTE_NONE;
    return rtnl_dump(RTM_GETROUTE, (uint8_t)family, on_route, &c) == 0 ? 0 : -1;
}
