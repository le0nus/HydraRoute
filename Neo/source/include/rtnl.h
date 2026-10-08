#ifndef RTNL_H
#define RTNL_H

#include <stddef.h>
#include <stdint.h>
#include <linux/netlink.h>

#define RTNL_TIMEOUT_MS   1000
#define RTNL_BUF_SIZE     8192

#define RTNL_MORE   1
#define RTNL_DONE   0
#define RTNL_FAIL  (-1)

/* Called for every message of a dump reply; non-zero ends it with RTNL_FAIL. */
typedef int (*rtnl_msg_fn)(const struct nlmsghdr *h, void *ctx);

/* Parses one datagram of a dump reply. Messages with another sequence number
 * are skipped. Returns RTNL_MORE until NLMSG_DONE with result 0, and
 * RTNL_DONE only once the rest of that datagram is checked too; RTNL_FAIL on
 * NLMSG_DONE with an error, NLMSG_ERROR other than an ACK, NLMSG_OVERRUN, an
 * interrupted dump (NLM_F_DUMP_INTR), a cut or broken message, a message of
 * the dump after its NLMSG_DONE, or a callback error. */
int rtnl_parse(const void *buf, size_t len, uint32_t seq, rtnl_msg_fn fn, void *ctx);

/* Dumps one rtnetlink table (RTM_GETRULE, RTM_GETROUTE) of a family on a
 * socket of its own, separate from the ipset and conntrack sockets, and feeds
 * every reply message to fn. Returns 0 after NLMSG_DONE, -1 on any error, on
 * a datagram larger than RTNL_BUF_SIZE, when no datagram came for
 * RTNL_TIMEOUT_MS, or when it was not done by the deadline (rtnl_set_deadline). */
int rtnl_dump(uint16_t type, uint8_t family, rtnl_msg_fn fn, void *ctx);

typedef struct {
    uint32_t mark;          /* in: a policy mark */
    uint32_t table;         /* out: table of its NDMS rule, 0 if there is none */
} rtnl_fwmark_rule_t;

/* Finds the NDMS rule of each policy mark in one dump of the family's ip
 * rules: "fwmark <mark> lookup <table>" with a full mask and nothing else
 * that selects packets (no "not", from, to, iif, oif, tos, ...). The first
 * such rule of a mark gives its table. Marks are checked while the dump is
 * read, so a long rule list cannot push one out. Returns how many of the n
 * marks have a rule, or -1 if the dump failed or was broken anywhere; the
 * tables then mean nothing. */
int rtnl_fwmark_rules(int family, rtnl_fwmark_rule_t *rules, int n);

/* CLOCK_MONOTONIC in ms: the clock of rtnl_set_deadline. */
int64_t rtnl_now_ms(void);

/* A deadline on rtnl_now_ms() for the dumps that follow, 0 for none (the
 * default). With one, a dump asked for once it has passed fails at once,
 * without a request; each recv waits until the deadline at most (and
 * RTNL_TIMEOUT_MS at most), and a dump not done when it comes fails. */
void rtnl_set_deadline(int64_t deadline_ms);

#define RTNL_ROUTE_NONE     0   /* no default route in the table */
#define RTNL_ROUTE_UNICAST  1   /* default route through an interface */
#define RTNL_ROUTE_OTHER    2   /* default blackhole, unreachable, prohibit, ... */

/* State of the default route in each of tables[0..n-1] of the family, from
 * one route dump (the table comes from RTA_TABLE, so ids above 255 work;
 * cached clones are skipped; a table 0 matches nothing). A unicast default
 * through an interface (RTA_OIF or RTA_MULTIPATH) wins over any other
 * default of its table. Every route of the dump is checked, ours or not: a
 * broken one fails the dump. Returns 0, or -1 if the dump failed or was
 * broken anywhere; the states then mean nothing. */
int rtnl_default_routes(int family, const uint32_t *tables, int n, int *state);

#endif
