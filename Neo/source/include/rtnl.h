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
 * are skipped. Returns RTNL_MORE until NLMSG_DONE with result 0; RTNL_FAIL on
 * NLMSG_DONE with an error, NLMSG_ERROR other than an ACK, NLMSG_OVERRUN, an
 * interrupted dump (NLM_F_DUMP_INTR), a cut or broken message or a callback
 * error. */
int rtnl_parse(const void *buf, size_t len, uint32_t seq, rtnl_msg_fn fn, void *ctx);

/* Dumps one rtnetlink table (RTM_GETRULE, RTM_GETROUTE) of a family on a
 * socket of its own, separate from the ipset and conntrack sockets, and feeds
 * every reply message to fn. Returns 0 after NLMSG_DONE, -1 on any error, on
 * a datagram larger than RTNL_BUF_SIZE, or when no datagram came for
 * RTNL_TIMEOUT_MS. */
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

#endif
