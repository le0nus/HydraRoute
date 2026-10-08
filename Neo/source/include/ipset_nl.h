#ifndef IPSET_NL_H
#define IPSET_NL_H

#include "hrneo.h"
#include <netinet/in.h>

#define IPSET_MAX_SETS 512

/* The wait for one netlink answer (Ruling 50): SO_RCVTIMEO of every recv,
 * and the time within which answers to older requests are skipped. A
 * request whose answer does not come, a batch sent in part or an answer out
 * of step replaces the socket, so no answer left behind reaches the next
 * request; an ADD without timeout whose result is not known marks its set
 * incomplete. */
#define IPSET_NL_TIMEOUT_MS 1000

/* Host entries (/32, /128) a CIDR list added without timeout, per set: a DNS
 * answer for such an IP must not give it IpsetTimeout. Keys are appended while
 * the lists load, sorted and deduplicated once at the first lookup after that,
 * and found by halving: 81 bytes per host (capacity is a power of two) instead
 * of an 8192-bucket table.
 *
 * "Incomplete" sets: when the index may lack hosts the kernel still holds
 * (allocation failure here, or a CIDR list that did not load at start), the
 * entries of that set are not refreshed at all, since refreshing a permanent
 * host would give it IpsetTimeout. Only the set names are kept (allocated on
 * the first failure), nothing per host; a new manager (restart) starts clean. */
typedef struct {
    char    set[64];
    uint8_t family;
    uint8_t ip[16];
} ipset_perm_key_t;

typedef struct {
    ipset_perm_key_t *keys;
    size_t count, cap;
    int sorted;
    int all_incomplete;             /* every set is incomplete (no memory for names) */
    char (*incomplete)[64];         /* names of the incomplete sets */
    size_t incomplete_count;
} ipset_perm_t;

typedef struct {
    int fd;
    uint32_t seq;
    uint32_t pid;
    uint32_t default_timeout;
    char set_names[IPSET_MAX_SETS][64];
    int set_count;
    ipset_perm_t permanent;         /* host entries added without timeout */
} ipset_manager_t;

int ipset_manager_init(ipset_manager_t *mgr);
void ipset_manager_close(ipset_manager_t *mgr);

int ipset_create(ipset_manager_t *mgr, const char *name, const char *type, int family, uint32_t timeout, uint32_t maxelem);
int ipset_flush(ipset_manager_t *mgr, const char *name);

/* Adds entries to set_name: with_timeout for DNS/L7 entries (IpsetTimeout,
 * NLM_F_EXCL; an existing one is refreshed), without for the CIDR lists
 * (permanent). With with_timeout, new_indices (room for count) gets the
 * index of every entry that is new, and of every entry sent whose answer did
 * not come, since it may be in the set now (Ruling 52): the caller flushes
 * conntrack for all of them, also when the call returns -1. Returns 0, or -1
 * when some entry's result is not known (not sent, answer lost or out of
 * step) or, for permanent entries, the kernel refused one. */
int ipset_add_batch(ipset_manager_t *mgr, const char *set_name,
                    const parsed_cidr_t *entries, int count,
                    int with_timeout, int *new_count, int *new_indices);

/* The permanent-host index of the set may be missing hosts: stop refreshing
 * its existing entries (one WARN per set). */
void ipset_perm_mark_incomplete(ipset_manager_t *mgr, const char *set_name);
int ipset_perm_incomplete(const ipset_manager_t *mgr, const char *set_name);

int ipset_refresh_set_list(ipset_manager_t *mgr);
int ipset_set_exists(ipset_manager_t *mgr, const char *name);

#endif
