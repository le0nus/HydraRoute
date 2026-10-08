#ifndef IPSET_NL_H
#define IPSET_NL_H

#include "hrneo.h"
#include <netinet/in.h>

#define IPSET_MAX_SETS 512

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
