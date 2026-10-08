#ifndef GEODAT_H
#define GEODAT_H

#include "hrneo.h"
#include "ipset_nl.h"

int parse_geosite_rules(const char *watchlist_path,
                        geosite_rule_t *rules, int max_rules);

int build_geosite_domain_map(const char (*file_paths)[512], int file_count,
                             const geosite_rule_t *rules, int rule_count,
                             domain_hashtable_t *ht);

int parse_cidr_policy_headers(const char *path, char names[][64], int max_names);

/* Loads the CIDR list into the target sets. 0 on success, -ENOENT when the
 * file is missing (an empty list), otherwise -errno of what was lost: the file
 * could not be read, an entry was dropped for lack of memory, a GeoIP file it
 * names is missing or cut short (the ENOENT exemption is for the list only),
 * a batch could not be sent or acknowledged. */
int add_cidr_to_ipsets(ipset_manager_t *mgr, const char *cidr_path,
                       const char (*geoip_files)[512], int geoip_count,
                       uint32_t maxelem);

#endif
