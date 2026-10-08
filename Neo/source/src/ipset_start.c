#include "../include/ipset_start.h"
#include "../include/config.h"
#include "../include/geodat.h"
#include "../include/log.h"
#include <errno.h>
#include <string.h>

/* §4.3: the sets survive a restart unless config_flush_ipsets_on_start()
 * says otherwise (neo ipset-clean), so the raw guard keeps matching while
 * hrneo is down. After a flush the CIDR list puts its permanent addresses
 * back here; addresses learned from DNS come back with new DNS answers. */
void ipset_start_targets(ipset_manager_t *mgr, const ipset_pair_t *pairs, int count,
                         const config_t *cfg) {
    int flush = config_flush_ipsets_on_start(cfg);
    if (cfg->clear_ipset && !flush)
        LOG_INFO("clearIPSet=true: ipsets kept, KeepIpsetOnRestart=true (neo ipset-clean empties them)");
    for (int i = 0; i < count; i++) {
        ipset_create(mgr, pairs[i].ipv4, IPSET_HASH_TYPE, AF_INET, mgr->default_timeout,
                     (uint32_t)cfg->ipset_maxelem);
        ipset_create(mgr, pairs[i].ipv6, IPSET_HASH_TYPE, AF_INET6, mgr->default_timeout,
                     (uint32_t)cfg->ipset_maxelem);
        if (flush) {
            ipset_flush(mgr, pairs[i].ipv4);
            ipset_flush(mgr, pairs[i].ipv6);
        }
    }
    if (cfg->cidr_enabled && cfg->cidr_file_path[0] != '\0') {
        int rc = add_cidr_to_ipsets(mgr, cfg->cidr_file_path,
                                    (const char (*)[512])cfg->geo_ip_files,
                                    cfg->geo_ip_file_count, (uint32_t)cfg->ipset_maxelem);
        /* A missing file is an empty list, the normal case. Anything else left
         * part of the list unread, and the kept sets may hold permanent hosts
         * of that part: the unread part could feed any of our sets, so none
         * may refresh its existing entries (they would get IpsetTimeout). */
        if (rc != 0 && rc != -ENOENT) {
            LOG_WARN("CIDR list %s not fully loaded (%s)", cfg->cidr_file_path, strerror(-rc));
            for (int i = 0; i < count; i++) {
                ipset_perm_mark_incomplete(mgr, pairs[i].ipv4);
                ipset_perm_mark_incomplete(mgr, pairs[i].ipv6);
            }
        }
    }
}
