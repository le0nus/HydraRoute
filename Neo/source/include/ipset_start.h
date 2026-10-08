#ifndef IPSET_START_H
#define IPSET_START_H

#include "hrneo.h"
#include "ipset_nl.h"

/* At start: the v4 and v6 set of every target exists, emptied only when
 * config_flush_ipsets_on_start(), then the CIDR list is loaded into them.
 * mgr->default_timeout is the timeout of new sets. */
void ipset_start_targets(ipset_manager_t *mgr, const ipset_pair_t *pairs, int count,
                         const config_t *cfg);

#endif
