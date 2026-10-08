#ifndef GUARD_H
#define GUARD_H

#include <stddef.h>
#include <stdint.h>

/* hrneo's netfilter rules, spelled exactly as iptables 1.4.21 `-S` prints
 * them back: a full mask is left out (`--mark 0x0`, not `0x0/0xffffffff`),
 * marks are lowercase hex without leading zeros. The commit audit compares
 * dump lines with these strings byte for byte, so any other spelling would
 * replace the rules on every commit. */

#define GUARD_CHAIN         "HRNEO_GUARD"
#define GUARD_JUMP          "-A PREROUTING -j " GUARD_CHAIN
#define GUARD_LINE_MAX      320
#define GUARD_MANGLE_RULES  4

/* Packet mark NDMS gives to devices bound to a policy (0xffffaaX). With
 * GlobalRouting=false hrneo leaves such packets to NDMS (R1). */
#define GUARD_NDM_MARK      "0xffffaa0/0xffffff0"

/* Rule k (0..3) of a target in mangle PREROUTING, in this order:
 *  R0  policy targets only: copy the mark raw gave the packet into connmark
 *  R1  packets without that mark (RawGuard=false, degraded): first marking
 *  R2  restore connmark into the packet mark, only when connmark is not 0
 *  R3  replies of inbound connections: clear the raw mark
 * No subset of these rules can write 0 over the raw mark of an outbound
 * packet. Writes the rule into out without a newline. Returns its length,
 * 0 when the target has no rule k (R0 of an interface target), -1 if out is
 * too small. */
int guard_mangle_rule(char *out, size_t size, int k, const char *set,
                      uint32_t mark, int is_interface, int global_routing);

#endif
