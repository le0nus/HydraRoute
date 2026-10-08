#include "../include/guard.h"
#include <stdio.h>

static int fit(int n, size_t size) {
    return (n < 0 || (size_t)n >= size) ? -1 : n;
}

int guard_mangle_rule(char *out, size_t size, int k, const char *set,
                      uint32_t mark, int is_interface, int global_routing) {
    switch (k) {
    case 0:
        if (is_interface) return 0;
        return fit(snprintf(out, size,
            "-A PREROUTING -m mark --mark 0x%x -m conntrack --ctdir ORIGINAL "
            "-m connmark --mark 0x0 -m set --match-set %s dst "
            "-j CONNMARK --set-xmark 0x%x/0xffffffff", mark, set, mark), size);
    case 1:
        return fit(snprintf(out, size,
            "-A PREROUTING %s-m conntrack --ctdir ORIGINAL "
            "-m connmark --mark 0x0 -m set --match-set %s dst "
            "-j CONNMARK --set-xmark 0x%x/0xffffffff",
            global_routing ? "" : "-m mark ! --mark " GUARD_NDM_MARK " ", set, mark), size);
    case 2:
        return fit(snprintf(out, size,
            "-A PREROUTING -m connmark ! --mark 0x0 -m set --match-set %s dst "
            "-j CONNMARK --restore-mark --nfmask 0xffffffff --ctmask 0xffffffff", set), size);
    case 3:
        return fit(snprintf(out, size,
            "-A PREROUTING -m conntrack --ctdir REPLY -m connmark --mark 0x0 "
            "-m set --match-set %s dst -j MARK --set-xmark 0x0/0xffffffff", set), size);
    }
    return 0;
}
