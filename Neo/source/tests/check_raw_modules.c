#define STATUS_PATH "build/check_raw_modules.status"
#include "fake_nf.h"

/* The raw table of each family on its own (§4.7). IPv4: iptable_raw.ko is
 * there but does not load (other firmware). IPv6: no ip6table_raw.ko, which
 * may mean built into the kernel, so reading the table decides; at first the
 * table is not there. Mangle goes in either way, the commit does not fail
 * over it, and the cause is a WARN once. */
int main(void) {
    config_t cfg;
    unified_target_t t[2];
    setup_targets(t, &cfg);
    cfg.raw_guard = 1;
    remove(STATUS_PATH);
    guard_status_init(STATUS_PATH);
    raw_kmod_fail[0] = 1;
    raw_dump_fail[1] = 1;

    reset();
    assert(apply_unified_connmark_rules(t, 2, &cfg, NULL) == 0);
    assert(strcmp(calls, "m4 m6 ") == 0);
    assert(raw_kmod_calls[0] == 1 && raw_kmod_calls[1] == 1);
    assert(dumps == 5);                     /* mangle and its read-back per family, raw v6 */
    assert_mangle(0, 0, 0xff2, 0);
    assert_mangle(1, 0, 0xff2, 0);
    assert(!nf[0].guard_exists && !nf[1].guard_exists);
    assert(status_has("raw_guard=degraded:modules-v4"));
    assert(status_has("raw_rules_v4=unknown") && status_has("raw_rules_v6=unknown"));
    assert(warns == 3);                     /* the v4 loader, the v6 dump, the raw guard */
    assert(strstr(warn_log, "kmod iptable_raw: init_module failed"));
    assert(strstr(warn_log, "ip6tables -t raw -S failed or output truncated"));
    assert(strstr(warn_log, "raw guard degraded: modules-v4"));

    /* Loading is tried once per process: no retries and no more log lines.
     * IPv4 raw is not even read; IPv6 raw is read again. */
    reset();
    assert(apply_unified_connmark_rules(t, 2, &cfg, NULL) == 0);
    assert(raw_kmod_calls[0] == 0 && raw_kmod_calls[1] == 0);
    assert(warns == 0 && calls[0] == '\0');
    assert(dumps == 3);                     /* mangle v4, mangle v6, raw v6 */

    /* The IPv6 table is there now (built in, or loaded by someone): its chain
     * goes in without a loader call; IPv4 stays as it is. */
    raw_dump_fail[1] = 0;
    reset();
    assert(apply_unified_connmark_rules(t, 2, &cfg, NULL) == 0);
    assert(strcmp(calls, "r6 ") == 0);
    assert(raw_kmod_calls[0] == 0 && raw_kmod_calls[1] == 0);
    assert(warns == 0);
    assert(!nf[0].guard_exists);
    assert_raw(1, 0xff2);
    assert(status_has("raw_guard=degraded:modules-v4"));
    assert(status_has("raw_rules_v4=unknown") && status_has("raw_rules_v6=2"));

    puts("check_raw_modules: OK");
    return 0;
}
