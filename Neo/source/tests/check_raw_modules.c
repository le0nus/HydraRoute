#define STATUS_PATH "build/check_raw_modules.status"
#include "fake_nf.h"

/* The raw table of each family on its own (§4.7). IPv4: iptable_raw.ko is
 * there but does not load (other firmware); it is not tried again. IPv6: no
 * ip6table_raw.ko, which may mean built into the kernel. Either way reading
 * the table decides, on every commit: at first the read fails and the kernel
 * does not list raw, so the table is absent. Mangle goes in, the commit does
 * not fail over it, and each cause is a WARN once. */
int main(void) {
    config_t cfg;
    unified_target_t t[2];
    setup_targets(t, &cfg);
    cfg.raw_guard = 1;
    remove(STATUS_PATH);
    guard_status_init(STATUS_PATH);
    raw_kmod_fail[0] = 1;
    raw_dump_fail[0] = raw_dump_fail[1] = 1;
    raw_listed[0] = raw_listed[1] = 0;

    reset();
    assert(apply_unified_connmark_rules(t, 2, &cfg, NULL) == 0);
    assert(strcmp(calls, "m4 m6 ") == 0);
    assert(raw_kmod_calls[0] == 1 && raw_kmod_calls[1] == 1);
    assert(dumps == 6);                     /* per family: mangle, its read-back, raw */
    assert(proc_calls == 2);
    assert_mangle(0, 0, 0xff2, 0);
    assert_mangle(1, 0, 0xff2, 0);
    assert(!nf[0].guard_exists && !nf[1].guard_exists);
    assert(status_has("raw_guard=degraded:raw-modules-v4"));
    assert(status_has("raw_rules_v4=unknown") && status_has("raw_rules_v6=unknown"));
    assert(warns == 4);                     /* the v4 loader, both raw reads, the raw guard */
    assert(strstr(warn_log, "kmod iptable_raw: init_module failed"));
    assert(strstr(warn_log, "iptables -t raw -S failed or output truncated"));
    assert(strstr(warn_log, "ip6tables -t raw -S failed or output truncated"));
    assert(strstr(warn_log, "raw guard degraded: raw-modules-v4"));

    /* Loading is tried once per process: no second attempt and no more log
     * lines, but raw is read again in both families. */
    reset();
    assert(apply_unified_connmark_rules(t, 2, &cfg, NULL) == 0);
    assert(raw_kmod_calls[0] == 0 && raw_kmod_calls[1] == 0);
    assert(warns == 0 && calls[0] == '\0');
    assert(dumps == 4 && proc_calls == 2);  /* mangle and raw per family */

    /* The IPv6 table is there now (built in, or loaded by someone): its chain
     * goes in without a loader call; IPv4 stays as it is. */
    raw_dump_fail[1] = 0;
    raw_listed[1] = 1;
    reset();
    assert(apply_unified_connmark_rules(t, 2, &cfg, NULL) == 0);
    assert(strcmp(calls, "r6 ") == 0);
    assert(raw_kmod_calls[0] == 0 && raw_kmod_calls[1] == 0);
    assert(warns == 0);
    assert(!nf[0].guard_exists);
    assert_raw(1, 0xff2);
    assert(status_has("raw_guard=degraded:raw-modules-v4"));
    assert(status_has("raw_rules_v4=unknown") && status_has("raw_rules_v6=2"));

    /* Another process loads iptable_raw after hrneo's attempt failed: the
     * next commit reads the table and puts the chain in. */
    raw_dump_fail[0] = 0;
    raw_listed[0] = 1;
    reset();
    assert(apply_unified_connmark_rules(t, 2, &cfg, NULL) == 0);
    assert(strcmp(calls, "r4 ") == 0);
    assert(raw_kmod_calls[0] == 0);
    assert_raw(0, 0xff2);
    assert(status_has("raw_guard=on") && status_has("raw_rules_v4=2"));

    puts("check_raw_modules: OK");
    return 0;
}
