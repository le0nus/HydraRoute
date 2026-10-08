#include "../include/args.h"
#include "../include/config.h"
#include "../include/ipset_start.h"
#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

/* The target sets at start (§4.3), with the netlink calls faked: which sets
 * are created and emptied, and that the CIDR list's permanent addresses go
 * in after any flush. */

#define CONF_PATH "build/check_ipset_start.conf"

static char calls[1024], info_log[1024];
extern int log_enabled;

int __wrap_ipset_create(ipset_manager_t *mgr, const char *name, const char *type, int family,
                        uint32_t timeout, uint32_t maxelem) {
    assert(strcmp(type, IPSET_HASH_TYPE) == 0);
    assert(family == (strstr(name, "v6") ? AF_INET6 : AF_INET));
    assert(timeout == mgr->default_timeout && maxelem == 262144);
    snprintf(calls + strlen(calls), sizeof(calls) - strlen(calls), "create %s,", name);
    return 0;
}

int __wrap_ipset_flush(ipset_manager_t *mgr, const char *name) {
    (void)mgr;
    snprintf(calls + strlen(calls), sizeof(calls) - strlen(calls), "flush %s,", name);
    return 0;
}

int __wrap_add_cidr_to_ipsets(ipset_manager_t *mgr, const char *cidr_path,
                              const char (*geoip_files)[512], int geoip_count, uint32_t maxelem) {
    (void)mgr; (void)geoip_files; (void)geoip_count; (void)maxelem;
    snprintf(calls + strlen(calls), sizeof(calls) - strlen(calls), "cidr %s,", cidr_path);
    return 0;
}

void __wrap_log_write(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(info_log + strlen(info_log), sizeof(info_log) - strlen(info_log), fmt, ap);
    va_end(ap);
}

static const ipset_pair_t PAIRS[2] = {{"RU", "RUv6"}, {"HydraRoute", "HydraRoutev6"}};

/* One start: the config file, then the CLI flags, as main() reads them. */
static void start(const char *conf, int argc, char **argv) {
    FILE *f = fopen(CONF_PATH, "w");
    assert(f);
    fputs(conf, f);
    fclose(f);
    config_t cfg;
    cli_args_t args;
    assert(config_read(CONF_PATH, &cfg) == 0);
    assert(args_parse(argc, argv, &args) == 0);
    args_apply(&args, &cfg);
    ipset_manager_t mgr;
    memset(&mgr, 0, sizeof(mgr));
    mgr.default_timeout = 21600;
    calls[0] = info_log[0] = '\0';
    ipset_start_targets(&mgr, PAIRS, 2, &cfg);
}

#define CREATE "create RU,create RUv6,"
#define CREATE_HR "create HydraRoute,create HydraRoutev6,"
#define CIDR "cidr /opt/etc/HydraRoute/ip.list,"

int main(void) {
    char *plain[] = {"hrneo", NULL};
    char *clean[] = {"hrneo", "--KeepIpsetOnRestart", "false", "--clearIPSet", "true", NULL};
    log_enabled = 1;

    /* A restart with clearIPSet=true (the default) keeps the sets, and says
     * so; the CIDR list is loaded again on top of what is there. */
    start("clearIPSet=true\n", 1, plain);
    assert(strcmp(calls, CREATE CREATE_HR CIDR) == 0);
    assert(strstr(info_log, "[INFO] clearIPSet=true: ipsets kept, KeepIpsetOnRestart=true"));
    start("", 1, plain);
    assert(strcmp(calls, CREATE CREATE_HR CIDR) == 0);

    /* neo ipset-clean over a file that keeps them: every set of every target
     * is emptied, and only then the permanent addresses go back in. */
    start("clearIPSet=false\nKeepIpsetOnRestart=true\n", 5, clean);
    assert(strcmp(calls, CREATE "flush RU,flush RUv6," CREATE_HR
                         "flush HydraRoute,flush HydraRoutev6," CIDR) == 0);
    assert(!strstr(info_log, "ipsets kept"));

    /* The same from the file alone. */
    start("clearIPSet=true\nKeepIpsetOnRestart=false\n", 1, plain);
    assert(strcmp(calls, CREATE "flush RU,flush RUv6," CREATE_HR
                         "flush HydraRoute,flush HydraRoutev6," CIDR) == 0);

    /* Neither flag: nothing is emptied and nothing is said about it. */
    start("clearIPSet=false\n", 1, plain);
    assert(strcmp(calls, CREATE CREATE_HR CIDR) == 0);
    assert(info_log[0] == '\0');

    /* Without a CIDR list there is nothing to load after the flush. */
    start("CIDR=false\n", 5, clean);
    assert(strcmp(calls, CREATE "flush RU,flush RUv6," CREATE_HR
                         "flush HydraRoute,flush HydraRoutev6,") == 0);

    remove(CONF_PATH);
    puts("check_ipset_start: OK");
    return 0;
}
