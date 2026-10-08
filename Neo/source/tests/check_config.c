#include "../include/args.h"
#include "../include/config.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

#define CONF_PATH "build/check_config.conf"

/* PARAMS[] use more than 32 set bits. */
_Static_assert(sizeof(((cli_args_t *)0)->set_mask) == 8, "set_mask must be 64-bit");

static void write_conf(const char *text) {
    FILE *f = fopen(CONF_PATH, "w");
    assert(f);
    fputs(text, f);
    fclose(f);
}

static void check_empty_geo_files_ignored(void) {
    write_conf("GeoIPFile=\nGeoSiteFile=\nGeoSiteFile=/opt/geosite.dat\nGeoSiteFile=\n");
    config_t cfg;
    assert(config_read(CONF_PATH, &cfg) == 0);
    assert(cfg.geo_ip_file_count == 0);
    assert(cfg.geo_site_file_count == 1);
    assert(strcmp(cfg.geo_site_files[0], "/opt/geosite.dat") == 0);
    remove(CONF_PATH);
}

/* hrweb rewrites hrneo.conf without keys it does not know: a missing key must
 * keep the guard on (§5). The CLI can still turn it off. */
static void check_raw_guard(void) {
    write_conf("GlobalRouting=false\n");
    config_t cfg;
    assert(config_read(CONF_PATH, &cfg) == 0);
    assert(cfg.raw_guard == 1);

    char *argv[] = {"hrneo", "--RawGuard", "false", NULL};
    cli_args_t args;
    assert(args_parse(3, argv, &args) == 0);
    args_apply(&args, &cfg);
    assert(cfg.raw_guard == 0);

    write_conf("RawGuard=false\n");
    assert(config_read(CONF_PATH, &cfg) == 0);
    assert(cfg.raw_guard == 0);
    remove(CONF_PATH);
}

int main(void) {
    check_empty_geo_files_ignored();
    check_raw_guard();
    printf("check_config: OK\n");
    return 0;
}
