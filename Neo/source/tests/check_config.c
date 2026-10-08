#include "../include/args.h"
#include "../include/config.h"
#include "../include/params.h"
#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

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

/* Runs fn with stdout in path, so its output can be checked and does not
 * show among the test lines. */
static void capture_stdout(const char *path, void (*fn)(void)) {
    fflush(stdout);
    int saved = dup(1);
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    assert(saved >= 0 && fd >= 0);
    dup2(fd, 1);
    close(fd);
    fn();
    fflush(stdout);
    dup2(saved, 1);
    close(saved);
}

static int file_has_line(const char *path, const char *want) {
    char line[512];
    int found = 0;
    FILE *f = fopen(path, "r");
    assert(f);
    while (!found && fgets(line, sizeof(line), f)) {
        line[strcspn(line, "\n")] = '\0';
        found = strcmp(line, want) == 0;
    }
    fclose(f);
    return found;
}

static int file_has(const char *path, const char *needle) {
    char buf[16384];
    FILE *f = fopen(path, "r");
    assert(f);
    size_t n = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    buf[n] = '\0';
    return strstr(buf, needle) != NULL;
}

#define GEN_PATH  "build/check_config.gen"
#define HELP_PATH "build/check_config.help"

static void gen_defaults(void) { assert(config_generate(GEN_PATH) == 0); }

static void help(void) {
    char *argv[] = {"hrneo", "--help", NULL};
    cli_args_t args;
    assert(args_parse(2, argv, &args) == 2);
}

/* §4.3: a restart keeps the sets even with clearIPSet=true, so the raw guard
 * still matches through it; neo ipset-clean restarts with flags that empty
 * them whatever the file says. */
static void check_keep_ipset(void) {
    config_t cfg;

    /* A config without the key (hrweb rewrites the file without keys it
     * does not know), and an empty one: kept. clearIPSet defaults to true. */
    write_conf("clearIPSet=true\n");
    assert(config_read(CONF_PATH, &cfg) == 0);
    assert(cfg.keep_ipset_on_restart == 1);
    assert(config_flush_ipsets_on_start(&cfg) == 0);
    write_conf("");
    assert(config_read(CONF_PATH, &cfg) == 0);
    assert(cfg.clear_ipset == 1 && cfg.keep_ipset_on_restart == 1);
    assert(config_flush_ipsets_on_start(&cfg) == 0);

    /* Off in the file, spaces around key and value: clearIPSet counts. */
    write_conf("clearIPSet=true\n  KeepIpsetOnRestart  =  false  \n");
    assert(config_read(CONF_PATH, &cfg) == 0);
    assert(cfg.keep_ipset_on_restart == 0);
    assert(config_flush_ipsets_on_start(&cfg) == 1);
    write_conf("clearIPSet=false\nKeepIpsetOnRestart=false\n");
    assert(config_read(CONF_PATH, &cfg) == 0);
    assert(config_flush_ipsets_on_start(&cfg) == 0);

    /* The CLI wins both ways. */
    write_conf("clearIPSet=true\nKeepIpsetOnRestart=false\n");
    assert(config_read(CONF_PATH, &cfg) == 0);
    char *keep[] = {"hrneo", "--KeepIpsetOnRestart", "true", NULL};
    cli_args_t args;
    assert(args_parse(3, keep, &args) == 0);
    args_apply(&args, &cfg);
    assert(cfg.keep_ipset_on_restart == 1);
    assert(config_flush_ipsets_on_start(&cfg) == 0);

    write_conf("clearIPSet=true\n");
    assert(config_read(CONF_PATH, &cfg) == 0);
    char *nokeep[] = {"hrneo", "--KeepIpsetOnRestart", "false", NULL};
    assert(args_parse(3, nokeep, &args) == 0);
    args_apply(&args, &cfg);
    assert(cfg.keep_ipset_on_restart == 0);
    assert(config_flush_ipsets_on_start(&cfg) == 1);

    /* neo ipset-clean passes exactly these flags (S99hrneo, check_lifecycle):
     * they empty the sets over a file that keeps them. */
    write_conf("clearIPSet=false\nKeepIpsetOnRestart=true\n");
    assert(config_read(CONF_PATH, &cfg) == 0);
    char *clean[] = {"hrneo", "--KeepIpsetOnRestart", "false", "--clearIPSet", "true", NULL};
    assert(args_parse(5, clean, &args) == 0);
    args_apply(&args, &cfg);
    assert(cfg.clear_ipset == 1 && cfg.keep_ipset_on_restart == 0);
    assert(config_flush_ipsets_on_start(&cfg) == 1);
    remove(CONF_PATH);

    /* The generated defaults and the help carry the new key. */
    capture_stdout(HELP_PATH, gen_defaults);
    assert(file_has_line(GEN_PATH, "KeepIpsetOnRestart=true"));
    assert(file_has_line(GEN_PATH, "RawGuard=true"));
    assert(file_has_line(GEN_PATH, "clearIPSet=true"));
    assert(config_read(GEN_PATH, &cfg) == 0);
    assert(cfg.keep_ipset_on_restart == 1 && config_flush_ipsets_on_start(&cfg) == 0);
    remove(GEN_PATH);
    capture_stdout(HELP_PATH, help);
    assert(file_has(HELP_PATH, "--KeepIpsetOnRestart <true|false>"));
    remove(HELP_PATH);
}

/* Every parameter has its own bit in the 64-bit set_mask: one shared bit
 * would let one flag on the CLI override the other's config value. */
static void check_set_bits(void) {
    for (int i = 0; i < PARAMS_COUNT; i++) {
        assert(PARAMS[i].set_bit != 0 && (PARAMS[i].set_bit & (PARAMS[i].set_bit - 1)) == 0);
        for (int j = i + 1; j < PARAMS_COUNT; j++) assert(PARAMS[i].set_bit != PARAMS[j].set_bit);
    }
}

/* hrneo --raw-off is a command of its own: no daemon, the config not read. */
static void check_raw_off_flag(void) {
    char *argv[] = {"hrneo", "--raw-off", NULL};
    cli_args_t args;
    assert(args_parse(2, argv, &args) == 6);
    char *after[] = {"hrneo", "--config", "/nonexistent", "--raw-off", NULL};
    assert(args_parse(4, after, &args) == 6);
    capture_stdout(HELP_PATH, help);
    assert(file_has(HELP_PATH, "--raw-off"));
    remove(HELP_PATH);
}

/* BlockedLogDelay uses set bit 32: a 32-bit set_mask would drop the CLI flag. */
static void check_blocked_log_delay(void) {
    config_t cfg;
    write_conf("log=off\n");
    assert(config_read(CONF_PATH, &cfg) == 0);
    assert(cfg.blocked_log_delay == 30);
    char *argv[] = {"hrneo", "--BlockedLogDelay", "5", NULL};
    cli_args_t args;
    assert(args_parse(3, argv, &args) == 0);
    args_apply(&args, &cfg);
    assert(cfg.blocked_log_delay == 5);
    write_conf("BlockedLogDelay=60\n");
    assert(config_read(CONF_PATH, &cfg) == 0);
    assert(cfg.blocked_log_delay == 60);
    remove(CONF_PATH);
    for (int i = 0; i < PARAMS_COUNT; i++)
        if (strcmp(PARAMS[i].config_key, "BlockedLogDelay") == 0) assert(PARAMS[i].set_bit == (1ull << 32));

    capture_stdout(HELP_PATH, gen_defaults);
    assert(file_has_line(GEN_PATH, "BlockedLogDelay=30"));
    remove(GEN_PATH);
    capture_stdout(HELP_PATH, help);
    assert(file_has(HELP_PATH, "--BlockedLogDelay <seconds>"));
    remove(HELP_PATH);
}

int main(void) {
    check_empty_geo_files_ignored();
    check_raw_guard();
    check_keep_ipset();
    check_set_bits();
    check_raw_off_flag();
    check_blocked_log_delay();
    printf("check_config: OK\n");
    return 0;
}
