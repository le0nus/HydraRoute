#include "../include/args.h"
#include "../include/config.h"
#include "../include/ipset_start.h"
#include <assert.h>
#include <errno.h>
#include <linux/netlink.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

/* The target sets at start (§4.3), with the netlink calls faked: which sets
 * are created and emptied, and that the CIDR list's permanent addresses go
 * in after any flush. The last part runs the real CIDR loader (geodat.c)
 * over GeoIP files, through to a DNS answer. */

#define CONF_PATH "build/check_ipset_start.conf"

static char calls[1024], info_log[1024];
static int cidr_result;               /* what the faked CIDR load returns */
static ipset_manager_t mgr;           /* the manager of the last start */
static int sent_count, recv_count, next_reply;    /* fake kernel for the DNS step */
static uint16_t sent_flags[8];
static uint32_t sent_seq[8];

ssize_t __wrap_send(int fd, const void *buf, size_t len, int flags) {
    (void)fd; (void)flags;
    sent_seq[sent_count] = ((const struct nlmsghdr *)buf)->nlmsg_seq;
    sent_flags[sent_count++] = ((const struct nlmsghdr *)buf)->nlmsg_flags;
    return (ssize_t)len;
}

ssize_t __wrap_recv(int fd, void *buf, size_t len, int flags) {
    (void)fd; (void)flags;
    memset(buf, 0, len);
    struct nlmsghdr *h = buf;
    struct nlmsgerr *e = (struct nlmsgerr *)((uint8_t *)buf + NLMSG_HDRLEN);
    h->nlmsg_seq = sent_seq[recv_count++];
    h->nlmsg_type = NLMSG_ERROR;
    h->nlmsg_len = NLMSG_HDRLEN + sizeof(*e);
    e->error = -next_reply;
    return (ssize_t)h->nlmsg_len;
}
extern int log_enabled;

int __wrap_ipset_create(ipset_manager_t *mgr, const char *name, const char *type, int family,
                        uint32_t timeout, uint32_t maxelem) {
    assert(strcmp(type, IPSET_HASH_TYPE) == 0);
    assert(family == (strstr(name, "v6") ? AF_INET6 : AF_INET));
    assert(timeout == mgr->default_timeout && maxelem == 262144);
    snprintf(calls + strlen(calls), sizeof(calls) - strlen(calls), "create %s,", name);
    snprintf(mgr->set_names[mgr->set_count++], sizeof(mgr->set_names[0]), "%s", name);
    return 0;
}

int __wrap_ipset_flush(ipset_manager_t *mgr, const char *name) {
    (void)mgr;
    snprintf(calls + strlen(calls), sizeof(calls) - strlen(calls), "flush %s,", name);
    return 0;
}

/* With real_load the real loader (geodat.c) runs instead; its result is load_rc. */
static int real_load, load_rc;
int __real_add_cidr_to_ipsets(ipset_manager_t *mgr, const char *cidr_path,
                              const char (*geoip_files)[512], int geoip_count, uint32_t maxelem);

int __wrap_add_cidr_to_ipsets(ipset_manager_t *mgr, const char *cidr_path,
                              const char (*geoip_files)[512], int geoip_count, uint32_t maxelem) {
    snprintf(calls + strlen(calls), sizeof(calls) - strlen(calls), "cidr %s,", cidr_path);
    if (real_load)
        return load_rc = __real_add_cidr_to_ipsets(mgr, cidr_path, geoip_files, geoip_count, maxelem);
    return cidr_result;
}

int __wrap_ipset_refresh_set_list(ipset_manager_t *mgr) { (void)mgr; return 0; }

void __wrap_log_write(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(info_log + strlen(info_log), sizeof(info_log) - strlen(info_log), fmt, ap);
    va_end(ap);
}

static const ipset_pair_t PAIRS[2] = {{"RU", "RUv6"}, {"HydraRoute", "HydraRoutev6"}};

static void f_list(const char *text) {
    FILE *f = fopen("build/chain.list", "w");
    assert(f);
    fputs(text, f);
    fclose(f);
}

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
    memset(&mgr, 0, sizeof(mgr));
    mgr.default_timeout = 21600;
    calls[0] = info_log[0] = '\0';
    sent_count = recv_count = 0;
    ipset_start_targets(&mgr, PAIRS, 2, &cfg);
}

/* A start with the real loader over the list "geoip:xx" and a geoip.dat of
 * these bytes, every ADD acknowledged; then a DNS answer names host in set
 * and the kernel already has it. Returns the messages that answer sent:
 * 1 = the exclusive ADD only (entry left as it is), 2 = it was refreshed. */
static int load_then_dns(const uint8_t *dat, size_t len, const char *set,
                         const parsed_cidr_t *host) {
    char *plain[] = {"hrneo", NULL};
    FILE *f = fopen("build/chain.dat", "wb");
    assert(f && fwrite(dat, 1, len, f) == len);
    fclose(f);
    mgr.fd = -1;
    ipset_manager_close(&mgr);
    real_load = 1;
    next_reply = 0;
    start("CIDRfile=build/chain.list\nGeoIPFile=build/chain.dat\n", 1, plain);
    real_load = 0;
    sent_count = recv_count = 0;
    next_reply = IPSET_ERR_EXIST;
    int new_count, new_idx[1];
    assert(ipset_add_batch(&mgr, set, host, 1, 1, &new_count, new_idx) == 0);
    return sent_count;
}

#define XX 0x0a, 0x02, 'X', 'X'
#define H4 0x0a, 0x04, 198, 51, 100, 7                      /* ip 198.51.100.7 */
#define H6 0x0a, 0x10, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7  /* 2001:db8::7 */
#define V10 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x02     /* + 2^64 (bytes 2-10) */
#define C11 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00  /* bytes 2-11: 10th goes on */
/* XX with one entry for 198.51.100.7/32 whose tag (0x12) is replaced. */
#define ENTRY_AS(tag) {0x0a, 0x0e, XX, tag, 0x08, H4, 0x10, 32}

/* A good file: country YY, then XX with 198.51.100.7/32 (and an unknown
 * varint field 3 in it), 2001:db8::7/128, reverse_match (3) and an unknown
 * field 4: what the parser skips must not fail a good file. */
static const uint8_t GOOD[] = {
    0x0a, 0x04, 0x0a, 0x02, 'Y', 'Y',
    0x0a, 0x2c, XX,
    0x12, 0x0a, H4, 0x10, 32, 0x18, 0x05,
    0x12, 0x15, H6, 0x10, 0x80, 0x01,
    0x18, 0x00,
    0x22, 0x01, 0x00};

/* Broken files (Ruling 44). Each is a single record of country XX unless said. */
static const uint8_t PREFIX_288[] =                 /* Codex r3: 198.51.100.7, prefix 288 */
    {0x0a, 0x0f, 0x0a, 0x02, 0x58, 0x58, 0x12, 0x09, 0x0a, 0x04, 0xc6, 0x33, 0x64, 0x07, 0x10, 0xa0, 0x02};
static const uint8_t CODE_LEN_2_64[] =              /* Codex r3: code length 2^64+2 read as 2, "YY" */
    {0x0a, 0x0d, 0x0a, 0x82, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x02, 0x59, 0x59};
static const uint8_t CODE_LEN_11_BYTES[] =          /* code length of 11 bytes, then "YY" */
    {0x0a, 0x0e, 0x0a, 0x82, C11, 0x59, 0x59};
static const uint8_t RECORD_LEN_2_64[] =            /* record length 2^64+2, read as 2 */
    {0x0a, 0x82, V10, 0x0a, 0x00};
static const uint8_t RECORD_LEN_11_BYTES[] =        /* record length of 11 bytes */
    {0x0a, 0x82, C11, 0x0a, 0x00};
static const uint8_t FIELD_LEN_2_64[] =             /* unknown field 4 of length 2^64+10 swallows the entry */
    {0x0a, 0x19, XX, 0x22, 0x8a, V10, 0x12, 0x08, H4, 0x10, 32};
static const uint8_t PREFIX_2_32[] =                /* prefix 2^32+32: /32 if cut to 32 bits */
    {0x0a, 0x12, XX, 0x12, 0x0c, H4, 0x10, 0xa0, 0x80, 0x80, 0x80, 0x10};
static const uint8_t PREFIX_2_64[] =                /* prefix 2^64+32 */
    {0x0a, 0x17, XX, 0x12, 0x11, H4, 0x10, 0xa0, V10};
static const uint8_t V6_PREFIX_129[] = {0x0a, 0x1b, XX, 0x12, 0x15, H6, 0x10, 0x81, 0x01};
static const uint8_t V4_PREFIX_33[] = {0x0a, 0x0e, XX, 0x12, 0x08, H4, 0x10, 33};
static const uint8_t ZERO_PREFIX_33[] =             /* 0.0.0.0/33: not a valid all-zero network */
    {0x0a, 0x0e, XX, 0x12, 0x08, 0x0a, 0x04, 0, 0, 0, 0, 0x10, 33};
static const uint8_t TAG_TWO_BYTES[] = ENTRY_AS(0x92);   /* bit 7: a field >= 16 */
static const uint8_t ENTRY_VARINT[] = ENTRY_AS(0x10);    /* bit 1: entry field, varint type */
static const uint8_t ENTRY_VARINT_ONLY[] = {0x0a, 0x06, XX, 0x10, 0x05};  /* entry field 5 */
static const uint8_t ENTRY_FIELD3[] = ENTRY_AS(0x1a);    /* bit 3: reverse_match, bytes type */
static const uint8_t ENTRY_CODE[] = ENTRY_AS(0x0a);      /* bit 4: a second country code */
static const uint8_t ENTRY_FIELD0[] = ENTRY_AS(0x02);    /* field 0 does not exist */
static const uint8_t PREFIX_BYTES[] =               /* prefix field of bytes type */
    {0x0a, 0x0f, XX, 0x12, 0x09, H4, 0x12, 0x01, 32};
static const uint8_t ADDR_VARINT[] =                /* an address field of varint type, then the address */
    {0x0a, 0x10, XX, 0x12, 0x0a, 0x08, 0x01, H4, 0x10, 32};

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

    /* A CIDR list that did not load (anything but a missing file) leaves the
     * permanent hosts of the kept sets unknown: no set of any target refreshes
     * its existing entries, every one says so once. A missing file is an empty
     * list: the index is complete. */
    static const int failures[] = {-EIO, -EACCES, -ENOMEM, -EISDIR};
    for (size_t i = 0; i < sizeof(failures) / sizeof(failures[0]); i++) {
        cidr_result = failures[i];
        start("", 1, plain);
        assert(strcmp(calls, CREATE CREATE_HR CIDR) == 0);
        assert(ipset_perm_incomplete(&mgr, "RU") && ipset_perm_incomplete(&mgr, "RUv6"));
        assert(ipset_perm_incomplete(&mgr, "HydraRoute") && ipset_perm_incomplete(&mgr, "HydraRoutev6"));
        assert(!ipset_perm_incomplete(&mgr, "Foreign"));
        assert(strstr(info_log, "permanent-host index incomplete for HydraRoute: refresh disabled"));
        assert(strstr(info_log, "permanent-host index incomplete for RUv6: refresh disabled"));
    }
    cidr_result = -ENOENT;
    start("", 1, plain);
    assert(!ipset_perm_incomplete(&mgr, "RU") && !ipset_perm_incomplete(&mgr, "HydraRoute"));
    assert(!strstr(info_log, "incomplete"));
    cidr_result = 0;
    start("", 1, plain);
    assert(!ipset_perm_incomplete(&mgr, "HydraRoute") && !strstr(info_log, "incomplete"));

    /* End to end: the kernel kept a permanent host (timeout 0) from the last
     * run, the list cannot be read, a DNS answer names that host. Its entry is
     * left as it is: the exclusive ADD is the only message sent. */
    parsed_cidr_t host;
    memset(&host, 0, sizeof(host));
    host.family = AF_INET;
    host.prefix = 32;
    host.ip[0] = 198; host.ip[1] = 51; host.ip[2] = 100; host.ip[3] = 7;
    int new_count, new_idx[1];
    cidr_result = -EIO;
    start("", 1, plain);
    mgr.fd = 3;
    sent_count = recv_count = 0;
    next_reply = IPSET_ERR_EXIST;
    assert(ipset_add_batch(&mgr, "HydraRoute", &host, 1, 1, &new_count, new_idx) == 0);
    assert(sent_count == 1 && (sent_flags[0] & NLM_F_EXCL));
    /* With the list read (or absent) the same answer would refresh a DNS entry. */
    cidr_result = -ENOENT;
    start("", 1, plain);
    mgr.fd = 3;
    sent_count = recv_count = 0;
    assert(ipset_add_batch(&mgr, "HydraRoute", &host, 1, 1, &new_count, new_idx) == 0);
    assert(sent_count == 2 && !(sent_flags[1] & NLM_F_EXCL));
    mgr.fd = -1;
    ipset_manager_close(&mgr);

    /* The same with the real loader (geodat.c) and a geoip.dat. A good file:
     * the kept hosts are in the index, a DNS entry is still refreshed. */
    f_list("/HydraRoute\ngeoip:xx\n");
    parsed_cidr_t host6, other = host;
    memset(&host6, 0, sizeof(host6));
    host6.family = AF_INET6;
    host6.prefix = 128;
    memcpy(host6.ip, (const uint8_t[]){0x20, 0x01, 0x0d, 0xb8, [15] = 7}, 16);
    other.ip[3] = 8;
    assert(load_then_dns(GOOD, sizeof(GOOD), "HydraRoute", &host) == 1);
    assert(load_rc == 0 && !ipset_perm_incomplete(&mgr, "HydraRoute"));
    assert(load_then_dns(GOOD, sizeof(GOOD), "HydraRoutev6", &host6) == 1);
    assert(load_then_dns(GOOD, sizeof(GOOD), "HydraRoute", &other) == 2);

    /* The kernel kept 198.51.100.7/32 from a good file, and the file is now
     * broken: any structural error in it is a load failure (Ruling 44), every
     * set is flagged, and the DNS answer sends the exclusive ADD only. */
    static const struct { const char *what; const uint8_t *b; size_t n; } broken[] = {
#define CASE(a) {#a, a, sizeof(a)}
        CASE(PREFIX_288), CASE(CODE_LEN_2_64), CASE(CODE_LEN_11_BYTES), CASE(RECORD_LEN_2_64),
        CASE(RECORD_LEN_11_BYTES), CASE(FIELD_LEN_2_64), CASE(PREFIX_2_32), CASE(PREFIX_2_64),
        CASE(V6_PREFIX_129), CASE(V4_PREFIX_33), CASE(ZERO_PREFIX_33), CASE(TAG_TWO_BYTES),
        CASE(ENTRY_VARINT), CASE(ENTRY_VARINT_ONLY), CASE(ENTRY_FIELD3), CASE(ENTRY_CODE),
        CASE(ENTRY_FIELD0), CASE(PREFIX_BYTES), CASE(ADDR_VARINT),
#undef CASE
    };
    int wrong = 0;
    for (size_t i = 0; i < sizeof(broken) / sizeof(broken[0]); i++) {
        int sent = load_then_dns(broken[i].b, broken[i].n, "HydraRoute", &host);
        int flagged = ipset_perm_incomplete(&mgr, "HydraRoute") &&
                      ipset_perm_incomplete(&mgr, "HydraRoutev6") && ipset_perm_incomplete(&mgr, "RU");
        if (sent != 1 || load_rc == 0 || load_rc == -ENOENT || !flagged) {
            printf("%s: load %d, flagged %d, DNS messages %d\n", broken[i].what, load_rc, flagged, sent);
            wrong++;
        }
    }
    fflush(stdout);
    assert(wrong == 0);
    mgr.fd = -1;
    ipset_manager_close(&mgr);
    remove("build/chain.dat");
    remove("build/chain.list");

    remove(CONF_PATH);
    puts("check_ipset_start: OK");
    return 0;
}
