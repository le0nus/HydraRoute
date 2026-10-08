#include "../include/geodat.h"
#include "../include/ipset_nl.h"
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* The result of loading a CIDR list: a missing file is -ENOENT (an empty
 * list), a file that cannot be read to the end is -errno, a good file is 0.
 * ipset_start_targets() relies on the difference (permanent-host index). */

void __wrap_log_write(const char *fmt, ...) { (void)fmt; }
/* malloc/realloc that fail on demand: the next fail_malloc_big calls of 64 KB
 * or more (the GeoIP entry buffer), the next fail_realloc calls of any size. */
static int fail_malloc_big, fail_realloc;
void *__real_malloc(size_t n);
void *__real_realloc(void *p, size_t n);
void *__wrap_malloc(size_t n) {
    if (n >= 65536 && fail_malloc_big > 0) { fail_malloc_big--; return NULL; }
    return __real_malloc(n);
}
void *__wrap_realloc(void *p, size_t n) {
    if (fail_realloc > 0) { fail_realloc--; return NULL; }
    return __real_realloc(p, n);
}

/* A geoip.dat with one country: n host entries 198.51.x.y/32 (RFC 5737 is
 * only 198.51.100.0/24, so n <= 254 uses that; more spill into 198.51.101+).
 * cut bytes are dropped from the end. */
static void write_geoip(const char *path, const char *code, int n, size_t cut) {
    size_t cap = 16 + (size_t)n * 12;
    uint8_t *b = __real_malloc(cap), *body = __real_malloc(cap);
    size_t bl = 0, l = 0;
    body[bl++] = 0x0A; body[bl++] = (uint8_t)strlen(code);
    memcpy(body + bl, code, strlen(code)); bl += strlen(code);
    for (int i = 0; i < n; i++) {
        body[bl++] = 0x12; body[bl++] = 8;      /* CIDR: ip (4) + prefix */
        body[bl++] = 0x0A; body[bl++] = 4;
        body[bl++] = 198; body[bl++] = 51; body[bl++] = (uint8_t)(100 + i / 250);
        body[bl++] = (uint8_t)(1 + i % 250);
        body[bl++] = 0x10; body[bl++] = 32;
    }
    b[l++] = 0x0A;
    size_t v = bl;
    while (v >= 0x80) { b[l++] = (uint8_t)(v | 0x80); v >>= 7; }
    b[l++] = (uint8_t)v;
    memcpy(b + l, body, bl); l += bl;
    FILE *f = fopen(path, "wb");
    assert(f);
    fwrite(b, 1, l - cut, f);
    fclose(f);
    free(b); free(body);
}

int __wrap_ipset_refresh_set_list(ipset_manager_t *mgr) { (void)mgr; return 0; }
int __wrap_ipset_add_batch(ipset_manager_t *mgr, const char *set_name,
                           const parsed_cidr_t *entries, int count,
                           int with_timeout, int *new_count, int *new_indices) {
    (void)mgr; (void)set_name; (void)entries; (void)with_timeout; (void)new_indices;
    *new_count = 0;
    return count == 2 ? -1 : 0;   /* a two-entry batch is the one the "kernel" refuses */
}

int main(void) {
    ipset_manager_t mgr;
    memset(&mgr, 0, sizeof(mgr));
    mgr.set_count = 1;
    strcpy(mgr.set_names[0], "HydraRoute");

    assert(add_cidr_to_ipsets(&mgr, "build/no-such-cidr.list", NULL, 0, 1000) == -ENOENT);

    /* A directory opens for reading and fails at the first read: the whole
     * file is unread. */
    mkdir("build/cidr_dir", 0755);
    int rc = add_cidr_to_ipsets(&mgr, "build/cidr_dir", NULL, 0, 1000);
    assert(rc == -EISDIR);
    rmdir("build/cidr_dir");

    FILE *f = fopen("build/cidr.list", "w");
    assert(f);
    fputs("/HydraRoute\n198.51.100.7/32\n", f);
    fclose(f);
    assert(add_cidr_to_ipsets(&mgr, "build/cidr.list", NULL, 0, 1000) == 0);

    /* A batch the kernel did not take is a failure too. */
    f = fopen("build/cidr.list", "w");
    fputs("/HydraRoute\n198.51.100.7/32\n198.51.100.8/32\n", f);
    fclose(f);
    assert(add_cidr_to_ipsets(&mgr, "build/cidr.list", NULL, 0, 1000) == -EIO);
    remove("build/cidr.list");

    /* geoip: lines make the GeoIP files part of the list. A file that is
     * missing, cut short or does not fit in memory is a load failure, never an
     * empty list (the ENOENT exemption is for the list itself): the kept
     * sets may hold permanent hosts of that country. */
    f = fopen("build/cidr.list", "w");
    fputs("/HydraRoute\ngeoip:xx\n", f);
    fclose(f);
    static char geo[1][512];
    strcpy(geo[0], "build/geo.dat");
    write_geoip("build/geo.dat", "XX", 1, 0);
    assert(add_cidr_to_ipsets(&mgr, "build/cidr.list", (const char (*)[512])geo, 1, 100000) == 0);
    write_geoip("build/geo.dat", "XX", 1, 0);
    assert(add_cidr_to_ipsets(&mgr, "build/cidr.list", (const char (*)[512])geo, 1, 100000) == 0);

    remove("build/geo.dat");
    rc = add_cidr_to_ipsets(&mgr, "build/cidr.list", (const char (*)[512])geo, 1, 100000);
    assert(rc != 0 && rc != -ENOENT);

    write_geoip("build/geo.dat", "XX", 1, 5);            /* truncated */
    rc = add_cidr_to_ipsets(&mgr, "build/cidr.list", (const char (*)[512])geo, 1, 100000);
    assert(rc != 0 && rc != -ENOENT);

    write_geoip("build/geo.dat", "XX", 1, 0);
    fail_malloc_big = 1;                                   /* entry buffer */
    rc = add_cidr_to_ipsets(&mgr, "build/cidr.list", (const char (*)[512])geo, 1, 100000);
    assert(rc != 0 && rc != -ENOENT && fail_malloc_big == 0);

    write_geoip("build/geo.dat", "XX", 4100, 0);           /* buffer must grow */
    fail_realloc = 1;
    rc = add_cidr_to_ipsets(&mgr, "build/cidr.list", (const char (*)[512])geo, 1, 100000);
    assert(rc != 0 && rc != -ENOENT && fail_realloc == 0);

    remove("build/geo.dat");
    remove("build/cidr.list");

    puts("check_cidr_load: OK");
    return 0;
}
