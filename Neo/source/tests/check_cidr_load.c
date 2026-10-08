#include "../include/geodat.h"
#include "../include/ipset_nl.h"
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* The result of loading a CIDR list: a missing file is -ENOENT (an empty
 * list), a file that cannot be read to the end is -errno, a good file is 0.
 * ipset_start_targets() relies on the difference (permanent-host index). */

void __wrap_log_write(const char *fmt, ...) { (void)fmt; }
int __wrap_ipset_refresh_set_list(ipset_manager_t *mgr) { (void)mgr; return 0; }
int __wrap_ipset_add_batch(ipset_manager_t *mgr, const char *set_name,
                           const parsed_cidr_t *entries, int count,
                           int with_timeout, int *new_count, int *new_indices) {
    (void)mgr; (void)set_name; (void)entries; (void)with_timeout; (void)new_indices;
    *new_count = 0;
    return count == 1 ? 0 : -1;
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

    puts("check_cidr_load: OK");
    return 0;
}
