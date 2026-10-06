#include "../include/routing.h"
#include "../include/watchlist.h"
#include "../include/util.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static void present(direct_route_manager_t *drm, const char *name) {
    snprintf(drm->interfaces[drm->interface_count++].name, MAX_INTERFACE_NAME, "%s", name);
}

int main(void) {
    static config_t cfg;
    snprintf(cfg.force_interfaces[0], 64, "awgmX");
    snprintf(cfg.force_interfaces[1], 64, "t2s3");
    cfg.force_interface_count = 2;

    static direct_route_manager_t drm;
    drm_init(&drm, &cfg);
    present(&drm, "awgm0");
    present(&drm, "eth0");

    assert(drm_classify_target(&drm, "awgm0") == TARGET_INTERFACE);
    assert(drm_classify_target(&drm, "eth0") == TARGET_INTERFACE);
    assert(drm_classify_target(&drm, "awgm1") == TARGET_ABSENT_INTERFACE);
    assert(drm_classify_target(&drm, "awgm12") == TARGET_ABSENT_INTERFACE);
    assert(drm_classify_target(&drm, "awgm") == TARGET_POLICY);
    assert(drm_classify_target(&drm, "awgm1a") == TARGET_POLICY);
    assert(drm_classify_target(&drm, "awgmX") == TARGET_POLICY);
    assert(drm_classify_target(&drm, "t2s3") == TARGET_ABSENT_INTERFACE);
    assert(drm_classify_target(&drm, "t2s4") == TARGET_POLICY);
    assert(drm_classify_target(&drm, "HydraRoute") == TARGET_POLICY);

    char path[] = "/tmp/check_routing_XXXXXX";
    int fd = mkstemp(path);
    assert(fd >= 0);
    static const char wl[] = "a.com/awgm1\nb.com,c.com/awgm0\nd.com/RU\n";
    assert(write(fd, wl, sizeof(wl) - 1) == (ssize_t)(sizeof(wl) - 1));
    close(fd);

    domain_hashtable_t *ht = ht_create();
    char policies[MAX_POLICY_ORDER][64], ifaces[MAX_INTERFACES][64];
    int pc, ic;
    assert(parse_watchlist_classified(path, &drm, ht, policies, &pc, ifaces, &ic) == 0);
    unlink(path);

    assert(pc == 1 && strcmp(policies[0], "RU") == 0);
    assert(ic == 1 && strcmp(ifaces[0], "awgm0") == 0);
    assert(!watchlist_match(ht, "a.com", 5, NULL));
    assert(strcmp(watchlist_match(ht, "www.c.com", 9, NULL)->name, "awgm0") == 0);
    assert(strcmp(watchlist_match(ht, "d.com", 5, NULL)->name, "RU") == 0);
    ht_destroy(ht);

    printf("check_routing: OK\n");
    return 0;
}
