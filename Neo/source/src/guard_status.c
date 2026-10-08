#include "../include/guard_status.h"
#include "../include/log.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>

typedef struct {
    char path[128];
    int  dirty;
    int  write_warned;
    int  raw_known;
    raw_guard_state_t raw;
    char reason[GUARD_REASON_MAX];
    int  rules[2];          /* -1: unknown */
    time_t last_rebuild;
} guard_status_t;

static guard_status_t g_st;

void guard_status_init(const char *path) {
    memset(&g_st, 0, sizeof(g_st));
    snprintf(g_st.path, sizeof(g_st.path), "%s", path);
    g_st.dirty = 1;
}

void guard_status_set_raw(raw_guard_state_t state, const char *reason,
                          int rules_v4, int rules_v6) {
    if (!reason) reason = "";
    if (!g_st.raw_known || g_st.raw != state || strcmp(g_st.reason, reason) != 0) {
        if (state == RAW_GUARD_DEGRADED)
            LOG_WARN("raw guard degraded: %s", reason);
        else if (state == RAW_GUARD_ON && g_st.raw_known && g_st.raw == RAW_GUARD_DEGRADED)
            LOG_WARN("raw guard on again (was degraded: %s)", g_st.reason);
        else if (state == RAW_GUARD_ON)
            LOG_INFO("raw guard on");
        else
            LOG_INFO("raw guard off");
        g_st.raw_known = 1;
        g_st.raw = state;
        snprintf(g_st.reason, sizeof(g_st.reason), "%s", reason);
        g_st.dirty = 1;
    }
    if (g_st.rules[0] != rules_v4 || g_st.rules[1] != rules_v6) {
        g_st.rules[0] = rules_v4;
        g_st.rules[1] = rules_v6;
        g_st.dirty = 1;
    }
}

void guard_status_set_rebuild(time_t when) {
    if (g_st.last_rebuild != when) {
        g_st.last_rebuild = when;
        g_st.dirty = 1;
    }
}

static void count_text(char *out, size_t size, int n) {
    if (n < 0) snprintf(out, size, "unknown");
    else snprintf(out, size, "%d", n);
}

int guard_status_flush(void) {
    if (!g_st.path[0] || !g_st.dirty || !g_st.raw_known) return 0;
    char text[256], counts[2][12], tmp[sizeof(g_st.path) + 8];
    count_text(counts[0], sizeof(counts[0]), g_st.rules[0]);
    count_text(counts[1], sizeof(counts[1]), g_st.rules[1]);
    int n = snprintf(text, sizeof(text),
                     "raw_guard=%s%s\nraw_rules_v4=%s\nraw_rules_v6=%s\nlast_rebuild=%ld\n",
                     g_st.raw == RAW_GUARD_DEGRADED ? "degraded:" :
                     g_st.raw == RAW_GUARD_ON ? "on" : "off",
                     g_st.raw == RAW_GUARD_DEGRADED ? g_st.reason : "",
                     counts[0], counts[1], (long)g_st.last_rebuild);
    snprintf(tmp, sizeof(tmp), "%s.tmp", g_st.path);

    /* Readers see the old file or the new one, never a part of it. */
    FILE *out = fopen(tmp, "w");
    int ok = out != NULL && n > 0 && (size_t)n < sizeof(text);
    if (out) {
        if (ok && fwrite(text, 1, (size_t)n, out) != (size_t)n) ok = 0;
        if (fclose(out) != 0) ok = 0;
    }
    if (!ok || rename(tmp, g_st.path) != 0) {
        if (out) unlink(tmp);
        if (!g_st.write_warned) LOG_WARN("cannot write %s", g_st.path);
        g_st.write_warned = 1;
        return -1;
    }
    g_st.write_warned = 0;
    g_st.dirty = 0;
    return 0;
}
