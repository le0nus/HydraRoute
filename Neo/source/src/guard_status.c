#include "../include/guard_status.h"
#include "../include/log.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* One watched policy, by its index among the policies (Ruling 16: no name
 * copies, allocated for exactly the policies there are). */
typedef struct {
    time_t  since[2];       /* wall time each family's blocked run began (POL_RUN) */
    long    episode_start;  /* CLOCK_MONOTONIC s the worst family's blocked run began */
    uint8_t st[2];          /* path_state_t of the last round, per family */
    uint8_t flags;
} policy_status_t;

#define POL_RUN(f)   (1u << (f))    /* family f is blocked, unknown rounds included */
#define POL_EPISODE  (1u << 2)      /* the worst tracked family is blocked, likewise */
#define POL_WARNED   (1u << 3)      /* "blocked" logged for this episode */
#define POL_GONE     (1u << 4)      /* deleted in Keenetic: not in the file */

typedef struct {
    char path[128];
    int  dirty;
    int  write_warned;
    int  raw_known;
    raw_guard_state_t raw;
    char reason[GUARD_REASON_MAX];
    int  rules[2];          /* -1: unknown */
    time_t last_rebuild;
    policy_status_t *pol;   /* pol_count entries; NULL: none, or no memory */
    int  pol_count;
    const char *(*pol_name)(int k);
} guard_status_t;

static guard_status_t g_st;

void guard_status_init(const char *path) {
    free(g_st.pol);
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

/* Worst tracked family: blocked > unknown > ok; n/a is not tracked. */
static path_state_t worst(path_state_t a, path_state_t b) {
    static const int rank[] = {0, 1, 3, 2};     /* NA, OK, BLOCKED, UNKNOWN */
    return rank[a] >= rank[b] ? a : b;
}

int guard_status_policy_count(int count, const char *(*name)(int k)) {
    if (count < 0) count = 0;
    free(g_st.pol);
    g_st.pol = NULL;
    g_st.pol_count = count;
    g_st.pol_name = name;
    g_st.dirty = 1;
    if (count == 0) return 0;
    g_st.pol = calloc((size_t)count, sizeof(*g_st.pol));
    if (!g_st.pol) {
        LOG_WARN("guard: no memory for the path state of %d policies; they show as unknown", count);
        return -1;
    }
    for (int k = 0; k < count; k++) g_st.pol[k].st[0] = g_st.pol[k].st[1] = PATH_UNKNOWN;
    return 0;
}

void guard_status_policy(int k, path_state_t v4, path_state_t v6,
                         long now_mono, time_t now_unix, int delay) {
    if (!g_st.pol || k < 0 || k >= g_st.pol_count) return;
    policy_status_t *ps = &g_st.pol[k];
    const path_state_t st[2] = {v4, v6};
    if (ps->flags & POL_GONE) {
        ps->flags = 0;                          /* back: a fresh start */
        g_st.dirty = 1;
    }
    /* A family's run begins at its first blocked round and ends only at ok
     * or n/a: unknown keeps the time it began (Codex #4). */
    for (int f = 0; f < 2; f++) {
        if (st[f] == PATH_BLOCKED && !(ps->flags & POL_RUN(f))) {
            ps->flags |= POL_RUN(f);
            ps->since[f] = now_unix;
        } else if (st[f] == PATH_OK || st[f] == PATH_NA) {
            ps->flags &= ~POL_RUN(f);
        }
        if (ps->st[f] != st[f]) {
            ps->st[f] = (uint8_t)st[f];
            g_st.dirty = 1;
        }
    }
    path_state_t agg = worst(v4, v6);
    if (agg == PATH_BLOCKED) {
        if (!(ps->flags & POL_EPISODE)) {
            ps->flags = (uint8_t)((ps->flags | POL_EPISODE) & ~POL_WARNED);
            ps->episode_start = now_mono;
        }
        if (!(ps->flags & POL_WARNED) && now_mono - ps->episode_start >= delay) {
            ps->flags |= POL_WARNED;
            LOG_WARN("guard: policy %s blocked", g_st.pol_name(k));
        }
    } else if (agg == PATH_OK || agg == PATH_NA) {
        if ((ps->flags & POL_EPISODE) && (ps->flags & POL_WARNED))
            LOG_WARN("guard: policy %s restored after %ld s", g_st.pol_name(k),
                     now_mono - ps->episode_start);
        ps->flags &= (uint8_t)~(POL_EPISODE | POL_WARNED);
    }
}

void guard_status_policy_gone(int k) {
    if (!g_st.pol || k < 0 || k >= g_st.pol_count) return;
    policy_status_t *ps = &g_st.pol[k];
    if (ps->flags & POL_GONE) return;
    if ((ps->flags & POL_EPISODE) && (ps->flags & POL_WARNED))
        LOG_WARN("guard: policy %s is gone (deleted in Keenetic), no longer watched", g_st.pol_name(k));
    ps->flags = POL_GONE;                       /* its runs and episode end here */
    g_st.dirty = 1;
}

static int put(FILE *out, const char *text, int n, size_t size) {
    return n > 0 && (size_t)n < size && fwrite(text, 1, (size_t)n, out) == (size_t)n;
}

/* policy.<name>.v4=... and .v6=..., one fwrite each. */
static int put_policy(FILE *out, int k) {
    static const char text[][8] = {"n/a", "ok", "blocked", "unknown"};     /* path_state_t */
    const policy_status_t *ps = g_st.pol ? &g_st.pol[k] : NULL;
    const char *name = g_st.pol_name ? g_st.pol_name(k) : NULL;
    char line[160];
    if (!name || (ps && (ps->flags & POL_GONE))) return 1;
    for (int f = 0; f < 2; f++) {
        int st = ps ? ps->st[f] : PATH_UNKNOWN;
        int n = st == PATH_BLOCKED
              ? snprintf(line, sizeof(line), "policy.%s.v%d=blocked:%ld\n", name, f ? 6 : 4, (long)ps->since[f])
              : snprintf(line, sizeof(line), "policy.%s.v%d=%s\n", name, f ? 6 : 4, text[st]);
        if (!put(out, line, n, sizeof(line))) return 0;
    }
    return 1;
}

int guard_status_flush(void) {
    if (!g_st.path[0] || !g_st.dirty || !g_st.raw_known) return 0;
    char text[256], counts[2][12], tmp[sizeof(g_st.path) + 8];
    count_text(counts[0], sizeof(counts[0]), g_st.rules[0]);
    count_text(counts[1], sizeof(counts[1]), g_st.rules[1]);
    snprintf(tmp, sizeof(tmp), "%s.tmp", g_st.path);

    /* Readers see the old file or the new one, never a part of it. */
    FILE *out = fopen(tmp, "w");
    int ok = out != NULL;
    if (ok) {
        int n = snprintf(text, sizeof(text), "raw_guard=%s%s\nraw_rules_v4=%s\nraw_rules_v6=%s\n",
                         g_st.raw == RAW_GUARD_DEGRADED ? "degraded:" :
                         g_st.raw == RAW_GUARD_ON ? "on" : "off",
                         g_st.raw == RAW_GUARD_DEGRADED ? g_st.reason : "",
                         counts[0], counts[1]);
        ok = put(out, text, n, sizeof(text));
        for (int k = 0; ok && k < g_st.pol_count; k++) ok = put_policy(out, k);
        if (ok) {
            n = snprintf(text, sizeof(text), "last_rebuild=%ld\n", (long)g_st.last_rebuild);
            ok = put(out, text, n, sizeof(text));
        }
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
