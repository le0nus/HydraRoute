#include "../include/iptables.h"
#include "../include/guard.h"
#include "../include/guard_status.h"
#include "../include/l7_firewall.h"
#include "../include/log.h"
#include "../include/util.h"
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* main.c builds the target list once, so target i keeps its index, and its
 * state here, for the life of the process. */
typedef struct {
    uint32_t mark;          /* mark of the target's rules, 0 while unknown */
    int  gone;              /* RCI: the policy has no mark, its rules go */
    int  warned, warned_r;
} target_state_t;

/* An hrneo line of the family's dump. */
typedef struct {
    uint32_t off;           /* where the line starts in fam->dump */
    uint16_t len;
    int16_t  owner;         /* target index */
} owned_line_t;

_Static_assert(IPT_DUMP_SIZE <= 65536, "a dump line must fit owned_line_t.len");

/* The hrneo lines of one dump, in dump order. It lives on the caller's stack
 * for one call and the two families use it in turn: no static memory. */
typedef struct {
    owned_line_t line[IPT_MAX_OWNED];
    int count;
} owned_index_t;

/* The sets of the targets in PolicyOrder. The ipset_pair_t of target i is at
 * base + i * stride, so one scan reads unified_target_t (commit) and
 * ipset_pair_t (stop) without copying either. */
typedef struct {
    const char *base;
    size_t stride;
    int count;
} set_list_t;

typedef struct {
    const char *ipt_cmd;
    const char *restore_cmd;
    char dump[IPT_DUMP_SIZE];
    char batch[IPT_BATCH_SIZE];
    size_t len;             /* batch length; counts on past the buffer, see batch_append */
    int  rule_count;
    int  warned_audit;
    int  dump_ok;           /* dump holds the whole mangle dump of the last dump_chains() */
    int  raw_kmod;          /* raw table module: 0 not tried, 1 loaded or no .ko, -1 load failed */
    int  raw_seen;          /* a raw dump has worked in this process */
    int  warned_raw_dump, warned_raw;
} connmark_family_t;

typedef struct {
    int mangle_ok;          /* mangle PREROUTING holds exactly the expected rules */
    int replaced;           /* this commit replaced hrneo rules in mangle or raw */
    const char *reason;     /* why the raw guard does not fully work here, NULL if it does;
                             * after mangle: why mangle is not confirmed */
    int raw_rules;          /* HRNEO_GUARD rules in the last raw dump, -1 unknown */
} family_result_t;

#define BATCH_OVERFLOW (-2)

static target_state_t g_states[MAX_TARGETS];
static connmark_family_t g_fams[2];         /* no initializer: stays in .bss */

static connmark_family_t *family(int fi) {
    connmark_family_t *fam = &g_fams[fi];
    fam->ipt_cmd = fi ? "ip6tables" : "iptables";
    fam->restore_cmd = fi ? "ip6tables-restore" : "iptables-restore";
    return fam;
}

void iptables_delete_rules_matching(const char *ipt_cmd, const char *chain,
                                    const char *needle1, const char *needle2) {
    char *argv[] = {(char *)ipt_cmd, "-w", "-t", "mangle", "-S", (char *)chain, NULL};
    char output[IPT_DUMP_SIZE];
    if (run_command_output(ipt_cmd, argv, output, sizeof(output)) != 0) {
        LOG_WARN("%s -t mangle -S %s failed or output truncated", ipt_cmd, chain);
        return;
    }

    char *line = output;
    while (line && *line) {
        char *nl = strchr(line, '\n');
        if (nl) *nl = '\0';

        if (strncmp(line, "-A ", 3) == 0 && strstr(line, needle1) &&
            (!needle2 || strstr(line, needle2))) {
            const char *src = line + 3;
            size_t chain_len = strlen(chain);
            if (strncmp(src, chain, chain_len) == 0 && src[chain_len] == ' ')
                src += chain_len + 1;

            char *del_argv[IPT_MAX_RULE_ARGS];
            del_argv[0] = (char *)ipt_cmd;
            del_argv[1] = "-w";
            del_argv[2] = "-t";
            del_argv[3] = "mangle";
            del_argv[4] = "-D";
            del_argv[5] = (char *)chain;

            char args_buf[512];
            if (strlen(src) >= sizeof(args_buf)) {
                LOG_ERROR("Rule too long to delete in %s %s: %s", ipt_cmd, chain, src);
                line = nl ? nl + 1 : NULL;
                continue;
            }
            strcpy(args_buf, src);
            int argc = 6;
            char *saveptr_rule;
            char *tok = strtok_r(args_buf, " \t", &saveptr_rule);
            while (tok && argc < IPT_MAX_RULE_ARGS - 1) {
                del_argv[argc++] = tok;
                tok = strtok_r(NULL, " \t", &saveptr_rule);
            }
            if (tok) {
                LOG_ERROR("Rule has too many arguments to delete in %s %s", ipt_cmd, chain);
                line = nl ? nl + 1 : NULL;
                continue;
            }
            del_argv[argc] = NULL;

            char discard[256];
            if (run_command_output(ipt_cmd, del_argv, discard, sizeof(discard)) != 0)
                LOG_WARN("%s -t mangle -D %s failed: %s", ipt_cmd, chain, discard);
        }

        line = nl ? nl + 1 : NULL;
    }
}

static const char *const DUMP_CHAINS[] = {"PREROUTING", "FORWARD", "OUTPUT"};

static int dump_chains(connmark_family_t *fam, int chain_count) {
    size_t off = 0;
    fam->dump_ok = 0;
    for (int c = 0; c < chain_count; c++) {
        char *argv[] = {(char *)fam->ipt_cmd, "-w", "-t", "mangle", "-S",
                        (char *)DUMP_CHAINS[c], NULL};
        if (run_command_output(fam->ipt_cmd, argv, fam->dump + off,
                               sizeof(fam->dump) - off) != 0) {
            LOG_WARN("%s -t mangle -S %s failed or output truncated",
                     fam->ipt_cmd, DUMP_CHAINS[c]);
            return -1;
        }
        off += strlen(fam->dump + off);
    }
    fam->dump_ok = 1;
    return 0;
}

/* Appends to the batch. Past its end nothing more is written, but len keeps
 * counting, so an overflow can say how many bytes the batch needed. */
static void batch_append(connmark_family_t *fam, const char *fmt, ...) {
    size_t room = fam->len < sizeof(fam->batch) ? sizeof(fam->batch) - fam->len : 0;
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(room ? fam->batch + fam->len : NULL, room, fmt, ap);
    va_end(ap);
    fam->len += n < 0 ? sizeof(fam->batch) : (size_t)n;
}

static inline const char *family_set(const unified_target_t *t, int fi) {
    return fi ? t->pair.ipv6 : t->pair.ipv4;
}

static inline const char *set_name(const set_list_t *sets, int i, int fi) {
    const ipset_pair_t *p = (const ipset_pair_t *)(const void *)(sets->base + (size_t)i * sets->stride);
    return fi ? p->ipv6 : p->ipv4;
}

static inline const char *own_text(const connmark_family_t *fam, const owned_line_t *ol) {
    return fam->dump + ol->off;
}

/* The target whose set the rule matches as destination
 * ("--match-set <set> dst "), or -1. */
static int line_owner(const char *line, size_t len, const set_list_t *sets, int fi) {
    static const char tok[] = "--match-set ";
    const char *end = line + len;
    const char *p = line;
    while ((p = line_find(p, (size_t)(end - p), tok))) {
        const char *name = p + sizeof(tok) - 1;
        const char *sp = memchr(name, ' ', (size_t)(end - name));
        p = name;
        if (!sp || (size_t)(end - sp) < 5 || memcmp(sp, " dst ", 5) != 0) continue;
        for (int i = 0; i < sets->count; i++) {
            const char *s = set_name(sets, i, fi);
            if (strlen(s) == (size_t)(sp - name) && memcmp(s, name, (size_t)(sp - name)) == 0)
                return i;
        }
    }
    return -1;
}

/* Every "-A PREROUTING" line with one of our sets as destination is hrneo's:
 * NDMS and other software do not use these sets. */
static int collect_owned(const connmark_family_t *fam, const set_list_t *sets, int fi,
                         owned_index_t *own) {
    own->count = 0;
    for (const char *line = fam->dump; *line; ) {
        const char *nl = strchr(line, '\n');
        size_t len = nl ? (size_t)(nl - line) : strlen(line);
        int owner = (len > 14 && memcmp(line, "-A PREROUTING ", 14) == 0)
                    ? line_owner(line, len, sets, fi) : -1;
        if (owner >= 0) {
            if (own->count == IPT_MAX_OWNED) {
                LOG_ERROR("%s: more than %d hrneo rules in mangle PREROUTING",
                          fam->ipt_cmd, IPT_MAX_OWNED);
                return -1;
            }
            own->line[own->count].off = (uint32_t)(line - fam->dump);
            own->line[own->count].len = (uint16_t)len;
            own->line[own->count].owner = (int16_t)owner;
            own->count++;
        }
        if (!nl) break;
        line = nl + 1;
    }
    return 0;
}

/* The hrneo lines of the dump must be the expected rules of all targets in
 * PolicyOrder, nothing more, in this order. A target whose mark is unknown
 * (RCI down since start) keeps the lines it has. Returns 1 if equal; else 0,
 * with the first differing expected line in want (empty if the dump only has
 * extra lines) and its position among the hrneo lines in *pos_out. */
static int family_exact(const connmark_family_t *fam, const owned_index_t *own,
                        const unified_target_t *targets, int count, int fi,
                        const config_t *cfg, char *want, size_t want_size, int *pos_out) {
    int pos = 0;
    if (want_size) want[0] = '\0';
    for (int i = 0; i < count; i++) {
        const target_state_t *ts = &g_states[i];
        if (ts->gone) continue;
        if (!ts->mark) {
            while (pos < own->count && own->line[pos].owner == i) pos++;
            continue;
        }
        for (int k = 0; k < GUARD_MANGLE_RULES; k++) {
            char line[GUARD_LINE_MAX];
            int n = guard_mangle_rule(line, sizeof(line), k, family_set(&targets[i], fi),
                                      ts->mark, targets[i].is_interface, cfg->global_routing);
            if (n == 0) continue;
            if (n < 0 || pos == own->count || own->line[pos].len != (size_t)n ||
                memcmp(own_text(fam, &own->line[pos]), line, (size_t)n) != 0) {
                if (want_size && n > 0) snprintf(want, want_size, "%s", line);
                if (pos_out) *pos_out = pos;
                return 0;
            }
            pos++;
        }
    }
    if (pos_out) *pos_out = pos;
    return pos == own->count;
}

static void batch_delete_owned(connmark_family_t *fam, const owned_index_t *own) {
    for (int p = 0; p < own->count; p++)
        batch_append(fam, "-D%.*s\n", (int)own->line[p].len - 2,
                     own_text(fam, &own->line[p]) + 2);
}

/* Deletes every hrneo line and appends the expected rules in PolicyOrder, in
 * the one batch that commit_batch() swaps in, so no packet sees a partial set. */
static int batch_replace(connmark_family_t *fam, const owned_index_t *own,
                         const unified_target_t *targets, int count, int fi,
                         const config_t *cfg) {
    batch_delete_owned(fam, own);
    for (int i = 0; i < count; i++) {
        const target_state_t *ts = &g_states[i];
        const char *set = family_set(&targets[i], fi);
        if (ts->gone || !ts->mark) {
            for (int p = 0; p < own->count; p++) {
                const owned_line_t *ol = &own->line[p];
                if (ol->owner != i) continue;
                if (ts->gone) {
                    LOG_INFO("Policy %s has no mark, removing its rules for %s",
                             targets[i].pair.ipv4, set);
                    break;
                }
                batch_append(fam, "%.*s\n", (int)ol->len, own_text(fam, ol));
            }
            continue;
        }
        for (int k = 0; k < GUARD_MANGLE_RULES; k++) {
            char line[GUARD_LINE_MAX];
            int n = guard_mangle_rule(line, sizeof(line), k, set, ts->mark,
                                      targets[i].is_interface, cfg->global_routing);
            if (n < 0) {
                LOG_ERROR("Rule for %s does not fit %d bytes", set, GUARD_LINE_MAX);
                return -1;
            }
            if (n > 0) batch_append(fam, "%s\n", line);
        }
        LOG_INFO("Adding rules for %s (mark: 0x%x) via %s", set, ts->mark, fam->restore_cmd);
    }
    fam->rule_count++;
    return 0;
}

static int resolve_mark(const unified_target_t *t, target_state_t *ts) {
    if (t->is_interface) {
        ts->mark = (uint32_t)t->fwmark;
        return 0;
    }
    char buf[16];
    int r = rci_get_policy_mark(t->pair.ipv4, buf, sizeof(buf));
    if (r == RCI_MARK_OK) {
        char *end;
        unsigned long long v = strtoull(buf, &end, 16);
        if (end != buf && *end == '\0' && v != 0 && v <= 0xffffffffULL) {
            if (ts->mark && ts->mark != (uint32_t)v)
                LOG_WARN("Policy %s mark changed: 0x%x -> 0x%x, replacing its rules",
                         t->pair.ipv4, ts->mark, (uint32_t)v);
            ts->mark = (uint32_t)v;
            ts->gone = 0;
            ts->warned = 0;
            return 0;
        }
        r = RCI_MARK_ABSENT;        /* not a hex mark: like a policy without one */
    }
    if (r != RCI_MARK_TRANSPORT && r != RCI_MARK_DENIED) {
        ts->gone = 1;
        ts->mark = 0;
    }
    /* A failed commit is retried until this clears; WARN once per cause. */
    if (ts->warned && ts->warned_r == r) {
        LOG_DEBUG("Policy %s mark still unavailable (RCI result %d)", t->pair.ipv4, r);
        return -1;
    }
    ts->warned = 1;
    ts->warned_r = r;
    if (r == RCI_MARK_TRANSPORT) {
        LOG_WARN("RCI unreachable while reading policy %s", t->pair.ipv4);
    } else if (r == RCI_MARK_DENIED) {
        LOG_WARN("RCI denied reading policy %s: access token required or rejected",
                 t->pair.ipv4);
    } else {
        LOG_WARN("Policy %s has no mark ID yet", t->pair.ipv4);
    }
    return -1;
}

/* Sends the batch as one iptables-restore --noflush, which swaps the table in
 * one commit. A batch that does not fit is not sent at all: splitting it
 * would show packets a partial set. */
static int commit_batch(connmark_family_t *fam) {
    batch_append(fam, "COMMIT\n");
    if (fam->len >= sizeof(fam->batch)) {
        LOG_ERROR("mangle batch overflow (%zu bytes needed, %zu available)",
                  fam->len + 1, sizeof(fam->batch));
        return BATCH_OVERFLOW;
    }
    char *argv[] = {(char *)fam->restore_cmd, "--noflush", NULL};
    char err[160];
    int ret = run_command_stdin(fam->restore_cmd, argv, fam->batch, fam->len, err, sizeof(err));
    if (ret != 0) {
        LOG_WARN("%s failed (exit %d)%s%s", fam->restore_cmd, ret, err[0] ? ": " : "", err);
        return -1;
    }
    LOG_DEBUG("Committed %d rule groups via %s", fam->rule_count, fam->restore_cmd);
    return 0;
}

/* What was written must read back the same; a different spelling in
 * iptables -S would replace the rules on every commit. A mismatch fails the
 * commit, which is retried, with one WARN until the rules read back right. */
static int confirm_mangle(connmark_family_t *fam, owned_index_t *own,
                          const unified_target_t *targets, const set_list_t *sets,
                          int fi, const config_t *cfg) {
    char want[GUARD_LINE_MAX];
    int pos = 0;
    if (dump_chains(fam, 1) != 0 || collect_owned(fam, sets, fi, own) != 0) return -1;
    if (family_exact(fam, own, targets, sets->count, fi, cfg, want, sizeof(want), &pos)) {
        fam->warned_audit = 0;
        return 0;
    }
    if (!fam->warned_audit) {
        fam->warned_audit = 1;
        if (pos >= own->count)
            LOG_WARN("%s: mangle PREROUTING differs after replace: expected '%s', found nothing",
                     fam->ipt_cmd, want);
        else if (!want[0])
            LOG_WARN("%s: mangle PREROUTING differs after replace: expected nothing, found '%.*s'",
                     fam->ipt_cmd, (int)own->line[pos].len, own_text(fam, &own->line[pos]));
        else
            LOG_WARN("%s: mangle PREROUTING differs after replace: expected '%s', found '%.*s'",
                     fam->ipt_cmd, want, (int)own->line[pos].len, own_text(fam, &own->line[pos]));
    }
    return -1;
}

static int emit_l7(connmark_family_t *fam, const config_t *cfg, const char *l7_wan) {
    size_t room = fam->len < sizeof(fam->batch) ? sizeof(fam->batch) - fam->len : 0;
    int n = l7_firewall_emit_rules(cfg, l7_wan, fam->dump, fam->batch + fam->len, room);
    if (n < 0) {
        LOG_ERROR("%s batch overflow while emitting L7 rules", fam->restore_cmd);
        return -1;
    }
    if (n > 0) {
        fam->len += (size_t)n;
        fam->rule_count++;
        LOG_INFO("Adding L7 NFLOG rules via %s (wan=%s)", fam->restore_cmd, l7_wan);
    }
    return 0;
}

/* One family: dump, compare, and when the hrneo lines differ replace them all
 * in one iptables-restore (with the L7 rules, when due) and read them back.
 * Each step names its cause in r->reason before it can fail; the raw step
 * and the status file show it. */
static int commit_mangle(connmark_family_t *fam, owned_index_t *own,
                         const unified_target_t *targets, const set_list_t *sets, int fi,
                         const config_t *cfg, const char *l7_wan, family_result_t *r) {
    int l7 = l7_wan && l7_wan[0];
    r->reason = "dump";     /* no dump, or more hrneo lines than the index holds */
    if (dump_chains(fam, l7 ? 3 : 1) != 0 || collect_owned(fam, sets, fi, own) != 0)
        return -1;
    int exact = family_exact(fam, own, targets, sets->count, fi, cfg, NULL, 0, NULL);
    if (exact) fam->warned_audit = 0;
    fam->len = 0;
    fam->rule_count = 0;
    batch_append(fam, "*mangle\n");
    r->reason = "batch-overflow";
    if (l7 && emit_l7(fam, cfg, l7_wan) != 0) return -1;
    if (!exact) {
        LOG_INFO("%s: hrneo rules in mangle PREROUTING differ, replacing them in PolicyOrder",
                 fam->ipt_cmd);
        if (batch_replace(fam, own, targets, sets->count, fi, cfg) != 0) return -1;
    }
    if (fam->rule_count > 0) {
        int ret = commit_batch(fam);
        if (ret != 0) {
            if (ret != BATCH_OVERFLOW) r->reason = "restore";
            return -1;
        }
    }
    if (!exact) {
        r->reason = "audit";
        if (confirm_mangle(fam, own, targets, sets, fi, cfg) != 0) return -1;
        r->replaced = 1;
    }
    r->reason = NULL;
    r->mangle_ok = 1;
    return 0;
}

/* An unconditional CONNMARK --restore-mark in mangle PREROUTING (hrneo before
 * 1le2, the rule of a target no longer configured, a foreign rule) writes
 * connmark 0 over the raw mark of every new connection (§3.2). */
static int unsafe_restore(const char *dump) {
    for (const char *line = dump; *line; ) {
        const char *nl = strchr(line, '\n');
        size_t len = nl ? (size_t)(nl - line) : strlen(line);
        if (len > 14 && memcmp(line, "-A PREROUTING ", 14) == 0 &&
            line_find(line, len, "-j CONNMARK --restore-mark") &&
            !line_find(line, len, "-m connmark ! --mark 0x0 "))
            return 1;
        if (!nl) break;
        line = nl + 1;
    }
    return 0;
}

/* The raw table of a family as its last dump shows it, read in one pass with
 * no index: the chain, the jumps into it, and its rules compared in order
 * with the expected ones. */
typedef struct {
    int chain;              /* "-N HRNEO_GUARD" */
    int jumps;              /* exact GUARD_JUMP lines in PREROUTING */
    int jump_first;         /* the first PREROUTING rule is such a jump */
    int rules;              /* "-A HRNEO_GUARD" lines */
    int rules_exact;        /* they are the expected rules, in order */
    char want[GUARD_LINE_MAX];  /* first expected rule that differs, "" if none */
    const char *found;      /* first chain rule that differs, NULL if none */
    size_t found_len;
} raw_view_t;

/* The next target at or below index i that has a rule in HRNEO_GUARD, or -1.
 * The chain holds one rule per policy target in reverse PolicyOrder: the last
 * match sets the mark, so the first target in PolicyOrder wins. Interface
 * targets are not marked early (their tables go away on stop); a policy
 * without a mark ID has no rule. */
static int raw_next(const unified_target_t *targets, int i) {
    for (; i >= 0; i--)
        if (!targets[i].is_interface && !g_states[i].gone) return i;
    return -1;
}

static int raw_rule(char *out, size_t size, const unified_target_t *targets, int i, int fi) {
    return guard_raw_rule(out, size, family_set(&targets[i], fi), g_states[i].mark);
}

static void scan_raw(const connmark_family_t *fam, const unified_target_t *targets, int count,
                     int fi, raw_view_t *v) {
    static const char chain_line[] = "-N " GUARD_CHAIN;
    static const char rule_prefix[] = "-A " GUARD_CHAIN " ";
    int next = raw_next(targets, count - 1), pre_seen = 0;
    memset(v, 0, sizeof(*v));
    v->rules_exact = 1;
    for (const char *line = fam->dump; *line; ) {
        const char *nl = strchr(line, '\n');
        size_t len = nl ? (size_t)(nl - line) : strlen(line);
        if (len == sizeof(chain_line) - 1 && memcmp(line, chain_line, len) == 0) {
            v->chain = 1;
        } else if (len > 14 && memcmp(line, "-A PREROUTING ", 14) == 0) {
            if (len == sizeof(GUARD_JUMP) - 1 && memcmp(line, GUARD_JUMP, len) == 0) {
                if (!pre_seen) v->jump_first = 1;
                v->jumps++;
            }
            pre_seen = 1;
        } else if (len > sizeof(rule_prefix) - 1 &&
                   memcmp(line, rule_prefix, sizeof(rule_prefix) - 1) == 0) {
            v->rules++;
            if (v->rules_exact) {
                int n = next >= 0 ? raw_rule(v->want, sizeof(v->want), targets, next, fi) : 0;
                if (n > 0 && (size_t)n == len && memcmp(line, v->want, len) == 0) {
                    next = raw_next(targets, next - 1);
                } else {
                    if (n <= 0) v->want[0] = '\0';
                    v->rules_exact = 0;
                    v->found = line;
                    v->found_len = len;
                }
            }
        }
        if (!nl) break;
        line = nl + 1;
    }
    if (!v->rules_exact) return;
    v->want[0] = '\0';
    if (next >= 0) {
        v->rules_exact = 0;
        raw_rule(v->want, sizeof(v->want), targets, next, fi);
    }
}

/* The chain with the expected rules and exactly one jump, first in
 * PREROUTING: a jump behind a foreign rule misses what that rule accepts. */
static int raw_exact(const raw_view_t *v) {
    return v->chain && v->jumps == 1 && v->jump_first && v->rules_exact;
}

static int dump_raw(connmark_family_t *fam) {
    char *argv[] = {(char *)fam->ipt_cmd, "-w", "-t", "raw", "-S", NULL};
    fam->dump_ok = 0;       /* the mangle dump is gone */
    if (run_command_output(fam->ipt_cmd, argv, fam->dump, sizeof(fam->dump)) != 0) {
        if (!fam->warned_raw_dump)
            LOG_WARN("%s -t raw -S failed or output truncated", fam->ipt_cmd);
        fam->warned_raw_dump = 1;
        return -1;
    }
    fam->warned_raw_dump = 0;
    fam->raw_seen = 1;
    return 0;
}

/* What was written must read back the same: hooked, the exact chain; taken
 * down, no jump and no rule. One WARN until it does. v is rescanned. */
static int confirm_raw(connmark_family_t *fam, const unified_target_t *targets, int count,
                       int fi, int hooked, raw_view_t *v, family_result_t *r) {
    if (dump_raw(fam) != 0) {
        r->raw_rules = -1;
        return -1;
    }
    scan_raw(fam, targets, count, fi, v);
    r->raw_rules = v->rules;
    if (hooked ? raw_exact(v) : v->jumps == 0 && v->rules == 0) {
        fam->warned_raw = 0;
        return 0;
    }
    if (!fam->warned_raw) {
        fam->warned_raw = 1;
        if (!hooked)
            LOG_WARN("%s: raw %s still has %d jumps and %d rules after removal",
                     fam->ipt_cmd, GUARD_CHAIN, v->jumps, v->rules);
        else
            LOG_WARN("%s: raw %s differs after replace: chain %d, jumps %d, first %d, "
                     "expected '%s', found '%.*s'", fam->ipt_cmd, GUARD_CHAIN, v->chain,
                     v->jumps, v->jump_first, v->want, v->found ? (int)v->found_len : 0,
                     v->found ? v->found : "");
    }
    return -1;
}

/* One iptables-restore --noflush (§3.1): declaring the chain creates or
 * flushes it, the rules go in, and unless exactly one jump is first in
 * PREROUTING every own jump goes and one is inserted first. Packets see the
 * old chain or the new one, never a part. Returns the rule count or -1. */
static int batch_raw(connmark_family_t *fam, const unified_target_t *targets, int count,
                     int fi, const raw_view_t *v) {
    int rules = 0;
    fam->len = 0;
    fam->rule_count = 1;
    batch_append(fam, "*raw\n:%s - [0:0]\n", GUARD_CHAIN);
    for (int i = raw_next(targets, count - 1); i >= 0; i = raw_next(targets, i - 1)) {
        char line[GUARD_LINE_MAX];
        if (raw_rule(line, sizeof(line), targets, i, fi) < 0) return -1;
        batch_append(fam, "%s\n", line);
        rules++;
    }
    if (v->jumps != 1 || !v->jump_first) {
        for (int j = 0; j < v->jumps; j++) batch_append(fam, "-D PREROUTING -j %s\n", GUARD_CHAIN);
        batch_append(fam, "-I PREROUTING 1 -j %s\n", GUARD_CHAIN);
    }
    return rules;
}

/* The one case hrneo takes raw down; otherwise a chain in place is the
 * protection and stays (§4.5), whatever fails. A jump into the chain while
 * mangle PREROUTING holds an unconditional restore that this call could not
 * replace is a lasting leak: old R1 skips the raw mark and old R2 writes
 * connmark 0 over it on every new connection. The jumps go and the chain is
 * emptied in one restore; it comes back once mangle is known-good. */
static int unhook_raw(connmark_family_t *fam, const unified_target_t *targets, int count,
                      int fi, raw_view_t *v, family_result_t *r) {
    fam->len = 0;
    fam->rule_count = 1;
    batch_append(fam, "*raw\n:%s - [0:0]\n", GUARD_CHAIN);
    for (int j = 0; j < v->jumps; j++) batch_append(fam, "-D PREROUTING -j %s\n", GUARD_CHAIN);
    if (commit_batch(fam) != 0) return -1;
    r->replaced = 1;
    LOG_WARN("%s: removed the jump to raw %s: unconditional CONNMARK --restore-mark "
             "in mangle PREROUTING", fam->ipt_cmd, GUARD_CHAIN);
    return confirm_raw(fam, targets, count, fi, 0, v, r);
}

/* Raw of one family after the mangle step of both. The chain goes in or
 * changes only when this call left mangle known-good: every policy mark
 * known (all_marks), and in both families R0..R3 confirmed and no
 * unconditional restore (gate; this family's own part of it also gives the
 * reason). unsafe: this family's mangle still has an unconditional restore.
 * Sets r->reason (the order decides which one the status shows) and
 * r->raw_rules. Returns -1 when the call should be retried. */
static int commit_raw(connmark_family_t *fam, const unified_target_t *targets, int count,
                      int fi, int gate, int all_marks, int unsafe, family_result_t *r) {
    const char *mangle_reason = r->reason;
    raw_view_t v;
    int ret = 0;

    /* Loaded once per process. No .ko is not a failure: the table may be
     * built into the kernel, and reading it decides. */
    if (!fam->raw_kmod)
        fam->raw_kmod = l7_firewall_load_kmod_if_present(fi ? "ip6table_raw" : "iptable_raw") == 0
                        ? 1 : -1;
    if (fam->raw_kmod < 0) {
        r->reason = "modules";
        return 0;
    }
    int seen = fam->raw_seen;
    if (dump_raw(fam) != 0) {
        /* Never read in this process: no table, a stable state, no retries. */
        r->reason = seen ? "audit" : "modules";
        return seen ? -1 : 0;
    }
    scan_raw(fam, targets, count, fi, &v);
    r->raw_rules = v.rules;

    if (unsafe && v.jumps > 0) ret = unhook_raw(fam, targets, count, fi, &v, r);
    r->reason = !all_marks ? "no-mark" : unsafe ? "old-restore" : mangle_reason;
    /* Without the gate a chain in place stays as it is; the family that
     * closed the gate names the reason. */
    if (r->reason || !gate) return ret;
    if (raw_exact(&v)) {
        fam->warned_raw = 0;
        return 0;
    }
    int rules = batch_raw(fam, targets, count, fi, &v);
    if (rules < 0) {
        r->reason = "batch-overflow";
        return -1;
    }
    LOG_INFO("%s: installing raw %s (%d rules)", fam->ipt_cmd, GUARD_CHAIN, rules);
    int rc = commit_batch(fam);
    if (rc != 0) {
        r->reason = rc == BATCH_OVERFLOW ? "batch-overflow" : "restore";
        return -1;
    }
    r->replaced = 1;
    if (confirm_raw(fam, targets, count, fi, 1, &v, r) != 0) {
        r->reason = "audit";
        return -1;
    }
    return 0;
}

/* §3.2, §4.1: mangle first, then raw. The gate is checked once for both
 * families; the unsafe check reads each family's mangle dump before its raw
 * dump takes the buffer. */
static int commit_raw_all(const unified_target_t *targets, int count, family_result_t *res) {
    int unsafe[2], all_marks = 1, gate = 1, ret = 0;
    for (int i = 0; i < count; i++)
        if (!targets[i].is_interface && !g_states[i].gone && !g_states[i].mark) all_marks = 0;
    for (int fi = 0; fi < 2; fi++) {
        connmark_family_t *fam = family(fi);
        unsafe[fi] = fam->dump_ok && unsafe_restore(fam->dump);
        if (!res[fi].mangle_ok || unsafe[fi]) gate = 0;
    }
    for (int fi = 0; fi < 2; fi++)
        if (commit_raw(family(fi), targets, count, fi, gate, all_marks, unsafe[fi], &res[fi]) != 0)
            ret = -1;
    return ret;
}

/* raw_guard=<state>[:<reason>-v4|v6] in the status file; the first family
 * with a reason names it. */
static void publish_status(const config_t *cfg, const family_result_t *res) {
    if (!cfg->raw_guard) {
        guard_status_set_raw(RAW_GUARD_OFF, "", -1, -1);
    } else if (!res[0].reason && !res[1].reason) {
        guard_status_set_raw(RAW_GUARD_ON, "", res[0].raw_rules, res[1].raw_rules);
    } else {
        char reason[GUARD_REASON_MAX];
        int fi = res[0].reason ? 0 : 1;
        snprintf(reason, sizeof(reason), "%s-v%d", res[fi].reason, fi ? 6 : 4);
        guard_status_set_raw(RAW_GUARD_DEGRADED, reason, res[0].raw_rules, res[1].raw_rules);
    }
    if (res[0].replaced || res[1].replaced) guard_status_set_rebuild(time(NULL));
    guard_status_flush();
}

int apply_unified_connmark_rules(const unified_target_t *targets, int count,
                                 const config_t *cfg, const char *l7_wan) {
    static int startup_audit = 1;
    static int conntrack_module;
    const set_list_t sets = {(const char *)&targets->pair, sizeof(*targets), count};
    owned_index_t own;
    family_result_t res[2];
    int incomplete = 0;

    memset(res, 0, sizeof(res));
    res[0].raw_rules = res[1].raw_rules = -1;

    /* R0, R1 and R3 match on the conntrack direction. */
    if (!conntrack_module) {
        if (l7_firewall_load_kmod_if_present("xt_conntrack") != 0) {
            res[0].reason = res[1].reason = "conntrack-module";
            publish_status(cfg, res);
            return -1;
        }
        conntrack_module = 1;
    }

    /* RCI before the dumps keeps the dump -> restore gap short: NDMS may
     * rewrite the table in between, and the restore then fails. */
    for (int i = 0; i < count; i++) {
        target_state_t *ts = &g_states[i];
        if ((startup_audit || !ts->mark) && resolve_mark(&targets[i], ts) != 0)
            incomplete = 1;
    }

    for (int fi = 0; fi < 2; fi++)
        if (commit_mangle(family(fi), &own, targets, &sets, fi, cfg, l7_wan, &res[fi]) != 0)
            incomplete = 1;
    if (cfg->raw_guard && commit_raw_all(targets, count, res) != 0)
        incomplete = 1;
    publish_status(cfg, res);

    if (incomplete) return -1;
    startup_audit = 0;
    return 0;
}

/* On stop the whole hrneo set leaves mangle in one iptables-restore per
 * family; the sets are matched straight from the pairs. A raw chain, if any,
 * stays: R2 restores only non-zero connmarks, so no subset of the rules can
 * clear the raw mark. */
int cleanup_connmark_rules(const ipset_pair_t *pairs, int count) {
    const set_list_t sets = {(const char *)pairs, sizeof(*pairs), count};
    owned_index_t own;
    int ret = 0;

    for (int fi = 0; fi < 2; fi++) {
        connmark_family_t *fam = family(fi);
        if (dump_chains(fam, 1) != 0 || collect_owned(fam, &sets, fi, &own) != 0) {
            ret = -1;
            continue;
        }
        if (own.count == 0) continue;
        fam->len = 0;
        fam->rule_count = 1;
        batch_append(fam, "*mangle\n");
        batch_delete_owned(fam, &own);
        if (commit_batch(fam) != 0) ret = -1;
    }
    if (ret == 0) LOG_INFO("CONNMARK rules cleaned up");
    else LOG_WARN("CONNMARK rules cleanup incomplete");
    return ret;
}
