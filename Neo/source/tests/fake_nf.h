/* Fake netfilter, RCI and log for tests that link src/iptables.c.
 * Include from exactly one test file per program. */
#ifndef FAKE_NF_H
#define FAKE_NF_H

#include "../include/iptables.h"
#include "../include/guard.h"
#include "../include/guard_status.h"
#include "../include/rtnl.h"
#include "../include/util.h"
#include <assert.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>

#define MAX_LINES 64
#define LINE_LEN  320
#define NDM_LINE  "-A PREROUTING -j _NDM_HOTSPOT_PREROUTING_MANGL"
#define FOREIGN_RAW  "-A PREROUTING -p udp -m udp --dport 9 -j CT --notrack"
#define FOREIGN_RAW2 "-A PREROUTING -i br0 -p tcp -m tcp --dport 7 -j CT --notrack"

#ifndef STATUS_PATH
#define STATUS_PATH "build/check_connmark.status"
#endif

/* One family: mangle PREROUTING, FORWARD, OUTPUT and the raw table. */
typedef struct {
    char mangle[MAX_LINES][LINE_LEN];
    int  mangle_len;
    char fwd[MAX_LINES][LINE_LEN];         /* mangle FORWARD (L7 NFLOG) */
    int  fwd_len;
    char out[MAX_LINES][LINE_LEN];         /* mangle OUTPUT (L7 NFLOG) */
    int  out_len;
    char raw_pre[MAX_LINES][LINE_LEN];
    int  raw_pre_len;
    char guard[MAX_LINES][LINE_LEN];
    int  guard_len;
    int  guard_exists;
} fake_nf_t;

static fake_nf_t nf[2];
static int  restores[2][2];            /* [family][0 mangle, 1 raw] */
static char calls[512];                /* restores in order: "m4 r4 m6 r6 " */
static int  dumps, rci_calls, warns, errors, kmod_calls;
static int  rci_result = RCI_MARK_OK;  /* result for every policy ... */
static int  rci_result_ru = RCI_MARK_OK, rci_result_hr = RCI_MARK_OK;   /* ... unless OK */
static const char *mark_ru = "ff1", *mark_hr = "ff2";
static const char *restore_error;
static int  restore_error_family = -1; /* family restore_error applies to, -1: both */
static int  restore_error_table = -1;  /* table restore_error applies to: 0 mangle, 1 raw, -1 both */
static int  dump_fail[2];              /* iptables -t mangle -S fails or is truncated */
static const char *dump_fail_chain[2]; /* ... only for this mangle chain */
static int  dump_fail_at[2];           /* ... only the n-th mangle read since reset() */
static int  mangle_dumps[2];           /* mangle reads per family since reset() */
static int  raw_listed[2] = {1, 1};    /* /proc/net/ip*_tables_names: 1 has raw, 0 not, -1 unreadable */
static int  proc_calls;
static int  raw_dump_fail[2];          /* iptables -t raw -S fails (no table) or is truncated */
static int  raw_echo_other;            /* fake an iptables that prints the MARK target otherwise */
static int  kmod_result;               /* xt_conntrack */
static int  raw_kmod_fail[2], raw_kmod_calls[2];   /* iptable_raw, ip6table_raw */
static char warn_log[4096], error_log[1024];
static int  echo_full_mask;            /* fake an iptables that prints "--mark 0x0/0xffffffff" */

static const char *const SETS[2][2] = {{"RU", "HydraRoute"}, {"RU6", "HydraRoute6"}};

static inline int family_of(const char *cmd) {
    return strncmp(cmd, "ip6", 3) == 0;
}

static inline void lines_add(char (*a)[LINE_LEN], int *n, const char *line) {
    assert(*n < MAX_LINES);
    snprintf(a[(*n)++], LINE_LEN, "%s", line);
}

static inline void lines_insert0(char (*a)[LINE_LEN], int *n, const char *line) {
    assert(*n < MAX_LINES);
    memmove(a[1], a[0], (size_t)*n * LINE_LEN);
    snprintf(a[0], LINE_LEN, "%s", line);
    (*n)++;
}

static inline int lines_find(char (*a)[LINE_LEN], int n, const char *line) {
    for (int i = 0; i < n; i++)
        if (strcmp(a[i], line) == 0) return i;
    return -1;
}

static inline int lines_count(char (*a)[LINE_LEN], int n, const char *line) {
    int c = 0;
    for (int i = 0; i < n; i++)
        if (strcmp(a[i], line) == 0) c++;
    return c;
}

static inline void lines_remove(char (*a)[LINE_LEN], int *n, int idx) {
    memmove(a[idx], a[idx + 1], (size_t)(*n - idx - 1) * LINE_LEN);
    (*n)--;
}

static inline void mangle_remove_matching(int fi, const char *needle) {
    for (int i = 0; i < nf[fi].mangle_len; i++)
        if (strstr(nf[fi].mangle[i], needle)) lines_remove(nf[fi].mangle, &nf[fi].mangle_len, i--);
}

static inline int mangle_count(int fi, const char *needle) {
    int c = 0;
    for (int i = 0; i < nf[fi].mangle_len; i++)
        if (strstr(nf[fi].mangle[i], needle)) c++;
    return c;
}

int __wrap_run_command_output(const char *cmd, char *const argv[], char *output, size_t size) {
    int fi = family_of(cmd);
    fake_nf_t *f = &nf[fi];
    int raw = strcmp(argv[3], "raw") == 0;
    size_t off = 0;
    dumps++;
    output[0] = '\0';
    if (!raw) mangle_dumps[fi]++;
    if (raw ? raw_dump_fail[fi]
            : dump_fail[fi] || dump_fail_at[fi] == mangle_dumps[fi] ||
              (dump_fail_chain[fi] && strcmp(argv[5], dump_fail_chain[fi]) == 0))
        return -1;
#define OUT(...) (off += (size_t)snprintf(output + off, size - off, __VA_ARGS__))
    if (raw) {
        OUT("-P PREROUTING ACCEPT\n-P OUTPUT ACCEPT\n");
        if (f->guard_exists) OUT("-N %s\n", GUARD_CHAIN);
        for (int i = 0; i < f->raw_pre_len; i++) OUT("%s\n", f->raw_pre[i]);
        for (int i = 0; i < f->guard_len; i++) OUT("%s\n", f->guard[i]);
        return 0;
    }
    OUT("-P %s ACCEPT\n", argv[5]);
    if (strcmp(argv[5], "PREROUTING") == 0)
        for (int i = 0; i < f->mangle_len; i++) OUT("%s\n", f->mangle[i]);
    if (strcmp(argv[5], "FORWARD") == 0)
        for (int i = 0; i < f->fwd_len; i++) OUT("%s\n", f->fwd[i]);
    if (strcmp(argv[5], "OUTPUT") == 0)
        for (int i = 0; i < f->out_len; i++) OUT("%s\n", f->out[i]);
#undef OUT
    return 0;
}

/* iptables prints a rule back in its own spelling; echo_full_mask fakes one
 * that differs from what hrneo wrote. */
static inline void store(char (*a)[LINE_LEN], int *n, const char *line) {
    const char *tok = "-m connmark --mark 0x0 ";
    const char *p = echo_full_mask ? strstr(line, tok) : NULL;
    char buf[LINE_LEN];
    if (p)
        snprintf(buf, sizeof(buf), "%.*s-m connmark --mark 0x0/0xffffffff %s",
                 (int)(p - line), line, p + strlen(tok));
    else
        snprintf(buf, sizeof(buf), "%s", line);
    lines_add(a, n, buf);
}

/* A raw rule as this iptables prints it back; raw_echo_other leaves out the
 * mask, so the read-back differs from what hrneo wrote. */
static inline void store_raw(fake_nf_t *f, const char *line) {
    char buf[LINE_LEN];
    const char *mask = raw_echo_other ? strstr(line, "/0xffffffff") : NULL;
    if (mask)
        snprintf(buf, sizeof(buf), "%.*s", (int)(mask - line), line);
    else
        snprintf(buf, sizeof(buf), "%s", line);
    lines_add(f->guard, &f->guard_len, buf);
}

/* The foreign rules of raw PREROUTING, in order. */
static inline void raw_foreign(const fake_nf_t *f, char *out, size_t size) {
    out[0] = '\0';
    for (int i = 0; i < f->raw_pre_len; i++)
        if (strcmp(f->raw_pre[i], GUARD_JUMP) != 0)
            snprintf(out + strlen(out), size - strlen(out), "%s\n", f->raw_pre[i]);
}

static inline int has_unconditional_restore(int fi) {
    for (int i = 0; i < nf[fi].mangle_len; i++)
        if (strstr(nf[fi].mangle[i], "--restore-mark") &&
            !strstr(nf[fi].mangle[i], "-m connmark ! --mark 0x0 "))
            return 1;
    return 0;
}

/* §3.2: while raw marks packets, no unconditional --restore-mark may be left
 * in mangle, or it writes connmark 0 over the raw mark of every new connection. */
static inline void assert_no_unconditional_restore(int fi) {
    for (int i = 0; i < nf[fi].mangle_len; i++)
        if (strstr(nf[fi].mangle[i], "--restore-mark"))
            assert(strstr(nf[fi].mangle[i], "-m connmark ! --mark 0x0 "));
}

/* The lines of mangle chain `chain` ("PREROUTING ", "FORWARD ", "OUTPUT "). */
static inline int mangle_chain(fake_nf_t *f, const char *chain, char (**a)[LINE_LEN], int **n) {
    if (strcmp(chain, "PREROUTING ") == 0) { *a = f->mangle; *n = &f->mangle_len; return 1; }
    if (strcmp(chain, "FORWARD ") == 0)    { *a = f->fwd;    *n = &f->fwd_len;    return 1; }
    if (strcmp(chain, "OUTPUT ") == 0)     { *a = f->out;    *n = &f->out_len;    return 1; }
    return 0;
}

int __wrap_run_command_stdin(const char *cmd, char *const argv[], const char *input, size_t len,
                             char *err, size_t err_size) {
    static char buf[IPT_BATCH_SIZE];
    static char foreign_before[MAX_LINES * LINE_LEN], foreign_after[MAX_LINES * LINE_LEN];
    int fi = family_of(cmd);
    fake_nf_t *f = &nf[fi];
    int table = strncmp(input, "*raw\n", 5) == 0;
    int fail = restore_error && (restore_error_family < 0 || restore_error_family == fi) &&
               (restore_error_table < 0 || restore_error_table == table);
    /* One table, one transaction: --noflush keeps what the batch does not name,
     * and nothing is applied without the final COMMIT. */
    assert(argv[1] && strcmp(argv[1], "--noflush") == 0 && !argv[2]);
    assert(table || strncmp(input, "*mangle\n", 8) == 0);
    assert(len >= 8 && memcmp(input + len - 8, "\nCOMMIT\n", 8) == 0);
    for (size_t i = 0; i + 7 < len; i++) assert(memcmp(input + i, "COMMIT", 6) != 0);
    restores[fi][table]++;
    snprintf(calls + strlen(calls), sizeof(calls) - strlen(calls), "%c%d ", table ? 'r' : 'm', fi ? 6 : 4);
    snprintf(err, err_size, "%s", fail ? restore_error : "");
    if (fail) return 1;

    assert(len < sizeof(buf));
    memcpy(buf, input, len);
    buf[len] = '\0';
    raw_foreign(f, foreign_before, sizeof(foreign_before));
    int danger_before = f->guard_len > 0 && has_unconditional_restore(fi);
    char *save;
    for (char *line = strtok_r(buf, "\n", &save); line; line = strtok_r(NULL, "\n", &save)) {
        char chain[16] = "";
        char (*a)[LINE_LEN];
        int *n;
        if (line[0] == '*' || strcmp(line, "COMMIT") == 0) continue;
        if (line[0] == '-' && (line[1] == 'A' || line[1] == 'D') && line[2] == ' ') {
            const char *sp = strchr(line + 3, ' ');
            if (sp && (size_t)(sp - line - 2) < sizeof(chain))
                snprintf(chain, sizeof(chain), "%.*s", (int)(sp - line - 2), line + 3);
        }
        if (strcmp(line, ":" GUARD_CHAIN " - [0:0]") == 0) {
            assert(table);
            f->guard_exists = 1;            /* --noflush: a declared chain is created or flushed */
            f->guard_len = 0;
        } else if (strncmp(line, "-A " GUARD_CHAIN " ", strlen("-A " GUARD_CHAIN " ")) == 0) {
            assert(table && f->guard_exists);
            store_raw(f, line);
        } else if (strncmp(line, "-A PREROUTING ", 14) == 0 && table) {
            lines_add(f->raw_pre, &f->raw_pre_len, line);
        } else if (line[1] == 'A' && !table && mangle_chain(f, chain, &a, &n)) {
            store(a, n, line);
        } else if (strncmp(line, "-I PREROUTING 1 ", 16) == 0) {
            char ins[LINE_LEN];
            assert(table);
            snprintf(ins, sizeof(ins), "-A PREROUTING %s", line + 16);
            lines_insert0(f->raw_pre, &f->raw_pre_len, ins);
        } else if (strncmp(line, "-D PREROUTING ", 14) == 0 && table) {
            line[1] = 'A';
            int idx = lines_find(f->raw_pre, f->raw_pre_len, line);
            assert(idx >= 0);
            lines_remove(f->raw_pre, &f->raw_pre_len, idx);
        } else if (line[1] == 'D' && !table && mangle_chain(f, chain, &a, &n)) {
            line[1] = 'A';
            int idx = lines_find(a, *n, line);
            assert(idx >= 0);
            lines_remove(a, n, idx);
        } else if (strcmp(line, "-F " GUARD_CHAIN) == 0) {
            assert(table);
            f->guard_len = 0;
        } else if (strcmp(line, "-X " GUARD_CHAIN) == 0) {
            assert(table && f->guard_exists && f->guard_len == 0);
            assert(lines_find(f->raw_pre, f->raw_pre_len, GUARD_JUMP) < 0);
            f->guard_exists = 0;
        } else {
            fprintf(stderr, "unexpected restore line: %s\n", line);
            assert(0);
        }
    }
    raw_foreign(f, foreign_after, sizeof(foreign_after));
    assert(strcmp(foreign_before, foreign_after) == 0);     /* foreign raw rules stay, in order */
    /* A raw write never leaves a marking chain next to an unconditional
     * restore; a mangle write never creates that state (one that was there
     * before the call, a rollback leftover, is taken down by the raw write
     * that follows in the same call, which the tests check). */
    if (f->guard_len > 0 && (table || !danger_before)) assert_no_unconditional_restore(fi);
    return 0;
}

void __wrap_log_write(const char *fmt, ...) {
    char line[512];
    va_list ap;
    int warn = strncmp(fmt, "[WARN]", 6) == 0, error = strncmp(fmt, "[ERROR]", 7) == 0;
    if (!warn && !error) return;
    va_start(ap, fmt);
    vsnprintf(line, sizeof(line), fmt, ap);
    va_end(ap);
    if (warn) {
        warns++;
        snprintf(warn_log + strlen(warn_log), sizeof(warn_log) - strlen(warn_log), "%s", line);
    } else {
        errors++;
        snprintf(error_log + strlen(error_log), sizeof(error_log) - strlen(error_log), "%s", line);
    }
}

/* xt_conntrack, and the raw table modules of each family. A raw module that
 * fails logs its WARN, as the real loader does. */
int __wrap_l7_firewall_load_kmod_if_present(const char *name) {
    if (strcmp(name, "xt_conntrack") == 0) {
        kmod_calls++;
        return kmod_result;
    }
    int fi = strcmp(name, "ip6table_raw") == 0;
    assert(fi || strcmp(name, "iptable_raw") == 0);
    raw_kmod_calls[fi]++;
    if (!raw_kmod_fail[fi]) return 0;
    __wrap_log_write("[WARN] kmod %s: init_module failed: %s\n", name, "Exec format error");
    return -1;
}

/* The kernel's list of loaded tables of a family. */
int __wrap_proc_list_has(const char *path, const char *name) {
    int fi = strcmp(path, "/proc/net/ip6_tables_names") == 0;
    assert(fi || strcmp(path, "/proc/net/ip_tables_names") == 0);
    assert(strcmp(name, "raw") == 0);
    proc_calls++;
    return raw_listed[fi];
}

/* The NDMS ip rules of IPv4, "fwmark <mark> lookup <table>": RU (0xff1) and
 * HydraRoute (0xff2). fake_rule_count -1: the dump fails. As the real one,
 * every table is set, 0 for a mark without a rule. */
static rtnl_fwmark_rule_t fake_rules[8] = {{0xff1, 4096}, {0xff2, 4097}};
static int fake_rule_count = 2;
static int rule_dumps;

int rtnl_fwmark_rules(int family, rtnl_fwmark_rule_t *rules, int n) {
    int found = 0;
    assert(family == AF_INET);              /* the policy mark is the same in both families */
    rule_dumps++;
    if (fake_rule_count < 0) return -1;
    for (int k = 0; k < n; k++) {
        rules[k].table = 0;
        for (int j = 0; j < fake_rule_count && rules[k].mark; j++)
            if (fake_rules[j].mark == rules[k].mark) {
                rules[k].table = fake_rules[j].table;
                break;
            }
        if (rules[k].table) found++;
    }
    return found;
}

int rci_get_policy_mark(const char *name, char *mark, int mark_size) {
    int ru = strcmp(name, "RU") == 0;
    int r = rci_result != RCI_MARK_OK ? rci_result : ru ? rci_result_ru : rci_result_hr;
    rci_calls++;
    if (r != RCI_MARK_OK) return r;
    snprintf(mark, (size_t)mark_size, "%s", ru ? mark_ru : mark_hr);
    return RCI_MARK_OK;
}

static inline void reset(void) {
    memset(restores, 0, sizeof(restores));
    calls[0] = '\0';
    warn_log[0] = '\0';
    error_log[0] = '\0';
    dumps = rci_calls = warns = errors = kmod_calls = rule_dumps = 0;
    raw_kmod_calls[0] = raw_kmod_calls[1] = 0;
    mangle_dumps[0] = mangle_dumps[1] = 0;
    proc_calls = 0;
}

static inline void setup_targets(unified_target_t *t, config_t *cfg) {
    memset(cfg, 0, sizeof(*cfg));
    memset(t, 0, 2 * sizeof(*t));
    strcpy(t[0].pair.ipv4, "RU");         strcpy(t[0].pair.ipv6, "RU6");
    strcpy(t[1].pair.ipv4, "HydraRoute"); strcpy(t[1].pair.ipv6, "HydraRoute6");
}

/* mangle PREROUTING of family fi from line `base` on: R0..R3 of RU (0xff1,
 * mask bit 0) and of HydraRoute (hr_mark, mask bit 1) in PolicyOrder.
 * Returns the position after them. */
static inline int expect_mangle_rules(int fi, int base, unsigned mask, uint32_t hr_mark,
                                      int global_routing) {
    uint32_t marks[2] = {0xff1, hr_mark};
    int pos = base;
    for (int i = 0; i < 2; i++) {
        if (!(mask & (1u << i))) continue;
        for (int k = 0; k < GUARD_MANGLE_RULES; k++) {
            char want[GUARD_LINE_MAX];
            assert(guard_mangle_rule(want, sizeof(want), k, SETS[fi][i], marks[i], 0, global_routing) > 0);
            if (pos >= nf[fi].mangle_len || strcmp(nf[fi].mangle[pos], want) != 0) {
                fprintf(stderr, "family %d line %d: want '%s'\n  got '%s'\n", fi, pos, want,
                        pos < nf[fi].mangle_len ? nf[fi].mangle[pos] : "(none)");
                assert(0);
            }
            pos++;
        }
    }
    return pos;
}

/* `base` foreign lines, then the rules of the targets in mask, nothing else. */
static inline void assert_mangle_of(int fi, int base, unsigned mask, uint32_t hr_mark,
                                    int global_routing) {
    assert(nf[fi].mangle_len == expect_mangle_rules(fi, base, mask, hr_mark, global_routing));
}

/* Both targets, RU then HydraRoute. */
static inline void assert_mangle(int fi, int base, uint32_t hr_mark, int global_routing) {
    assert_mangle_of(fi, base, 3, hr_mark, global_routing);
}

/* The status file has this exact line. */
static inline int status_has(const char *line) {
    char buf[1024], want[128];
    FILE *f = fopen(STATUS_PATH, "r");
    if (!f) return 0;
    size_t n = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    buf[n] = '\0';
    snprintf(want, sizeof(want), "%s\n", line);
    for (const char *p = buf; (p = strstr(p, want)); p++)
        if (p == buf || p[-1] == '\n') return 1;
    return 0;
}

static inline int raw_jumps(int fi) {
    return lines_count(nf[fi].raw_pre, nf[fi].raw_pre_len, GUARD_JUMP);
}

/* neo raw-off by hand: chain and jumps gone. */
static inline void raw_clear(int fi) {
    nf[fi].guard_exists = 0;
    nf[fi].guard_len = 0;
    for (int i = 0; i < nf[fi].raw_pre_len; i++)
        if (strcmp(nf[fi].raw_pre[i], GUARD_JUMP) == 0)
            lines_remove(nf[fi].raw_pre, &nf[fi].raw_pre_len, i--);
}

/* raw of family fi: one jump, first in PREROUTING, and in the chain the rules
 * of the targets in mask (bit 0 RU 0xff1, bit 1 HydraRoute hr_mark) in reverse
 * PolicyOrder: HydraRoute, then RU, so the last match, RU, sets the mark. */
static inline void assert_raw_of(int fi, unsigned mask, uint32_t hr_mark) {
    uint32_t marks[2] = {0xff1, hr_mark};
    int pos = 0;
    assert(nf[fi].guard_exists);
    assert(nf[fi].raw_pre_len >= 1 && strcmp(nf[fi].raw_pre[0], GUARD_JUMP) == 0);
    assert(raw_jumps(fi) == 1);
    for (int i = 1; i >= 0; i--) {
        char want[GUARD_LINE_MAX];
        if (!(mask & (1u << i))) continue;
        assert(guard_raw_rule(want, sizeof(want), SETS[fi][i], marks[i]) > 0);
        if (pos >= nf[fi].guard_len || strcmp(nf[fi].guard[pos], want) != 0) {
            fprintf(stderr, "family %d raw rule %d: want '%s'\n  got '%s'\n", fi, pos, want,
                    pos < nf[fi].guard_len ? nf[fi].guard[pos] : "(none)");
            assert(0);
        }
        pos++;
    }
    assert(nf[fi].guard_len == pos);
}

static inline void assert_raw(int fi, uint32_t hr_mark) {
    assert_raw_of(fi, 3, hr_mark);
}

#endif
