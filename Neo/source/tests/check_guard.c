#include "../include/guard.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define M        0xffffaaau
#define CT_OTHER 0xbeefu       /* connmark of another target or of an old policy */
#define NDM_DEV  0xffffaa5u    /* mark NDMS gives a device bound to a policy */

/* Literal text: the commit audit compares `iptables -S` lines with these
 * strings byte for byte (iptables 1.4.21 omits a full mask). */
static void check_mangle_text(void) {
    char r[GUARD_LINE_MAX];

    assert(guard_mangle_rule(r, sizeof(r), 0, "HydraRoute", M, 0, 0) > 0);
    assert(strcmp(r, "-A PREROUTING -m mark --mark 0xffffaaa -m conntrack --ctdir ORIGINAL "
                     "-m connmark --mark 0x0 -m set --match-set HydraRoute dst "
                     "-j CONNMARK --set-xmark 0xffffaaa/0xffffffff") == 0);
    assert(guard_mangle_rule(r, sizeof(r), 1, "HydraRoute", M, 0, 0) > 0);
    assert(strcmp(r, "-A PREROUTING -m mark ! --mark 0xffffaa0/0xffffff0 -m conntrack --ctdir ORIGINAL "
                     "-m connmark --mark 0x0 -m set --match-set HydraRoute dst "
                     "-j CONNMARK --set-xmark 0xffffaaa/0xffffffff") == 0);
    assert(guard_mangle_rule(r, sizeof(r), 1, "HydraRoute", M, 0, 1) > 0);
    assert(strcmp(r, "-A PREROUTING -m conntrack --ctdir ORIGINAL "
                     "-m connmark --mark 0x0 -m set --match-set HydraRoute dst "
                     "-j CONNMARK --set-xmark 0xffffaaa/0xffffffff") == 0);
    assert(guard_mangle_rule(r, sizeof(r), 2, "HydraRoute", M, 0, 0) > 0);
    assert(strcmp(r, "-A PREROUTING -m connmark ! --mark 0x0 -m set --match-set HydraRoute dst "
                     "-j CONNMARK --restore-mark --nfmask 0xffffffff --ctmask 0xffffffff") == 0);
    assert(guard_mangle_rule(r, sizeof(r), 3, "HydraRoute", M, 0, 0) > 0);
    assert(strcmp(r, "-A PREROUTING -m conntrack --ctdir REPLY -m connmark --mark 0x0 "
                     "-m set --match-set HydraRoute dst -j MARK --set-xmark 0x0/0xffffffff") == 0);

    /* Interface targets (DirectRoute) have no raw mark, hence no R0. */
    assert(guard_mangle_rule(r, sizeof(r), 0, "wg0", 0x3001, 1, 0) == 0);
    assert(guard_mangle_rule(r, sizeof(r), 1, "wg0", 0x3001, 1, 0) > 0);
    assert(strcmp(r, "-A PREROUTING -m mark ! --mark 0xffffaa0/0xffffff0 -m conntrack --ctdir ORIGINAL "
                     "-m connmark --mark 0x0 -m set --match-set wg0 dst "
                     "-j CONNMARK --set-xmark 0x3001/0xffffffff") == 0);

    assert(guard_mangle_rule(r, 16, 2, "HydraRoute", M, 0, 0) == -1);
}

/* ---- Model of kernel 4.9: xt_mark, xt_conntrack, xt_connmark, xt_set and
 * the MARK/CONNMARK targets, evaluated on the generated rule text. ---- */

typedef struct {
    uint32_t mark;   /* skb->mark when the packet reaches mangle PREROUTING */
    uint32_t ct;     /* connmark of its conntrack entry */
    int has_ct;      /* 0: nf_ct_get() == NULL */
    int reply;       /* conntrack direction is REPLY */
    int untracked;   /* 4.9: the untracked template (raw NOTRACK), ctinfo IP_CT_NEW */
} pkt_t;

static const char *after(const char *s, const char *tok) {
    const char *p = strstr(s, tok);
    return p ? p + strlen(tok) : NULL;
}

/* "0xV" or "0xV/0xM"; iptables leaves out a full mask. */
static void parse_mark(const char *s, uint32_t *val, uint32_t *mask) {
    char *end;
    *val = (uint32_t)strtoul(s, &end, 16);
    *mask = *end == '/' ? (uint32_t)strtoul(end + 1, NULL, 16) : 0xffffffffu;
}

static int modules_in(const char *rule) {
    int n = 0;
    for (const char *p = rule; (p = strstr(p, " -m ")); p += 4) n++;
    for (const char *p = rule; (p = strstr(p, " -j ")); p += 4) n++;
    return n;
}

/* Every -m and -j of the rule must be one the model knows, or a new
 * condition would be ignored silently. All packets here go to an address of
 * the set, so -m set always matches. */
static void eval(const char *rule, pkt_t *p) {
    int known = 0, match = 1;
    int tracked = p->has_ct && !p->untracked;
    const char *s;
    uint32_t v, m;

    if ((s = after(rule, " -m mark "))) {
        int inv = strncmp(s, "! ", 2) == 0;
        known++;
        parse_mark(after(s, "--mark "), &v, &m);
        if (((p->mark & m) == v) == inv) match = 0;
    }
    if ((s = after(rule, " -m conntrack --ctdir "))) {
        known++;
        /* conntrack_mt: no entry and no --ctstate → no match. The untracked
         * template is an entry in direction ORIGINAL (ctinfo IP_CT_NEW). */
        if (!p->has_ct || p->reply != (strncmp(s, "REPLY", 5) == 0)) match = 0;
    }
    if ((s = after(rule, " -m connmark "))) {
        int inv = strncmp(s, "! ", 2) == 0;
        known++;
        parse_mark(after(s, "--mark "), &v, &m);
        /* connmark_mt: no entry or untracked → no match, with ! too */
        if (!tracked || ((p->ct & m) == v) == inv) match = 0;
    }
    if (after(rule, " -m set --match-set ")) known++;
    if ((s = after(rule, " -j CONNMARK --set-xmark "))) {
        known++;
        parse_mark(s, &v, &m);
        /* connmark_tg: no entry or untracked → nothing */
        if (match && tracked) p->ct = (p->ct & ~m) ^ v;
    } else if ((s = after(rule, " -j CONNMARK --restore-mark --nfmask "))) {
        uint32_t nfmask = (uint32_t)strtoul(s, NULL, 16);
        uint32_t ctmask = (uint32_t)strtoul(after(s, "--ctmask "), NULL, 16);
        known++;
        if (match && tracked) p->mark = (p->mark & ~nfmask) ^ (p->ct & ctmask);
    } else if ((s = after(rule, " -j MARK --set-xmark "))) {
        known++;
        parse_mark(s, &v, &m);
        if (match) p->mark = (p->mark & ~m) ^ v;
    }
    assert(known == modules_in(rule));
}

typedef struct {
    const char *name;
    pkt_t pkt;
    int raw_marked;   /* raw gave the packet the policy mark */
    int outbound;     /* ORIGINAL direction of a client's connection */
} kind_t;

static const kind_t KINDS[] = {
    {"new outbound, raw mark",                  {M, 0, 1, 0, 0},        1, 1},
    {"established outbound, raw mark",          {M, M, 1, 0, 0},        1, 1},
    {"outbound without conntrack entry",        {M, 0, 0, 0, 0},        1, 1},
    {"untracked outbound, raw mark",            {M, 0, 1, 0, 1},        1, 1},
    {"outbound, raw mark, other connmark",      {M, CT_OTHER, 1, 0, 0}, 1, 1},
    {"reply of an inbound connection",          {M, 0, 1, 1, 0},        1, 0},
    {"new outbound, no raw mark",               {0, 0, 1, 0, 0},        0, 1},
    {"established outbound, no raw mark",       {0, M, 1, 0, 0},        0, 1},
    {"established outbound, other connmark",    {0, CT_OTHER, 1, 0, 0}, 0, 1},
    {"untracked outbound, no raw mark",         {0, 0, 1, 0, 1},        0, 1},
    {"new outbound, NDMS device mark",          {NDM_DEV, 0, 1, 0, 0},  0, 1},
};

/* The mark the packet must leave mangle PREROUTING with when the rules of
 * `subset` (bit k: Rk present) are in place. */
static uint32_t want_mark(const kind_t *kind, int gr, unsigned subset) {
    int r1 = (subset & 2) != 0, r2 = (subset & 4) != 0, r3 = (subset & 8) != 0;
    const pkt_t *p = &kind->pkt;
    int tracked = p->has_ct && !p->untracked;

    if (kind->raw_marked && !kind->outbound) return r3 ? 0 : M;  /* R3 clears it */
    if (tracked && p->ct) return r2 ? p->ct : p->mark;    /* R2 restores a non-zero connmark */
    if (kind->raw_marked) return M;                       /* nothing writes over it */
    if (!tracked) return p->mark;                         /* no connmark to set */
    if (p->mark && !gr) return p->mark;                   /* NDMS device: R1 leaves it to NDMS */
    return (r1 && r2) ? M : p->mark;                      /* R1 sets connmark, R2 restores it */
}

/* §3.2/§8: for every subset of {R0,R1,R2,R3} (all, some, none present —
 * NDMS rebuild, stop, first install). For an outbound packet with a non-zero
 * mark from raw, every subset of R0..R3 keeps the mark non-zero; a foreign or
 * old non-zero connmark may change its value. Replies of inbound connections
 * lose the raw mark with R3. Beyond that property each kind of packet must
 * end with the exact mark want_mark() gives. */
static void check_invariant(void) {
    for (int gr = 0; gr < 2; gr++) {
        char rules[GUARD_MANGLE_RULES][GUARD_LINE_MAX];
        for (int k = 0; k < GUARD_MANGLE_RULES; k++)
            assert(guard_mangle_rule(rules[k], GUARD_LINE_MAX, k, "HydraRoute", M, 0, gr) > 0);
        for (unsigned subset = 0; subset < 16; subset++) {
            for (size_t i = 0; i < sizeof(KINDS) / sizeof(KINDS[0]); i++) {
                const kind_t *kind = &KINDS[i];
                pkt_t p = kind->pkt;
                uint32_t want = want_mark(kind, gr, subset);
                for (int k = 0; k < GUARD_MANGLE_RULES; k++)
                    if (subset & (1u << k)) eval(rules[k], &p);
                if (kind->raw_marked && kind->outbound && p.mark == 0) {
                    fprintf(stderr, "GlobalRouting=%d subset R0..R3=%x %s: raw mark cleared\n",
                            gr, subset, kind->name);
                    assert(p.mark != 0);
                }
                if (p.mark != want) {
                    fprintf(stderr, "GlobalRouting=%d subset R0..R3=%x %s: mark 0x%x, want 0x%x\n",
                            gr, subset, kind->name, p.mark, want);
                    assert(0);
                }
            }
        }
    }
}

/* Negative control: the model does see the leak of the old rules (raw on,
 * old R1 skips the raw mark, old R2 restores connmark 0). This is why mangle
 * is replaced and confirmed before raw goes in (§3.2, Codex rev4 P1). */
static void check_old_rules_leak(void) {
    static const char OLD_R1[] =
        "-A PREROUTING -m mark ! --mark 0xffffaa0/0xffffff0 -m connmark --mark 0x0 "
        "-m set --match-set HydraRoute dst -j CONNMARK --set-xmark 0xffffaaa/0xffffffff";
    static const char OLD_R2[] =
        "-A PREROUTING -m set --match-set HydraRoute dst "
        "-j CONNMARK --restore-mark --nfmask 0xffffffff --ctmask 0xffffffff";
    pkt_t p = KINDS[0].pkt;
    eval(OLD_R1, &p);
    eval(OLD_R2, &p);
    assert(p.mark == 0);
    p = KINDS[0].pkt;
    eval(OLD_R2, &p);
    assert(p.mark == 0);
}

int main(void) {
    check_mangle_text();
    check_invariant();
    check_old_rules_leak();
    puts("check_guard: OK");
    return 0;
}
