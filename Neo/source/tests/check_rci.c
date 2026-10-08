#include "../src/rci.c"
#include <assert.h>

/* Fake RCI server for rci_request_ex: connect succeeds, the request is kept,
 * the reply goes out a few bytes per recv, then EOF or a receive error. */
static const char *reply = "";
static int reply_err;                   /* errno after the reply, 0: EOF */
static size_t reply_off;
static char request[512];

int __wrap_connect(int fd, const struct sockaddr *addr, socklen_t len) {
    (void)fd; (void)addr; (void)len;
    reply_off = 0;
    request[0] = '\0';
    return 0;
}

ssize_t __wrap_send(int fd, const void *buf, size_t len, int flags) {
    (void)fd; (void)flags;
    snprintf(request + strlen(request), sizeof(request) - strlen(request), "%.*s",
             (int)len, (const char *)buf);
    return (ssize_t)len;
}

ssize_t __wrap_recv(int fd, void *buf, size_t len, int flags) {
    size_t left = strlen(reply) - reply_off, n = left < 5 ? left : 5;
    (void)fd; (void)flags;
    if (n > len) n = len;
    if (n == 0) {
        if (!reply_err) return 0;
        errno = reply_err;
        return -1;
    }
    memcpy(buf, reply + reply_off, n);
    reply_off += n;
    return (ssize_t)n;
}

static const char SHOW_OUTPUT[] =
    "\033[K\n"
    "            token: \n"
    "                   id: 3\n"
    "          fingerprint: 03...cd\n"
    "      truncated-value: VCN...YWy\n"
    "              service: Core::Security::Authenticator\n"
    "                local: yes\n"
    "                 user: admin\n"
    "            user-data: HydraRoute\n"
    "              expires: never\n"
    "          last-access: 236\n"
    "\n"
    "            token: \n"
    "                   id: 9\n"
    "          fingerprint: 61...af\n"
    "      truncated-value: cDK...stq\n"
    "                 user: admin\n"
    "            user-data: someone-else\n"
    "              expires: never\n"
    "          last-access: 4\n"
    "\n\033[K";

static const char GENERATE_OUTPUT[] =
    "\033[K\n"
    "               id: 8\n"
    "            value: \n"
    "                   ksPNNRb3RGRMowrJDsZhC92yu3SIBA16iXVduJziQD0V51N8kCEzaMzo\n"
    "\n"
    "Core::Security::Authenticator: Added a token for user \"admin\".\n"
    "\033[K";

static void check_strip_ansi(void) {
    char out[512];
    strip_ansi("\033[Kid: 3\033[K\n", out, sizeof(out));
    assert(strcmp(out, "id: 3\n") == 0);

    strip_ansi("plain", out, sizeof(out));
    assert(strcmp(out, "plain") == 0);

    strip_ansi("\033[", out, sizeof(out));
    assert(out[0] == '\0');
}

static void check_parse_token_value(void) {
    char clean[NDMC_OUT_MAX];
    char token[MAX_RCI_TOKEN];

    strip_ansi(GENERATE_OUTPUT, clean, sizeof(clean));
    assert(ndmc_parse_token_value(clean, token, sizeof(token)) == 1);
    assert(strcmp(token, "ksPNNRb3RGRMowrJDsZhC92yu3SIBA16iXVduJziQD0V51N8kCEzaMzo") == 0);

    strip_ansi(SHOW_OUTPUT, clean, sizeof(clean));
    assert(ndmc_parse_token_value(clean, token, sizeof(token)) == 0);

    assert(ndmc_parse_token_value("value: short\n", token, sizeof(token)) == 0);
    assert(ndmc_parse_token_value("nothing here\n", token, sizeof(token)) == 0);
}

static void check_collect_token_ids(void) {
    char clean[NDMC_OUT_MAX];
    int ids[TOKEN_MAX_OWNED];

    strip_ansi(SHOW_OUTPUT, clean, sizeof(clean));

    int n = ndmc_collect_token_ids(clean, TOKEN_LABEL, ids, TOKEN_MAX_OWNED);
    assert(n == 1);
    assert(ids[0] == 3);

    n = ndmc_collect_token_ids(clean, "someone-else", ids, TOKEN_MAX_OWNED);
    assert(n == 1);
    assert(ids[0] == 9);

    n = ndmc_collect_token_ids(clean, "absent", ids, TOKEN_MAX_OWNED);
    assert(n == 0);

    n = ndmc_collect_token_ids("", TOKEN_LABEL, ids, TOKEN_MAX_OWNED);
    assert(n == 0);
}

static void check_token_send_rules(void) {
    rci_set_token("");
    assert(rci_mode() == RCI_MODE_LOCAL);
    assert(rci_should_send_token() == 0);

    rci_set_token("ksPNNRb3RGRMowrJDsZhC92yu3SIBA16iXVduJziQD0V51N8kCEzaMzo");
    assert(rci_mode() == RCI_MODE_TOKEN);
    assert(rci_should_send_token() != 0);

    g_mode = RCI_MODE_LOCAL;
    assert(rci_should_send_token() == 0);

    g_mode = RCI_MODE_BLOCKED;
    assert(rci_should_send_token() != 0);

    rci_set_token("good\ttail");
    assert(strcmp(g_rci_token, "good") == 0);

    rci_set_token("");
}

/* GET /rci/show/ip/policy/<name>/mark answers "ffffaaa" (200) for a policy
 * and 404 when there is none. Only a whole answer counts (Ruling 33): 404 is
 * the one "no such policy", "" a policy without a mark yet; anything else
 * that is not exactly one quoted mark is no answer, and the caller keeps the
 * mark it knows. */
static void check_policy_mark_answers(void) {
    static const struct {
        const char *what, *reply;
        int err, want;
        const char *mark;
    } c[] = {
        {"200",                      "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                                     "Content-Length: 9\r\n\r\n\"ffffaaa\"", 0, RCI_MARK_OK, "ffffaaa"},
        {"200 0x, no length",        "HTTP/1.0 200 OK\r\n\r\n\"0xFFFFAAA\"\n", 0, RCI_MARK_OK, "FFFFAAA"},
        {"200 lower-case length",    "HTTP/1.1 200 OK\r\ncontent-length: 10\r\n\r\n\"ffffaaa\"\n", 0, RCI_MARK_OK, "ffffaaa"},
        {"404",                      "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n", 0, RCI_MARK_ABSENT, NULL},
        {"200 no mark yet",          "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n\"\"", 0, RCI_MARK_ABSENT, NULL},
        {"401",                      "HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n", 0, RCI_MARK_DENIED, NULL},
        {"500",                      "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n", 0, RCI_MARK_TRANSPORT, NULL},
        {"503",                      "HTTP/1.1 503 Service Unavailable\r\n\r\nbusy", 0, RCI_MARK_TRANSPORT, NULL},
        {"200 cut, length says 9",   "HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\n\"ffff", 0, RCI_MARK_TRANSPORT, NULL},
        {"200 cut, no length",       "HTTP/1.0 200 OK\r\n\r\n\"ffff", 0, RCI_MARK_TRANSPORT, NULL},
        {"200, then a reset",        "HTTP/1.1 200 OK\r\n\r\n\"ffffaaa\"", ECONNRESET, RCI_MARK_TRANSPORT, NULL},
        {"200 whole by length, reset", "HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\n\"ffffaaa\"",
                                     ECONNRESET, RCI_MARK_OK, "ffffaaa"},
        {"timeout after headers",    "HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\n", EAGAIN, RCI_MARK_TRANSPORT, NULL},
        {"200 garbage",              "HTTP/1.1 200 OK\r\n\r\n<html>busy</html>", 0, RCI_MARK_TRANSPORT, NULL},
        {"200 not hex",              "HTTP/1.1 200 OK\r\n\r\n\"zz\"", 0, RCI_MARK_TRANSPORT, NULL},
        {"200 zero",                 "HTTP/1.1 200 OK\r\n\r\n\"0\"", 0, RCI_MARK_TRANSPORT, NULL},
        {"200 nine digits",          "HTTP/1.1 200 OK\r\n\r\n\"1ffffaaa0\"", 0, RCI_MARK_TRANSPORT, NULL},
        {"200 trailing text",        "HTTP/1.1 200 OK\r\n\r\n\"ffffaaa\" x", 0, RCI_MARK_TRANSPORT, NULL},
        {"200 bare 0x",              "HTTP/1.1 200 OK\r\n\r\n\"0x\"", 0, RCI_MARK_TRANSPORT, NULL},
        {"200 longer than length",   "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\n\"ffffaaa\"", 0, RCI_MARK_TRANSPORT, NULL},
        {"404 cut in the headers",   "HTTP/1.1 404 Not Fo", 0, RCI_MARK_TRANSPORT, NULL},
        {"no status code",           "HTTP/1.1 OK\r\n\r\n\"ffffaaa\"", 0, RCI_MARK_TRANSPORT, NULL},
        {"length not a number",      "HTTP/1.1 200 OK\r\nContent-Length: x\r\n\r\n\"ffffaaa\"", 0, RCI_MARK_TRANSPORT, NULL},
        {"lower-case length, cut",   "HTTP/1.1 200 OK\r\ncontent-length: 20\r\n\r\n\"ffffaaa\"", 0, RCI_MARK_TRANSPORT, NULL},
        {"200 text before",          "HTTP/1.1 200 OK\r\n\r\nbusy \"ffffaaa\"", 0, RCI_MARK_TRANSPORT, NULL},
        {"200 no closing quote",     "HTTP/1.1 200 OK\r\n\r\n\"ffffaaa \n", 0, RCI_MARK_TRANSPORT, NULL},
        {"nothing",                  "", ECONNRESET, RCI_MARK_TRANSPORT, NULL},
    };
    rci_set_token("");
    for (size_t i = 0; i < sizeof(c) / sizeof(c[0]); i++) {
        char mark[16] = "";
        reply = c[i].reply;
        reply_err = c[i].err;
        int r = rci_get_policy_mark("HydraRoute", mark, sizeof(mark));
        if (r != c[i].want || (c[i].mark && strcmp(mark, c[i].mark) != 0)) {
            fprintf(stderr, "check_rci: %s: got %d '%s', want %d\n", c[i].what, r, mark, c[i].want);
            assert(0);
        }
        static const char want_req[] = "GET /rci/show/ip/policy/HydraRoute/mark HTTP/1.0\r\n";
        assert(strncmp(request, want_req, sizeof(want_req) - 1) == 0);
    }
    g_auth_stale = 0;

    /* The auth probe sees a status only in a whole answer with a real
     * status code; otherwise 0, "no answer". */
    reply = "HTTP/1.1 200 OK\r\nContent-Length: 20\r\n\r\n{\"title\":";
    reply_err = ECONNRESET;
    assert(rci_probe(0) == 0);
    reply = "HTTP/1.1 -200 OK\r\n\r\n{}";
    reply_err = 0;
    assert(rci_probe(0) == 0);
    reply = "HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n";
    assert(rci_probe(0) == 401);
    g_auth_stale = 0;
}

int main(void) {
    check_strip_ansi();
    check_parse_token_value();
    check_collect_token_ids();
    check_token_send_rules();
    check_policy_mark_answers();
    printf("check_rci: OK\n");
    return 0;
}
