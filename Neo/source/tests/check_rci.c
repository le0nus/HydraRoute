#include "../src/rci.c"
#include <assert.h>

/* Fake RCI server for rci_request_ex: connect succeeds, the request is kept,
 * the reply (any bytes, NUL too) goes out a few bytes per recv, then EOF, a
 * receive error, or with keep_open a peer that sends nothing more: a recv
 * then would wait out SO_RCVTIMEO, counted in late_recvs. */
static const char *reply = "";
static size_t reply_len, reply_off;
static int reply_err;                   /* errno after the reply, 0: EOF */
static int keep_open, late_recvs;
static size_t chunk = 5;                /* bytes per recv, 0: all that fits */
static char request[1024];
static size_t request_len;

#define BYTES(s) s, sizeof(s) - 1

static void serve(const char *bytes, size_t len, int err, int open) {
    reply = bytes;
    reply_len = len;
    reply_err = err;
    keep_open = open;
    late_recvs = 0;
}

int __wrap_connect(int fd, const struct sockaddr *addr, socklen_t len) {
    (void)fd; (void)addr; (void)len;
    reply_off = 0;
    request_len = 0;
    return 0;
}

ssize_t __wrap_send(int fd, const void *buf, size_t len, int flags) {
    (void)fd; (void)flags;
    assert(request_len + len < sizeof(request));
    memcpy(request + request_len, buf, len);
    request_len += len;
    request[request_len] = '\0';
    return (ssize_t)len;
}

ssize_t __wrap_recv(int fd, void *buf, size_t len, int flags) {
    size_t left = reply_len - reply_off, n = chunk && left > chunk ? chunk : left;
    (void)fd; (void)flags;
    if (n > len) n = len;
    if (n == 0) {
        if (keep_open) {
            late_recvs++;
            errno = EAGAIN;
            return -1;
        }
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
        size_t len;
        int err, open, want;            /* open: see the loop */
        const char *mark;
    } c[] = {
        {"200",                      BYTES("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                                           "Content-Length: 9\r\n\r\n\"ffffaaa\""), 0, 0, RCI_MARK_OK, "ffffaaa"},
        {"200 0x, no length",        BYTES("HTTP/1.0 200 OK\r\n\r\n\"0xFFFFAAA\"\n"), 0, 0, RCI_MARK_OK, "FFFFAAA"},
        {"200 lower-case length",    BYTES("HTTP/1.1 200 OK\r\ncontent-length: 10\r\n\r\n\"ffffaaa\"\n"), 0, 0, RCI_MARK_OK, "ffffaaa"},
        {"404",                      BYTES("HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n"), 0, 0, RCI_MARK_ABSENT, NULL},
        {"200 no mark yet",          BYTES("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n\"\""), 0, 0, RCI_MARK_ABSENT, NULL},
        {"401",                      BYTES("HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n"), 0, 0, RCI_MARK_DENIED, NULL},
        /* the peer keeps the connection open after a whole answer: no wait */
        {"200 kept open",            BYTES("HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\n\"ffffaaa\""), 0, 1, RCI_MARK_OK, "ffffaaa"},
        {"404 kept open",            BYTES("HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n"), 0, 1, RCI_MARK_ABSENT, NULL},
        {"500",                      BYTES("HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n"), 0, 0, RCI_MARK_TRANSPORT, NULL},
        {"503",                      BYTES("HTTP/1.1 503 Service Unavailable\r\n\r\nbusy"), 0, 0, RCI_MARK_TRANSPORT, NULL},
        {"200 cut, length says 9",   BYTES("HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\n\"ffff"), 0, 0, RCI_MARK_TRANSPORT, NULL},
        {"200 cut, no length",       BYTES("HTTP/1.0 200 OK\r\n\r\n\"ffff"), 0, 0, RCI_MARK_TRANSPORT, NULL},
        {"200, then a reset",        BYTES("HTTP/1.1 200 OK\r\n\r\n\"ffffaaa\""), ECONNRESET, 0, RCI_MARK_TRANSPORT, NULL},
        {"200 whole by length, reset", BYTES("HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\n\"ffffaaa\""),
                                     ECONNRESET, 0, RCI_MARK_OK, "ffffaaa"},
        {"timeout after headers",    BYTES("HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\n"), EAGAIN, 0, RCI_MARK_TRANSPORT, NULL},
        {"no length, kept open",     BYTES("HTTP/1.1 200 OK\r\n\r\n\"ffffaaa\""), 0, 2, RCI_MARK_TRANSPORT, NULL},
        /* Ruling 35: chunked (or any Transfer-Encoding) is not supported */
        {"404 chunked, cut",         BYTES("HTTP/1.1 404 Not Found\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nab"), 0, 0, RCI_MARK_TRANSPORT, NULL},
        {"404 chunked, no chunks",   BYTES("HTTP/1.1 404 Not Found\r\ntransfer-encoding: chunked\r\n\r\n"), 0, 0, RCI_MARK_TRANSPORT, NULL},
        {"200 chunked, cut",         BYTES("HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n9\r\n\"ffffaaa"), 0, 0, RCI_MARK_TRANSPORT, NULL},
        {"200 chunked, whole",       BYTES("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n9\r\n\"ffffaaa\"\r\n0\r\n\r\n"), 0, 0, RCI_MARK_TRANSPORT, NULL},
        {"200 chunked, kept open",   BYTES("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n9\r\n\"ffffaaa\"\r\n"), 0, 1, RCI_MARK_TRANSPORT, NULL},
        {"404 length and chunked",   BYTES("HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nTransfer-Encoding: chunked\r\n\r\n"), 0, 0, RCI_MARK_TRANSPORT, NULL},
        {"two lengths",              BYTES("HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n"), 0, 0, RCI_MARK_TRANSPORT, NULL},
        /* a NUL in the body must not hide what follows it */
        {"200 \"\" NUL x",           BYTES("HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\n\"\"\0x"), 0, 0, RCI_MARK_TRANSPORT, NULL},
        {"200 mark NUL x",           BYTES("HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\n\"ffffaaa\"\0x"), 0, 0, RCI_MARK_TRANSPORT, NULL},
        /* Ruling 36: a broken header block is no answer, whatever it says */
        {"404 LF before length",     BYTES("HTTP/1.1 404 Not Found\nContent-Length: 9\r\n\r\nab"), 0, 0, RCI_MARK_TRANSPORT, NULL},
        {"200 LF before length",     BYTES("HTTP/1.1 200 OK\nContent-Length: 20\r\n\r\n\"\""), 0, 0, RCI_MARK_TRANSPORT, NULL},
        {"404 LF before chunked",    BYTES("HTTP/1.1 404 Not Found\nTransfer-Encoding: chunked\r\n\r\n"), 0, 0, RCI_MARK_TRANSPORT, NULL},
        {"200 LF before chunked",    BYTES("HTTP/1.1 200 OK\r\nServer: ndm\nTransfer-Encoding: chunked\r\n\r\n\"\""), 0, 0, RCI_MARK_TRANSPORT, NULL},
        {"404 CR before length",     BYTES("HTTP/1.1 404 Not Found\rContent-Length: 9\r\n\r\nab"), 0, 0, RCI_MARK_TRANSPORT, NULL},
        {"404 length, no colon",     BYTES("HTTP/1.1 404 Not Found\r\nContent-Length 9\r\n\r\nab"), 0, 0, RCI_MARK_TRANSPORT, NULL},
        {"404 header, no colon",     BYTES("HTTP/1.1 404 Not Found\r\nServer ndm\r\nContent-Length: 0\r\n\r\n"), 0, 0, RCI_MARK_TRANSPORT, NULL},
        {"broken block, kept open",  BYTES("HTTP/1.1 404 Not Found\nContent-Length: 0\r\n\r\n"), 0, 1, RCI_MARK_TRANSPORT, NULL},
        {"length past any buffer",   BYTES("HTTP/1.1 404 Not Found\r\nContent-Length: 99999999999999999999999\r\n\r\n"), 0, 0, RCI_MARK_TRANSPORT, NULL},
        {"chunked, then a length",   BYTES("HTTP/1.1 404 Not Found\r\nTransfer-Encoding: chunked\r\nContent-Length: 0\r\n\r\n"), 0, 0, RCI_MARK_TRANSPORT, NULL},
        {"404 space before colon",   BYTES("HTTP/1.1 404 Not Found\r\nContent-Length : 9\r\n\r\nab"), 0, 0, RCI_MARK_TRANSPORT, NULL},
        {"404 folded line",          BYTES("HTTP/1.1 404 Not Found\r\nServer: ndm\r\n Content-Length: 9\r\n\r\nab"), 0, 0, RCI_MARK_TRANSPORT, NULL},
        {"404 NUL in a header",      BYTES("HTTP/1.1 404 Not Found\r\nServer: n\0m\r\nContent-Length: 0\r\n\r\n"), 0, 0, RCI_MARK_TRANSPORT, NULL},
        {"length, then no colon",    BYTES("HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nServer ndm\r\n\r\n"), 0, 0, RCI_MARK_TRANSPORT, NULL},
        {"HTTP/2.0 status line",     BYTES("HTTP/2.0 404 Not Found\r\nContent-Length: 0\r\n\r\n"), 0, 0, RCI_MARK_TRANSPORT, NULL},
        {"HTTP/2 status line",       BYTES("HTTP/2 404 Not Found\r\nContent-Length: 0\r\n\r\n"), 0, 0, RCI_MARK_TRANSPORT, NULL},
        {"four-digit status",        BYTES("HTTP/1.1 4040 Not Found\r\nContent-Length: 0\r\n\r\n"), 0, 0, RCI_MARK_TRANSPORT, NULL},
        {"404 no reason",            BYTES("HTTP/1.1 404\r\nContent-Length: 0\r\n\r\n"), 0, 0, RCI_MARK_ABSENT, NULL},
        {"200 garbage",              BYTES("HTTP/1.1 200 OK\r\n\r\n<html>busy</html>"), 0, 0, RCI_MARK_TRANSPORT, NULL},
        {"200 not hex",              BYTES("HTTP/1.1 200 OK\r\n\r\n\"zz\""), 0, 0, RCI_MARK_TRANSPORT, NULL},
        {"200 zero",                 BYTES("HTTP/1.1 200 OK\r\n\r\n\"0\""), 0, 0, RCI_MARK_TRANSPORT, NULL},
        {"200 nine digits",          BYTES("HTTP/1.1 200 OK\r\n\r\n\"1ffffaaa0\""), 0, 0, RCI_MARK_TRANSPORT, NULL},
        {"200 trailing text",        BYTES("HTTP/1.1 200 OK\r\n\r\n\"ffffaaa\" x"), 0, 0, RCI_MARK_TRANSPORT, NULL},
        {"200 bare 0x",              BYTES("HTTP/1.1 200 OK\r\n\r\n\"0x\""), 0, 0, RCI_MARK_TRANSPORT, NULL},
        {"200 longer than length",   BYTES("HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\n\"ffffaaa\""), 0, 0, RCI_MARK_TRANSPORT, NULL},
        {"404 cut in the headers",   BYTES("HTTP/1.1 404 Not Fo"), 0, 0, RCI_MARK_TRANSPORT, NULL},
        {"no status code",           BYTES("HTTP/1.1 OK\r\n\r\n\"ffffaaa\""), 0, 0, RCI_MARK_TRANSPORT, NULL},
        {"length with junk after",   BYTES("HTTP/1.1 200 OK\r\nContent-Length: 9x\r\n\r\n\"ffffaaa\""), 0, 0, RCI_MARK_TRANSPORT, NULL},
        {"length not a number",      BYTES("HTTP/1.1 200 OK\r\nContent-Length: x\r\n\r\n\"ffffaaa\""), 0, 0, RCI_MARK_TRANSPORT, NULL},
        {"lower-case length, cut",   BYTES("HTTP/1.1 200 OK\r\ncontent-length: 20\r\n\r\n\"ffffaaa\""), 0, 0, RCI_MARK_TRANSPORT, NULL},
        {"200 text before",          BYTES("HTTP/1.1 200 OK\r\n\r\nbusy \"ffffaaa\""), 0, 0, RCI_MARK_TRANSPORT, NULL},
        {"200 no closing quote",     BYTES("HTTP/1.1 200 OK\r\n\r\n\"ffffaaa \n"), 0, 0, RCI_MARK_TRANSPORT, NULL},
        {"nothing",                  BYTES(""), ECONNRESET, 0, RCI_MARK_TRANSPORT, NULL},
    };
    static const char want_req[] = "GET /rci/show/ip/policy/HydraRoute/mark HTTP/1.0\r\n";
    static const size_t splits[] = {1, 5, 7, 0};
    rci_set_token("");
    for (size_t i = 0; i < sizeof(c) / sizeof(c[0]) * 4; i++) {
        char mark[16] = "";
        size_t k = i / 4;
        chunk = splits[i % 4];
        serve(c[k].reply, c[k].len, c[k].err, c[k].open);
        int r = rci_get_policy_mark("HydraRoute", mark, sizeof(mark));
        if (r != c[k].want || (c[k].mark && strcmp(mark, c[k].mark) != 0)) {
            fprintf(stderr, "check_rci: %s (recv by %zu): got %d '%s', want %d\n",
                    c[k].what, chunk, r, mark, c[k].want);
            assert(0);
        }
        /* open 1: the answer is whole by its length, or its framing is not
         * read at all: no recv after it. open 2: no length, so only the
         * close can end it: one recv that waits out the timeout. */
        if (c[k].open && late_recvs != (c[k].open == 2)) {
            fprintf(stderr, "check_rci: %s: %d recv after the answer\n", c[k].what, late_recvs);
            assert(0);
        }
        assert(strncmp(request, want_req, sizeof(want_req) - 1) == 0);
    }
    chunk = 5;
    g_auth_stale = 0;

    /* A header line longer than the reader takes is no answer either. */
    {
        static char longline[1600];
        int n = snprintf(longline, sizeof(longline), "HTTP/1.1 404 Not Found\r\nServer: ");
        memset(longline + n, 'a', 1100);
        n += 1100;
        n += snprintf(longline + n, sizeof(longline) - (size_t)n, "\r\nContent-Length: 0\r\n\r\n");
        char mark[16];
        serve(longline, (size_t)n, 0, 0);
        assert(rci_get_policy_mark("HydraRoute", mark, sizeof(mark)) == RCI_MARK_TRANSPORT);
    }

    /* The auth probe and policy creation take no broken header block as an
     * answer, however the reply is split. */
    for (size_t i = 0; i < 4; i++) {
        static const char names[1][64] = {"HydraRoute"};
        chunk = splits[i];
        serve(BYTES("HTTP/1.1 200 OK\nContent-Length: 20\r\n\r\n{}"), 0, 0);
        assert(rci_probe(0) == 0);
        serve(BYTES("HTTP/1.1 200 OK\r\nServer: ndm\nTransfer-Encoding: chunked\r\n\r\n{}"), 0, 0);
        assert(rci_probe(0) == 0);
        serve(BYTES("HTTP/1.1 200 OK\nContent-Length: 40\r\n\r\n[]"), 0, 0);
        assert(rci_create_policies(names, 1) == -1);
        serve(BYTES("HTTP/1.1 200 OK\r\nServer: ndm\nTransfer-Encoding: chunked\r\n\r\n[]"), 0, 0);
        assert(rci_create_policies(names, 1) == -1);
    }
    chunk = 5;
    g_auth_stale = 0;

    /* The auth probe sees a status only in a whole answer with a real
     * status code and supported framing; otherwise 0, "no answer". */
    serve(BYTES("HTTP/1.1 200 OK\r\nContent-Length: 20\r\n\r\n{\"title\":"), ECONNRESET, 0);
    assert(rci_probe(0) == 0);
    serve(BYTES("HTTP/1.1 -200 OK\r\n\r\n{}"), 0, 0);
    assert(rci_probe(0) == 0);
    serve(BYTES("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n20\r\n{\"title\""), 0, 0);
    assert(rci_probe(0) == 0);
    serve(BYTES("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}"), 0, 1);
    assert(rci_probe(0) == 200 && late_recvs == 0);
    serve(BYTES("HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n"), 0, 0);
    assert(rci_probe(0) == 401);
    g_auth_stale = 0;

    /* Policy creation succeeds only on a whole 200. */
    {
        static const char names[1][64] = {"HydraRoute"};
        serve(BYTES("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n[]"), 0, 1);
        assert(rci_create_policies(names, 1) == 0 && late_recvs == 0);
        static const char post_req[] = "POST /rci/ HTTP/1.0\r\n";
        assert(strncmp(request, post_req, sizeof(post_req) - 1) == 0);
        serve(BYTES("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n["), 0, 0);
        assert(rci_create_policies(names, 1) == -1);
        serve(BYTES("HTTP/1.1 200 OK\r\nContent-Length: 40\r\n\r\n[{\"ip\""), ECONNRESET, 0);
        assert(rci_create_policies(names, 1) == -1);
    }
}

int main(void) {
    config_t quiet;                     /* the WARNs of the failure cases go nowhere */
    memset(&quiet, 0, sizeof(quiet));
    strcpy(quiet.log_level, "file");
    strcpy(quiet.log_file_path, "/dev/null");
    assert(log_setup(&quiet) == 0);
    check_strip_ansi();
    check_parse_token_value();
    check_collect_token_ids();
    check_token_send_rules();
    check_policy_mark_answers();
    printf("check_rci: OK\n");
    return 0;
}
