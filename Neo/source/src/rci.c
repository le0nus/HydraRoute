#include "../include/rci.h"
#include "../include/log.h"
#include "../include/util.h"
#include "../include/config.h"
#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define RCI_RAW_MAX      32768
#define RCI_LINE_MAX     1024           /* longest status or header line read */
#define RCI_ERR_TRANSPORT (-1)
#define RCI_ERR_DENIED    (-2)
#define RCI_ERR_HTTP      (-3)

#define RCI_PROBE_PATH   "/rci/show/version"
#define RCI_RECOVER_MIN_SEC 10

#define NDMC_PATH        "/bin/ndmc"
#define NDMC_OUT_MAX     8192
#define TOKEN_LABEL      "HydraRoute"
#define TOKEN_MIN_LEN    16
#define TOKEN_MAX_OWNED  16

static char g_rci_token[MAX_RCI_TOKEN];
static rci_mode_t g_mode = RCI_MODE_LOCAL;
static int g_auth_stale;
static int g_mode_logged;
static time_t g_last_recover;

void rci_set_token(const char *token) {
    int j = 0;
    if (token) {
        for (int i = 0; token[i] && j < MAX_RCI_TOKEN - 1; i++) {
            unsigned char ch = (unsigned char)token[i];
            if (ch <= 0x20 || ch >= 0x7f) break;
            g_rci_token[j++] = (char)ch;
        }
        if (token[j] != '\0')
            LOG_WARN("rciToken truncated at unsupported character, using first %d chars", j);
    }
    g_rci_token[j] = '\0';
    g_mode = g_rci_token[0] ? RCI_MODE_TOKEN : RCI_MODE_LOCAL;
}

rci_mode_t rci_mode(void) {
    return g_mode;
}

static int rci_should_send_token(void) {
    return g_rci_token[0] && g_mode != RCI_MODE_LOCAL && g_mode != RCI_MODE_TOKEN_REQUIRED;
}

static int rci_connect(void) {
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;

    struct timeval tv = { .tv_sec = RCI_TIMEOUT_SEC };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(RCI_PORT);
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

/* Where the header block of raw[0..total) ends: just past its first
 * CRLFCRLF, or -1 while it has not arrived. raw[0..from) is known to hold
 * none, so only the bytes that came since are scanned. */
static int head_end(const char *raw, int from, int total) {
    for (int i = from > 3 ? from - 3 : 0; i + 4 <= total; i++)
        if (memcmp(raw + i, "\r\n\r\n", 4) == 0) return i + 4;
    return -1;
}

static int header_is(const char *line, int name_len, const char *name) {
    return name_len == (int)strlen(name) && strncasecmp(line, name, (size_t)name_len) == 0;
}

/* The header block raw[0..head), read strictly (Ruling 36): the status line
 * "HTTP/1.x NNN[ reason]", then "Name: value" lines with a token name; each
 * line ends in CRLF, none is longer than RCI_LINE_MAX, and the block has no
 * other CR or LF and no NUL. Sets the status and how the body ends: its
 * Content-Length, -1 if there is none (the body ends where the connection
 * closes), -2 for framing hrneo does not read (Ruling 35): any
 * Transfer-Encoding (an HTTP/1.0 client must not get chunked), a
 * Content-Length that is not a number or comes twice. Returns 0, or -1 when
 * the block is broken: then nothing in it can be trusted, the framing least. */
static int parse_head(const char *raw, int head, int *status, long *length) {
    *length = -1;
    for (int i = 0; i < head; i++) {
        char ch = raw[i];
        if (ch == '\0' || (ch == '\r' && raw[i + 1] != '\n') ||
            (ch == '\n' && (i == 0 || raw[i - 1] != '\r')))
            return -1;
    }
    const char *line = raw;
    for (int n = 0; line < raw + head - 2; n++) {
        const char *eol = memchr(line, '\r', (size_t)(raw + head - line));
        int len = (int)(eol - line);
        if (len > RCI_LINE_MAX) return -1;
        if (n == 0) {
            if (len < 12 || memcmp(line, "HTTP/1.", 7) != 0 || !isdigit((unsigned char)line[7]) ||
                line[8] != ' ' || line[9] < '1' || line[9] > '5' ||
                !isdigit((unsigned char)line[10]) || !isdigit((unsigned char)line[11]) ||
                (len > 12 && line[12] != ' '))
                return -1;
            *status = (line[9] - '0') * 100 + (line[10] - '0') * 10 + (line[11] - '0');
        } else {
            int name = 0;
            while (name < len && (isalnum((unsigned char)line[name]) ||
                                  strchr("!#$%&'*+-.^_`|~", line[name])))
                name++;
            if (name == 0 || name == len || line[name] != ':') return -1;
            if (header_is(line, name, "Transfer-Encoding")) {
                *length = -2;
            } else if (header_is(line, name, "Content-Length")) {
                const char *v = line + name + 1, *end = line + len;
                long value = 0;
                while (v < end && (*v == ' ' || *v == '\t')) v++;
                if (v == end || !isdigit((unsigned char)*v) || *length != -1) {
                    *length = -2;
                } else {
                    for (; v < end && isdigit((unsigned char)*v); v++)
                        value = value < RCI_RAW_MAX ? value * 10 + (*v - '0') : RCI_RAW_MAX;
                    while (v < end && (*v == ' ' || *v == '\t')) v++;
                    *length = v == end ? value : -2;
                }
            }
        }
        line = eol + 2;
    }
    return 0;
}

static int rci_request_ex(const char *method, const char *path,
                          const char *body, int body_len,
                          char *response, int response_max,
                          int use_token, int *http_status) {
    if (http_status) *http_status = 0;

    int fd = rci_connect();
    if (fd < 0) {
        LOG_ERROR("RCI connect failed: %s", strerror(errno));
        return RCI_ERR_TRANSPORT;
    }

    char tkn_hdr[MAX_RCI_TOKEN + 24];
    if (use_token && g_rci_token[0])
        snprintf(tkn_hdr, sizeof(tkn_hdr), "X-NDMA-TKN: %s\r\n", g_rci_token);
    else
        tkn_hdr[0] = '\0';

    char header[MAX_RCI_TOKEN + 512];
    int hlen;
    if (body && body_len > 0) {
        hlen = snprintf(header, sizeof(header),
            "%s %s HTTP/1.0\r\n"
            "Host: 127.0.0.1\r\n"
            "%s"
            "Content-Type: application/json\r\n"
            "Content-Length: %d\r\n"
            "\r\n",
            method, path, tkn_hdr, body_len);
    } else {
        hlen = snprintf(header, sizeof(header),
            "%s %s HTTP/1.0\r\n"
            "Host: 127.0.0.1\r\n"
            "%s"
            "\r\n",
            method, path, tkn_hdr);
    }

    if (send(fd, header, hlen, 0) != hlen) {
        close(fd);
        return RCI_ERR_TRANSPORT;
    }

    if (body && body_len > 0) {
        int total = 0;
        while (total < body_len) {
            int n = send(fd, body + total, body_len - total, 0);
            if (n <= 0) { close(fd); return RCI_ERR_TRANSPORT; }
            total += n;
        }
    }

    /* Only a whole answer counts: its body as long as Content-Length says,
     * or without one, everything up to the close of the connection with no
     * receive error or timeout and within the buffer. Reading stops as soon
     * as the body has its length, so a peer that keeps the connection open
     * costs no wait, and at once on framing that is not read (Ruling 35). */
    static char raw[RCI_RAW_MAX];
    long length = -1;
    int total = 0, eof = 0, head = -1, status = 0, broken = 0;
    int max_raw = (int)sizeof(raw) - 1;
    while (total < max_raw) {
        int n = recv(fd, raw + total, max_raw - total, 0);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) {
            eof = n == 0;
            break;
        }
        total += n;
        raw[total] = '\0';
        if (head < 0 && (head = head_end(raw, total - n, total)) >= 0)
            broken = parse_head(raw, head, &status, &length) != 0;
        if (head >= 0 && (broken || length == -2 || (length >= 0 && total - head >= length)))
            break;
    }
    raw[total] = '\0';
    close(fd);

    if (head < 0 || broken || length == -2 || (length >= 0 && length != total - head) ||
        (length == -1 && !eof))
        return RCI_ERR_TRANSPORT;
    const char *body_start = raw + head;
    if (http_status) *http_status = status;

    if (status == 401 || status == 403) {
        g_auth_stale = 1;
        return RCI_ERR_DENIED;
    }
    if (status != 200) return RCI_ERR_HTTP;

    int response_len = total - (int)(body_start - raw);
    if (response_len > response_max - 1) response_len = response_max - 1;
    memcpy(response, body_start, response_len);
    response[response_len] = '\0';

    return response_len;
}

static int rci_request(const char *method, const char *path,
                       const char *body, int body_len,
                       char *response, int response_max) {
    return rci_request_ex(method, path, body, body_len, response, response_max,
                          rci_should_send_token(), NULL);
}

static int rci_probe(int use_token) {
    char response[512];
    int status = 0;
    rci_request_ex("GET", RCI_PROBE_PATH, NULL, 0, response, sizeof(response),
                   use_token, &status);
    return status;
}

static void rci_log_mode(void) {
    switch (g_mode) {
    case RCI_MODE_LOCAL:
        if (g_rci_token[0])
            LOG_WARN("Router rejected rciToken, falling back to unauthenticated RCI "
                     "while the firmware still allows it");
        else
            LOG_INFO("RCI accepts unauthenticated local requests, token not needed");
        break;
    case RCI_MODE_TOKEN:
        LOG_INFO("RCI authenticated with X-NDMA-TKN");
        break;
    case RCI_MODE_TOKEN_REQUIRED:
        LOG_ERROR("RCI requires an access token but rciToken is empty");
        break;
    case RCI_MODE_BLOCKED:
        LOG_ERROR("RCI requires an access token and the current rciToken is rejected");
        break;
    }
}

rci_mode_t rci_resolve_auth(void) {
    rci_mode_t before = g_mode;
    g_auth_stale = 0;

    if (g_rci_token[0] == '\0') {
        int status = rci_probe(0);
        if (status == 0) { g_auth_stale = 1; return g_mode; }
        g_mode = (status == 200) ? RCI_MODE_LOCAL : RCI_MODE_TOKEN_REQUIRED;
    } else {
        int status = rci_probe(1);
        if (status == 0) { g_auth_stale = 1; return g_mode; }
        if (status == 200) {
            g_mode = RCI_MODE_TOKEN;
        } else {
            int plain = rci_probe(0);
            if (plain == 0) { g_auth_stale = 1; return g_mode; }
            g_mode = (plain == 200) ? RCI_MODE_LOCAL : RCI_MODE_BLOCKED;
        }
    }

    if (g_mode != before || !g_mode_logged) {
        rci_log_mode();
        g_mode_logged = 1;
    }
    return g_mode;
}

static int token_char(unsigned char c) {
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
           c == '+' || c == '/' || c == '=' || c == '-' || c == '_';
}

static void strip_ansi(const char *in, char *out, int out_size) {
    int j = 0;
    for (int i = 0; in[i] && j < out_size - 1; i++) {
        if ((unsigned char)in[i] == 0x1b) {
            if (in[i + 1] == '[') {
                i += 2;
                while (in[i] && !((unsigned char)in[i] >= 0x40 && (unsigned char)in[i] <= 0x7e)) i++;
                if (!in[i]) break;
            }
            continue;
        }
        out[j++] = in[i];
    }
    out[j] = '\0';
}

static int ndmc_exec(const char *command, char *out, int out_size) {
    char *argv[] = { (char *)NDMC_PATH, (char *)"-c", (char *)command, NULL };
    out[0] = '\0';
    return run_command_output(NDMC_PATH, argv, out, (size_t)out_size);
}

static const char *line_field(const char *line, const char *key) {
    while (*line == ' ' || *line == '\t') line++;
    size_t klen = strlen(key);
    if (strncmp(line, key, klen) != 0) return NULL;
    line += klen;
    while (*line == ' ' || *line == '\t') line++;
    return line;
}

static int ndmc_parse_token_value(const char *text, char *token, int token_size) {
    for (const char *line = text; *line; ) {
        const char *value = line_field(line, "value:");
        if (value) {
            while (*value == '\r' || *value == '\n' || *value == ' ' || *value == '\t') value++;
            int n = 0;
            while (n < token_size - 1 && token_char((unsigned char)value[n])) n++;
            if (n < TOKEN_MIN_LEN) return 0;
            memcpy(token, value, n);
            token[n] = '\0';
            return 1;
        }
        const char *nl = strchr(line, '\n');
        if (!nl) break;
        line = nl + 1;
    }
    return 0;
}

static void copy_word(const char *src, char *buf, int buf_size) {
    int n = 0;
    while (n < buf_size - 1 && src[n] && src[n] != ' ' && src[n] != '\t' &&
           src[n] != '\r' && src[n] != '\n') n++;
    memcpy(buf, src, (size_t)n);
    buf[n] = '\0';
}

static int ndmc_collect_token_ids(const char *text, const char *label, int *ids, int max_ids) {
    int count = 0;
    int current = 0;

    for (const char *line = text; *line && count < max_ids; ) {
        const char *nl = strchr(line, '\n');
        int len = nl ? (int)(nl - line) : (int)strlen(line);

        char buf[160];
        if (len > 0 && len < (int)sizeof(buf)) {
            memcpy(buf, line, (size_t)len);
            buf[len] = '\0';

            char word[80];
            const char *field = line_field(buf, "user-data:");
            if (field) {
                copy_word(field, word, sizeof(word));
                if (current > 0 && strcmp(word, label) == 0) ids[count++] = current;
            } else if ((field = line_field(buf, "id:")) != NULL) {
                copy_word(field, word, sizeof(word));
                current = atoi(word);
            }
        }

        if (!nl) break;
        line = nl + 1;
    }
    return count;
}

static int rci_rotate_token(const char *config_path) {
    static char raw[NDMC_OUT_MAX];
    static char clean[NDMC_OUT_MAX];
    int ids[TOKEN_MAX_OWNED];
    int owned = 0;

    if (ndmc_exec("show authentication token", raw, sizeof(raw)) == 0) {
        strip_ansi(raw, clean, sizeof(clean));
        owned = ndmc_collect_token_ids(clean, TOKEN_LABEL, ids, TOKEN_MAX_OWNED);
    } else {
        LOG_WARN("ndmc: cannot list access tokens");
    }

    for (int i = 0; i < owned; i++) {
        char command[64];
        snprintf(command, sizeof(command), "authentication token delete %d", ids[i]);
        if (ndmc_exec(command, raw, sizeof(raw)) != 0)
            LOG_WARN("ndmc: failed to delete stale token %d", ids[i]);
        else
            LOG_INFO("Deleted stale RCI token %d", ids[i]);
    }

    if (ndmc_exec("authentication token generate " TOKEN_LABEL, raw, sizeof(raw)) != 0) {
        LOG_ERROR("ndmc: token generation failed");
        return -1;
    }

    strip_ansi(raw, clean, sizeof(clean));
    char token[MAX_RCI_TOKEN];
    if (!ndmc_parse_token_value(clean, token, sizeof(token))) {
        LOG_ERROR("ndmc: cannot parse generated token");
        return -1;
    }

    switch (config_set_keenetic_token(config_path, token)) {
    case KTOKEN_ADDED:
    case KTOKEN_UPDATED:
    case KTOKEN_UNCHANGED:
        LOG_INFO("Generated a new Keenetic RCI token, stored in %s", config_path);
        break;
    default:
        LOG_ERROR("Generated a Keenetic RCI token but failed to store it in %s, "
                  "it will be regenerated on next start", config_path);
        break;
    }

    rci_set_token(token);
    ndmc_exec("system configuration save", raw, sizeof(raw));
    return 0;
}

int rci_token_bootstrap(const char *config_path) {
    rci_mode_t mode = rci_resolve_auth();
    if (g_auth_stale) {
        LOG_WARN("RCI is not answering yet, authentication check deferred");
        return -1;
    }
    if (mode == RCI_MODE_LOCAL || mode == RCI_MODE_TOKEN) return 0;

    if (rci_rotate_token(config_path) != 0) return -1;

    mode = rci_resolve_auth();
    if (mode != RCI_MODE_TOKEN) {
        LOG_ERROR("Freshly generated RCI token is not accepted by the router");
        return -1;
    }
    return 0;
}

int rci_auth_recover(const char *config_path) {
    if (!g_auth_stale && g_mode != RCI_MODE_TOKEN_REQUIRED && g_mode != RCI_MODE_BLOCKED)
        return 0;

    time_t now = time(NULL);
    if (now - g_last_recover < RCI_RECOVER_MIN_SEC) return -1;
    g_last_recover = now;

    return rci_token_bootstrap(config_path);
}

/* The body of a mark answer, all len bytes of it: one JSON string,
 * "ffffaaa" (1..8 hex digits, "0x" allowed, not 0), or "" for a policy
 * without a mark yet. Returns RCI_MARK_OK, RCI_MARK_ABSENT for "",
 * RCI_MARK_TRANSPORT for anything else. */
static int parse_mark(const char *body, int len, char *mark, int mark_size) {
    const char *p = body;
    int prefix = 0, nonzero = 0;
    if (memchr(body, '\0', (size_t)len)) return RCI_MARK_TRANSPORT;  /* would hide what follows */
    while (isspace((unsigned char)*p)) p++;
    if (*p++ != '"') return RCI_MARK_TRANSPORT;
    if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) {
        p += 2;
        prefix = 1;
    }
    const char *digits = p;
    for (; isxdigit((unsigned char)*p); p++)
        if (*p != '0') nonzero = 1;
    int n = (int)(p - digits);
    if (*p++ != '"') return RCI_MARK_TRANSPORT;
    while (isspace((unsigned char)*p)) p++;
    if (*p != '\0') return RCI_MARK_TRANSPORT;
    if (n == 0) return prefix ? RCI_MARK_TRANSPORT : RCI_MARK_ABSENT;
    if (n > 8 || n > mark_size - 1 || !nonzero) return RCI_MARK_TRANSPORT;
    memcpy(mark, digits, (size_t)n);
    mark[n] = '\0';
    return RCI_MARK_OK;
}

/* RCI_MARK_ABSENT only on a whole answer that says the policy has no mark:
 * 404 (no such policy; Keenetic answers this path so) or "" (no mark yet).
 * Another status, a cut answer or one that is not a mark is no answer
 * (RCI_MARK_TRANSPORT): the caller keeps the mark it knows (Ruling 33). */
int rci_get_policy_mark(const char *name, char *mark, int mark_size) {
    char path[160];
    snprintf(path, sizeof(path), "/rci/show/ip/policy/%s/mark", name);

    char response[256];
    int status = 0;
    int len = rci_request_ex("GET", path, NULL, 0, response, sizeof(response),
                             rci_should_send_token(), &status);
    if (len == RCI_ERR_DENIED) return RCI_MARK_DENIED;
    if (len == RCI_ERR_HTTP && status == 404) return RCI_MARK_ABSENT;
    if (len < 0 || len >= (int)sizeof(response) - 1) {
        LOG_DEBUG("RCI policy: %s: no whole answer (HTTP %d)", name, status);
        return RCI_MARK_TRANSPORT;
    }
    int r = parse_mark(response, len, mark, mark_size);
    if (r == RCI_MARK_OK) LOG_DEBUG("RCI policy: %s mark=0x%s", name, mark);
    else if (r == RCI_MARK_TRANSPORT) LOG_DEBUG("RCI policy: %s: not a mark: %.32s", name, response);
    return r;
}

#define RCI_POLICY_CREATE_FMT "{\"ip\":{\"policy\":{\"%s\":{\"description\":\"%s\"}}}},"

int rci_create_policies(const char (*names)[64], int count) {
    if (count == 0) return 0;

    char body[MAX_POLICY_ORDER * (sizeof(RCI_POLICY_CREATE_FMT) + 2 * 64) + 64];
    int off = snprintf(body, sizeof(body), "[");
    for (int i = 0; i < count; i++) {
        off += snprintf(body + off, sizeof(body) - off,
                        RCI_POLICY_CREATE_FMT, names[i], names[i]);
    }
    off += snprintf(body + off, sizeof(body) - off,
                    "{\"system\":{\"configuration\":{\"save\":true}}}]");

    char response[4096];
    int ret = rci_request("POST", "/rci/", body, off, response, sizeof(response));
    if (ret == RCI_ERR_DENIED) {
        LOG_ERROR("RCI denied policy creation: access token required or rejected");
        return -1;
    }
    if (ret < 0) {
        LOG_WARN("Failed to create policies via RCI");
        return -1;
    }
    LOG_INFO("Policy creation commands executed");
    return 0;
}
