#include "../include/ipset_nl.h"
#include "../include/log.h"
#include "../include/util.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <linux/netlink.h>
#include <linux/netfilter/nfnetlink.h>

static void ipset_add_to_cache(ipset_manager_t *mgr, const char *name);

static void put_u32_network(uint8_t *buf, uint32_t val) {
    buf[0] = (val >> 24) & 0xFF;
    buf[1] = (val >> 16) & 0xFF;
    buf[2] = (val >>  8) & 0xFF;
    buf[3] =  val        & 0xFF;
}

static int nla_put_u8(uint8_t *buf, uint16_t type, uint8_t val) {
    uint16_t nla_len = NLA_HDRLEN + 1;
    memcpy(buf, &nla_len, 2);
    memcpy(buf + 2, &type, 2);
    buf[NLA_HDRLEN] = val;
    return NLA_ALIGN(nla_len);
}

static int nla_put_string(uint8_t *buf, uint16_t type, const char *str) {
    int slen = strlen(str) + 1;
    uint16_t nla_len = NLA_HDRLEN + slen;
    memcpy(buf, &nla_len, 2);
    memcpy(buf + 2, &type, 2);
    memcpy(buf + NLA_HDRLEN, str, slen);
    return NLA_ALIGN(nla_len);
}

static int nla_put_raw(uint8_t *buf, uint16_t type, const uint8_t *data, int data_len) {
    uint16_t nla_len = NLA_HDRLEN + data_len;
    memcpy(buf, &nla_len, 2);
    memcpy(buf + 2, &type, 2);
    memcpy(buf + NLA_HDRLEN, data, data_len);
    return NLA_ALIGN(nla_len);
}

/* What came instead of the answer to a request (Ruling 50). */
#define NL_LOST     (-1)    /* recv failed, or nothing came within IPSET_NL_TIMEOUT_MS (errno) */
#define NL_STEP     (-2)    /* a cut message, or one for a later request: out of step */
#define NL_PARTIAL  (-3)    /* a batch was sent only in part */

static int64_t now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/* socket + bind + SO_RCVTIMEO: the receive timeout bounds every recv, so an
 * answer the kernel never sends cannot hold up the main loop. */
static int nl_open(ipset_manager_t *mgr) {
    struct sockaddr_nl sa;
    struct timeval tv = {IPSET_NL_TIMEOUT_MS / 1000, IPSET_NL_TIMEOUT_MS % 1000 * 1000};
    const char *what = "socket";
    mgr->fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_NETFILTER);
    if (mgr->fd >= 0) {
        memset(&sa, 0, sizeof(sa));
        sa.nl_family = AF_NETLINK;
        sa.nl_pid = 0;
        what = "bind";
        if (bind(mgr->fd, (struct sockaddr *)&sa, sizeof(sa)) == 0) {
            what = "setsockopt SO_RCVTIMEO";
            if (setsockopt(mgr->fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) == 0)
                return 0;
        }
        int err = errno;
        close(mgr->fd);
        mgr->fd = -1;
        errno = err;
    }
    LOG_ERROR("netlink %s: %s", what, strerror(errno));
    return -1;
}

/* A socket left without one (a reopen that failed) gets a new one here. */
static int nl_ready(ipset_manager_t *mgr) {
    return mgr->fd >= 0 || nl_open(mgr) == 0 ? 0 : -1;
}

/* After a batch sent in part, or an answer lost, late or out of step (err:
 * the errno of a lost one), the answers on this socket can no longer be told
 * apart from the next request's: the socket is replaced, with what it holds
 * and what still comes for it, and the next request starts on an empty
 * queue. The sequence numbers go on, so an answer from before can only ever
 * be an older one. */
static void nl_reopen(ipset_manager_t *mgr, int why, int err) {
    const char *cause = why == NL_PARTIAL ? "batch sent only in part"
                      : why == NL_STEP ? "answer out of step"
                      : err == EAGAIN || err == EWOULDBLOCK || err == ETIMEDOUT
                        ? "no answer in time" : strerror(err);
    LOG_WARN("ipset netlink: %s, socket reopened", cause);
    if (mgr->fd >= 0) close(mgr->fd);
    mgr->fd = -1;
    nl_open(mgr);
}

/* Receives the answer to request seq into resp and returns its length.
 * Answers to older requests (whatever left them queued) are skipped, all
 * within IPSET_NL_TIMEOUT_MS of the call; each recv is bounded by
 * SO_RCVTIMEO. NL_LOST or NL_STEP otherwise: the caller reopens. */
static int nl_recv_answer(ipset_manager_t *mgr, uint32_t seq, uint8_t *resp, int size) {
    int64_t deadline = now_ms() + IPSET_NL_TIMEOUT_MS;
    for (;;) {
        int n = recv(mgr->fd, resp, size, 0);
        if (n < 0) {
            if (errno != EINTR) return NL_LOST;
        } else if (n < (int)NLMSG_HDRLEN) {
            return NL_STEP;
        } else {
            int32_t age = (int32_t)(seq - ((const struct nlmsghdr *)resp)->nlmsg_seq);
            if (age == 0) return n;
            if (age < 0) return NL_STEP;
        }
        if (now_ms() >= deadline) {
            errno = ETIMEDOUT;
            return NL_LOST;
        }
    }
}

/* The ACK of request seq: 0 with *error its result (0, or the positive
 * errno of the kernel), or what nl_recv_answer returned. */
static int nl_recv_ack(ipset_manager_t *mgr, uint32_t seq, int *error) {
    uint8_t resp[256];
    int n = nl_recv_answer(mgr, seq, resp, sizeof(resp));
    if (n < 0) return n;
    if (n < (int)(NLMSG_HDRLEN + sizeof(struct nlmsgerr)) ||
        ((const struct nlmsghdr *)resp)->nlmsg_type != NLMSG_ERROR)
        return NL_STEP;
    *error = -((const struct nlmsgerr *)(resp + NLMSG_HDRLEN))->error;
    return 0;
}

static int nl_send_recv_ack(ipset_manager_t *mgr, uint8_t *buf, int len) {
    if (nl_ready(mgr) != 0) return -1;
    if (send(mgr->fd, buf, len, 0) < 0) {
        LOG_ERROR("netlink send: %s", strerror(errno));
        return -1;
    }
    int error = 0;
    int rc = nl_recv_ack(mgr, ((struct nlmsghdr *)buf)->nlmsg_seq, &error);
    if (rc != 0) {
        nl_reopen(mgr, rc, errno);
        return -1;
    }
    return error;
}

int ipset_manager_init(ipset_manager_t *mgr) {
    memset(mgr, 0, sizeof(*mgr));
    if (nl_open(mgr) != 0) return -1;
    mgr->seq = 1;
    mgr->pid = getpid();
    return 0;
}

void ipset_manager_close(ipset_manager_t *mgr) {
    if (mgr->fd >= 0) close(mgr->fd);
    mgr->fd = -1;
    free(mgr->permanent.keys);
    free(mgr->permanent.incomplete);
    memset(&mgr->permanent, 0, sizeof(mgr->permanent));
}

static int ipset_query_revision(ipset_manager_t *mgr, const char *type, int family) {
    uint8_t buf[256];
    memset(buf, 0, sizeof(buf));

    struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
    nlh->nlmsg_type = (NFNL_SUBSYS_IPSET << 8) | IPSET_CMD_TYPE;
    nlh->nlmsg_flags = NLM_F_REQUEST;
    nlh->nlmsg_seq = mgr->seq++;
    nlh->nlmsg_pid = mgr->pid;

    uint8_t nf_family = (family == AF_INET6) ? 10 : 2;
    uint8_t *nfgen = buf + NLMSG_HDRLEN;
    nfgen[0] = nf_family;

    int offset = NLMSG_HDRLEN + 4;
    offset += nla_put_u8(buf + offset, IPSET_ATTR_PROTOCOL, IPSET_PROTOCOL);
    offset += nla_put_string(buf + offset, IPSET_ATTR_TYPENAME, type);
    offset += nla_put_u8(buf + offset, IPSET_ATTR_FAMILY, nf_family);
    nlh->nlmsg_len = offset;

    if (nl_ready(mgr) != 0 || send(mgr->fd, buf, offset, 0) < 0)
        return 0;

    uint8_t resp[512];
    int n = nl_recv_answer(mgr, nlh->nlmsg_seq, resp, sizeof(resp));
    if (n < 0) {
        nl_reopen(mgr, n, errno);
        return 0;
    }
    if (n < (int)(NLMSG_HDRLEN + 4))
        return 0;

    struct nlmsghdr *rnh = (struct nlmsghdr *)resp;
    if (rnh->nlmsg_type == NLMSG_ERROR)
        return 0;

    uint8_t *attrs = resp + NLMSG_HDRLEN + 4;
    int attrs_len = n - NLMSG_HDRLEN - 4;
    int pos = 0;
    while (pos + NLA_HDRLEN <= attrs_len) {
        uint16_t nla_len, nla_type;
        memcpy(&nla_len, attrs + pos, 2);
        memcpy(&nla_type, attrs + pos + 2, 2);
        if ((nla_type & ~(NLA_F_NESTED | NLA_F_NET_BYTEORDER)) == IPSET_ATTR_REVISION
                && nla_len >= (uint16_t)(NLA_HDRLEN + 1))
            return attrs[pos + NLA_HDRLEN];
        int next = NLA_ALIGN(nla_len);
        if (next <= 0 || pos + next > attrs_len)
            break;
        pos += next;
    }
    return 0;
}

static int build_create_msg(uint8_t *buf, int buf_size, ipset_manager_t *mgr,
                            const char *name, const char *type, int family,
                            uint32_t timeout, uint32_t maxelem, uint8_t revision) {
    memset(buf, 0, buf_size);

    struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
    nlh->nlmsg_type = (NFNL_SUBSYS_IPSET << 8) | IPSET_CMD_CREATE;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL;
    nlh->nlmsg_seq = mgr->seq++;
    nlh->nlmsg_pid = mgr->pid;

    uint8_t nf_family = (family == AF_INET6) ? 10 : 2;
    uint8_t *nfgen = buf + NLMSG_HDRLEN;
    nfgen[0] = nf_family;

    int offset = NLMSG_HDRLEN + 4;
    offset += nla_put_u8(buf + offset, IPSET_ATTR_PROTOCOL, IPSET_PROTOCOL);
    offset += nla_put_string(buf + offset, IPSET_ATTR_SETNAME, name);
    offset += nla_put_string(buf + offset, IPSET_ATTR_TYPENAME, type);
    offset += nla_put_u8(buf + offset, IPSET_ATTR_REVISION, revision);
    offset += nla_put_u8(buf + offset, IPSET_ATTR_FAMILY, nf_family);

    if (timeout > 0 || maxelem > 0) {
        uint8_t data_buf[32];
        int data_len = 0;
        if (timeout > 0) {
            uint8_t timeout_bytes[4];
            put_u32_network(timeout_bytes, timeout);
            data_len += nla_put_raw(data_buf + data_len,
                                    IPSET_ATTR_TIMEOUT | NLA_F_NET_BYTEORDER,
                                    timeout_bytes, 4);
        }
        if (maxelem > 0) {
            uint8_t maxelem_bytes[4];
            put_u32_network(maxelem_bytes, maxelem);
            data_len += nla_put_raw(data_buf + data_len,
                                    IPSET_ATTR_MAXELEM | NLA_F_NET_BYTEORDER,
                                    maxelem_bytes, 4);
        }
        offset += nla_put_raw(buf + offset, IPSET_ATTR_DATA | NLA_F_NESTED,
                                 data_buf, data_len);
    }

    nlh->nlmsg_len = offset;
    return offset;
}


int ipset_create(ipset_manager_t *mgr, const char *name, const char *type, int family, uint32_t timeout, uint32_t maxelem) {
    uint8_t revision = (uint8_t)ipset_query_revision(mgr, type, family);

    LOG_DEBUG("Netlink CREATE: set=%s type=%s family=%d timeout=%u revision=%u",
              name, type, family, timeout, revision);

    uint8_t buf[512];
    int msg_len = build_create_msg(buf, sizeof(buf), mgr, name, type, family,
                                   timeout, maxelem, revision);
    int ret = nl_send_recv_ack(mgr, buf, msg_len);

    if (ret == 17) {
        LOG_DEBUG("Set %s already exists", name);
        ipset_add_to_cache(mgr, name);
        return 0;
    }
    if (ret != 0) {
        LOG_ERROR("Netlink CREATE error for %s: errno=%d", name, ret);
        return ret;
    }

    LOG_DEBUG("Set %s created", name);
    ipset_add_to_cache(mgr, name);
    return 0;
}

int ipset_flush(ipset_manager_t *mgr, const char *name) {
    uint8_t buf[256];
    memset(buf, 0, sizeof(buf));

    struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
    nlh->nlmsg_type = (NFNL_SUBSYS_IPSET << 8) | IPSET_CMD_FLUSH;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    nlh->nlmsg_seq = mgr->seq++;
    nlh->nlmsg_pid = mgr->pid;

    uint8_t *nfgen = buf + NLMSG_HDRLEN;
    nfgen[0] = 2;

    int offset = NLMSG_HDRLEN + 4;
    offset += nla_put_u8(buf + offset, IPSET_ATTR_PROTOCOL, IPSET_PROTOCOL);
    offset += nla_put_string(buf + offset, IPSET_ATTR_SETNAME, name);

    nlh->nlmsg_len = offset;

    LOG_DEBUG("Netlink FLUSH: set=%s", name);

    int ret = nl_send_recv_ack(mgr, buf, offset);
    if (ret != 0) {
        LOG_DEBUG("Netlink FLUSH error: errno=%d", ret);
        return ret;
    }

    LOG_DEBUG("Netlink success: set %s flushed", name);
    return 0;
}

static int build_ipset_add_msg(uint8_t *buf, int buf_size, ipset_manager_t *mgr,
                               const char *set_name_nul, int set_name_len,
                               const parsed_cidr_t *entry,
                               int has_timeout, const uint8_t *timeout_bytes,
                               uint16_t extra_flags) {
    memset(buf, 0, buf_size > 256 ? 256 : buf_size);

    struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
    nlh->nlmsg_type = (NFNL_SUBSYS_IPSET << 8) | IPSET_CMD_ADD;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | extra_flags;
    nlh->nlmsg_seq = mgr->seq++;
    nlh->nlmsg_pid = mgr->pid;

    uint8_t *nfgen = buf + NLMSG_HDRLEN;
    nfgen[0] = 2;

    int offset = NLMSG_HDRLEN + 4;
    offset += nla_put_u8(buf + offset, IPSET_ATTR_PROTOCOL, IPSET_PROTOCOL);

    {
        uint16_t nla_len_val = NLA_HDRLEN + set_name_len;
        uint16_t nla_type_val = IPSET_ATTR_SETNAME;
        memcpy(buf + offset, &nla_len_val, 2);
        memcpy(buf + offset + 2, &nla_type_val, 2);
        memcpy(buf + offset + NLA_HDRLEN, set_name_nul, set_name_len);
        offset += NLA_ALIGN(nla_len_val);
    }

    uint8_t data_buf[64];
    int data_len = 0;

    {
        uint8_t ip_buf[32];
        int ip_len = 0;
        if (entry->family == AF_INET) {
            uint16_t attr_type = IPSET_ATTR_IPADDR_IPV4 | NLA_F_NET_BYTEORDER;
            uint16_t attr_len = NLA_HDRLEN + 4;
            memcpy(ip_buf + ip_len, &attr_len, 2);
            memcpy(ip_buf + ip_len + 2, &attr_type, 2);
            memcpy(ip_buf + ip_len + NLA_HDRLEN, entry->ip, 4);
            ip_len += NLA_ALIGN(attr_len);
        } else {
            uint16_t attr_type = IPSET_ATTR_IPADDR_IPV6 | NLA_F_NET_BYTEORDER;
            uint16_t attr_len = NLA_HDRLEN + 16;
            memcpy(ip_buf + ip_len, &attr_len, 2);
            memcpy(ip_buf + ip_len + 2, &attr_type, 2);
            memcpy(ip_buf + ip_len + NLA_HDRLEN, entry->ip, 16);
            ip_len += NLA_ALIGN(attr_len);
        }

        data_len += nla_put_raw(data_buf + data_len, IPSET_ATTR_IP | NLA_F_NESTED,
                                   ip_buf, ip_len);
    }

    data_len += nla_put_u8(data_buf + data_len, IPSET_ATTR_CIDR, entry->prefix);

    if (has_timeout) {
        data_len += nla_put_raw(data_buf + data_len,
                                IPSET_ATTR_TIMEOUT | NLA_F_NET_BYTEORDER,
                                timeout_bytes, 4);
    }

    offset += nla_put_raw(buf + offset, IPSET_ATTR_DATA | NLA_F_NESTED,
                             data_buf, data_len);

    nlh->nlmsg_len = offset;
    return offset;
}

static int is_service_ip(const uint8_t *ip, int family) {
    if (family == AF_INET) {
        return (ip[0] == 0 || ip[0] == 127);
    }
    static const uint8_t zeros[16] = {0};
    static const uint8_t loopback[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1};
    return (memcmp(ip, zeros, 16) == 0 || memcmp(ip, loopback, 16) == 0);
}

_Static_assert(sizeof(ipset_perm_key_t) == 81, "permanent key has no padding");

/* CIDR lists add their entries without timeout, i.e. permanently. A host entry
 * (/32, /128) is the same set element as a DNS-learned IP, and refreshing that
 * IP would give it IpsetTimeout, so such entries are remembered per set. */
static int perm_key(ipset_perm_key_t *k, const char *set_name, const parsed_cidr_t *entry) {
    size_t ip_len = entry->family == AF_INET ? 4 : 16;
    if (entry->prefix != (uint32_t)ip_len * 8) return 0;
    memset(k, 0, sizeof(*k));
    snprintf(k->set, sizeof(k->set), "%s", set_name);
    k->family = (uint8_t)entry->family;
    memcpy(k->ip, entry->ip, ip_len);
    return 1;
}

static int perm_cmp(const void *a, const void *b) {
    return memcmp(a, b, sizeof(ipset_perm_key_t));
}

int ipset_perm_incomplete(const ipset_manager_t *mgr, const char *set_name) {
    const ipset_perm_t *p = &mgr->permanent;
    if (p->all_incomplete) return 1;
    for (size_t i = 0; i < p->incomplete_count; i++)
        if (strncmp(p->incomplete[i], set_name, 63) == 0) return 1;
    return 0;
}

static void perm_mark_all_incomplete(ipset_manager_t *mgr) {
    if (mgr->permanent.all_incomplete) return;
    mgr->permanent.all_incomplete = 1;
    LOG_WARN("permanent-host index incomplete for all sets: refresh disabled");
}

void ipset_perm_mark_incomplete(ipset_manager_t *mgr, const char *set_name) {
    ipset_perm_t *p = &mgr->permanent;
    if (ipset_perm_incomplete(mgr, set_name)) return;
    if (p->incomplete_count >= SIZE_MAX / 64 - 1) {
        perm_mark_all_incomplete(mgr);
        return;
    }
    char (*names)[64] = realloc(p->incomplete, (p->incomplete_count + 1) * 64);
    if (!names) {
        /* Cannot even remember the name: the safe side is every set. */
        perm_mark_all_incomplete(mgr);
        return;
    }
    p->incomplete = names;
    snprintf(p->incomplete[p->incomplete_count++], 64, "%s", set_name);
    LOG_WARN("permanent-host index incomplete for %s: refresh disabled", set_name);
}

static void remember_permanent(ipset_manager_t *mgr, const char *set_name,
                               const parsed_cidr_t *entry) {
    ipset_perm_t *p = &mgr->permanent;
    ipset_perm_key_t k;
    if (!perm_key(&k, set_name, entry)) return;
    if (p->count == p->cap) {
        size_t cap = p->cap ? p->cap * 2 : 4;
        if (p->cap > SIZE_MAX / 2 || cap > SIZE_MAX / sizeof(*p->keys)) {
            ipset_perm_mark_incomplete(mgr, set_name);
            return;
        }
        ipset_perm_key_t *keys = realloc(p->keys, cap * sizeof(*keys));
        if (!keys) {
            ipset_perm_mark_incomplete(mgr, set_name);
            return;
        }
        p->keys = keys;
        p->cap = cap;
    }
    p->keys[p->count++] = k;
    p->sorted = 0;
}

/* Sorts after appends and drops repeated keys (the same list loaded twice,
 * a host listed twice) in place, so a lookup is one halving over unique keys. */
static void perm_sort(ipset_perm_t *p) {
    qsort(p->keys, p->count, sizeof(*p->keys), perm_cmp);
    size_t n = 0;
    for (size_t i = 0; i < p->count; i++)
        if (n == 0 || perm_cmp(&p->keys[n - 1], &p->keys[i]) != 0)
            p->keys[n++] = p->keys[i];
    p->count = n;
    p->sorted = 1;
}

static int is_permanent(ipset_manager_t *mgr, const char *set_name,
                        const parsed_cidr_t *entry) {
    ipset_perm_t *p = &mgr->permanent;
    ipset_perm_key_t k;
    if (p->count == 0 || !perm_key(&k, set_name, entry)) return 0;
    if (!p->sorted) perm_sort(p);
    return bsearch(&k, p->keys, p->count, sizeof(*p->keys), perm_cmp) != NULL;
}

int ipset_add_batch(ipset_manager_t *mgr, const char *set_name,
                    const parsed_cidr_t *entries, int count,
                    int with_timeout, int *new_count, int *new_indices) {
    if (count == 0) return 0;

    int has_timeout = mgr->default_timeout > 0;

    uint8_t timeout_bytes[4] = {0};
    if (has_timeout && with_timeout) {
        put_u32_network(timeout_bytes, mgr->default_timeout);
    }

    uint16_t excl_flag = with_timeout ? NLM_F_EXCL : 0;

    char set_name_nul[64];
    int set_name_len = snprintf(set_name_nul, sizeof(set_name_nul), "%s", set_name) + 1;

    *new_count = 0;
    int result = 0;

    for (int start = 0; start < count; start += IPSET_CHUNK_SIZE) {
        int end = start + IPSET_CHUNK_SIZE;
        if (end > count) end = count;

        uint8_t msg_bufs[IPSET_CHUNK_SIZE][256];
        int msg_lens[IPSET_CHUNK_SIZE];
        int valid_indices[IPSET_CHUNK_SIZE];
        int msg_count = 0;

        for (int i = start; i < end; i++) {
            if (is_service_ip(entries[i].ip, entries[i].family)) {
                LOG_FILTERED("Service IP rejected (family=%d)", entries[i].family);
                continue;
            }

            msg_lens[msg_count] = build_ipset_add_msg(
                msg_bufs[msg_count], sizeof(msg_bufs[msg_count]),
                mgr, set_name_nul, set_name_len,
                &entries[i],
                has_timeout, timeout_bytes,
                excl_flag);
            valid_indices[msg_count] = i;
            msg_count++;
        }

        if (msg_count == 0) continue;

        if (nl_ready(mgr) != 0) {
            if (!with_timeout) ipset_perm_mark_incomplete(mgr, set_name_nul);
            return -1;
        }
        int sent = 0;
        while (sent < msg_count && send(mgr->fd, msg_bufs[sent], msg_lens[sent], 0) >= 0)
            sent++;
        if (sent < msg_count)
            LOG_ERROR("netlink send batch: %s", strerror(errno));

        int refresh[IPSET_CHUNK_SIZE];
        int refresh_count = 0;

        /* The answers come in the order of the requests, each with its
         * sequence. One that is lost or out of step leaves the rest unknown. */
        int answered = 0, rc = sent < msg_count ? NL_PARTIAL : 0, lost_errno = 0;
        for (; answered < sent; answered++) {
            int i = answered, error = 0;
            int r = nl_recv_ack(mgr, ((struct nlmsghdr *)msg_bufs[i])->nlmsg_seq, &error);
            if (r != 0) {
                rc = r;
                lost_errno = errno;
                break;
            }
            const parsed_cidr_t *entry = &entries[valid_indices[i]];
            if (error == 0) {
                if (with_timeout && new_indices) {
                    new_indices[*new_count] = valid_indices[i];
                    (*new_count)++;
                } else if (!with_timeout && has_timeout) {
                    remember_permanent(mgr, set_name_nul, entry);
                }
            } else if (error == IPSET_ERR_EXIST) {
                if (!with_timeout && has_timeout) {
                    remember_permanent(mgr, set_name_nul, entry);
                } else if (has_timeout && with_timeout &&
                           !ipset_perm_incomplete(mgr, set_name_nul) &&
                           !is_permanent(mgr, set_name_nul, entry)) {
                    refresh[refresh_count++] = i;
                }
            } else if (error == IPSET_ERR_HASH_FULL) {
                LOG_WARN("ipset '%s' full (maxelem exceeded): set IpsetMaxElem in config", set_name);
            } else {
                LOG_DEBUG("Netlink ADD error: errno=%d", error);
                if (!with_timeout) {
                    ipset_perm_mark_incomplete(mgr, set_name_nul);
                    result = -1;
                }
            }
        }

        /* Entries added without timeout are the permanent ones. One not known
         * to be acknowledged (not sent, its answer lost or out of step) may be
         * in the set without being in the index: stop refreshing that set.
         * A DNS entry left out comes again with the next answer. */
        if (rc != 0) {
            nl_reopen(mgr, rc, lost_errno);
            if (!with_timeout) ipset_perm_mark_incomplete(mgr, set_name_nul);
            result = -1;
        }

        /* NLM_F_EXCL tells new IPs apart but also keeps the kernel from touching an
         * existing entry, so live IPs expired IpsetTimeout after their first sighting. */
        for (int r = 0; r < refresh_count; r++) {
            struct nlmsghdr *h = (struct nlmsghdr *)msg_bufs[refresh[r]];
            h->nlmsg_flags &= ~NLM_F_EXCL;
            h->nlmsg_seq = mgr->seq++;
            int err = nl_send_recv_ack(mgr, msg_bufs[refresh[r]], msg_lens[refresh[r]]);
            if (err != 0) LOG_DEBUG("Netlink timeout refresh error: errno=%d", err);
        }
        if (sent < msg_count) return -1;
    }

    return result;
}

int ipset_refresh_set_list(ipset_manager_t *mgr) {
    char output[32768];
    char *argv[] = {"ipset", "list", "-n", NULL};
    int ret = run_command_output("ipset", argv, output, sizeof(output));
    if (ret != 0) {
        LOG_WARN("ipset list -n failed (exit %d)", ret);
        return -1;
    }

    mgr->set_count = 0;
    char *saveptr;
    char *line = strtok_r(output, "\n", &saveptr);
    while (line && mgr->set_count < IPSET_MAX_SETS) {
        char *trimmed = trim_whitespace(line);
        if (trimmed[0] != '\0') {
            strncpy(mgr->set_names[mgr->set_count], trimmed, 63);
            mgr->set_names[mgr->set_count][63] = '\0';
            mgr->set_count++;
        }
        line = strtok_r(NULL, "\n", &saveptr);
    }

    LOG_DEBUG("RefreshSetList: loaded %d sets into cache", mgr->set_count);
    return 0;
}

int ipset_set_exists(ipset_manager_t *mgr, const char *name) {
    for (int i = 0; i < mgr->set_count; i++) {
        if (strcmp(mgr->set_names[i], name) == 0) return 1;
    }
    return 0;
}

static void ipset_add_to_cache(ipset_manager_t *mgr, const char *name) {
    if (mgr->set_count < IPSET_MAX_SETS) {
        strncpy(mgr->set_names[mgr->set_count], name, 63);
        mgr->set_names[mgr->set_count][63] = '\0';
        mgr->set_count++;
        LOG_DEBUG("AddToCache: added %s to cache", name);
    }
}
