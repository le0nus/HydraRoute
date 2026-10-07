#include "../include/packet_capture.h"
#include <assert.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int packets;

static void count_packet(const uint8_t *pkt, int pkt_len, void *user_data) {
    (void)pkt; (void)pkt_len; (void)user_data;
    packets++;
}

int main(void) {
    int rx = socket(AF_INET, SOCK_DGRAM, 0);
    int tx = socket(AF_INET, SOCK_DGRAM, 0);
    assert(rx >= 0 && tx >= 0);
    int bufsize = 1 << 20;
    setsockopt(rx, SOL_SOCKET, SO_RCVBUF, &bufsize, sizeof(bufsize));

    struct sockaddr_in sa;
    socklen_t sa_len = sizeof(sa);
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    assert(bind(rx, (struct sockaddr *)&sa, sizeof(sa)) == 0);
    assert(getsockname(rx, (struct sockaddr *)&sa, &sa_len) == 0);
    assert(connect(tx, (struct sockaddr *)&sa, sizeof(sa)) == 0);

    static pkt_capture_t cap;
    cap.fd4 = rx;
    cap.fd6 = -1;
    cap.callback = count_packet;

    /* A burst of answers queued while the loop was busy is read in one wakeup,
     * up to PKT_CAPTURE_BURST so the other descriptors still get their turn. */
    int burst = PKT_CAPTURE_BURST + 6;
    for (int i = 0; i < burst; i++)
        assert(send(tx, "dns", 3, 0) == 3);
    usleep(20000);
    assert(pkt_capture_process(&cap, rx) == 0);
    assert(packets == PKT_CAPTURE_BURST);
    assert(pkt_capture_process(&cap, rx) == 0);
    assert(packets == burst);

    /* An empty socket returns at once instead of blocking the loop. */
    assert(pkt_capture_process(&cap, rx) == 0);
    assert(packets == burst);

    close(tx);
    close(rx);
    puts("check_packet_capture: OK");
    return 0;
}
