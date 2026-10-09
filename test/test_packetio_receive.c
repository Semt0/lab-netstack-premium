#include "packetio.h"
#include "device.h"
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

/* Scripted capture: no real devices, sockets or network traffic. */
struct Event {
    int result;
    unsigned int caplen;
    unsigned int len;
    int null_header;
    int null_data;
};
static const struct Event *events;
static size_t event_count;
static size_t reads;
static int link_type;
static int callback_mode;
static int callbacks;
static int callback_bad_args;
static unsigned char token;
static unsigned char packet[80];
static struct pcap_pkthdr packet_header;

pcap_t *getDeviceHandle(int id) {
    return id == 0 ? (pcap_t *)&token : NULL;
}
int getDeviceMAC(int id, unsigned char mac[6]) {
    if (id != 0 || mac == NULL) return -1;
    memset(mac, 0, 6);
    return 0;
}
int pcap_inject(pcap_t *handle, const void *buf, size_t len) {
    (void)handle; (void)buf; (void)len;
    return -1;
}
char *pcap_geterr(pcap_t *handle) {
    (void)handle;
    static char message[] = "simulated capture failure";
    return message;
}
int pcap_datalink(pcap_t *handle) {
    return handle == (pcap_t *)&token ? link_type : PCAP_ERROR;
}
int pcap_next_ex(pcap_t *handle, struct pcap_pkthdr **header,
                 const unsigned char **data) {
    size_t index = reads++;
    if (handle != (pcap_t *)&token || index >= event_count) {
        return PCAP_ERROR_BREAK;
    }
    const struct Event *event = &events[index];
    if (event->result == 1) {
        memset(&packet_header, 0, sizeof(packet_header));
        packet_header.caplen = event->caplen;
        packet_header.len = event->len;
        *header = event->null_header ? NULL : &packet_header;
        *data = event->null_data ? NULL : packet;
    } else {
        *header = NULL;
        *data = NULL;
    }
    return event->result;
}
static int on_frame(const void *buf, int len, int id) {
    ++callbacks;
    if (buf != packet || id != 0 || len < 14 ||
        (size_t)len > sizeof(packet) ||
        len != (int)packet_header.caplen) {
        callback_bad_args = 1;
        return -1;
    }
    const unsigned char *bytes = buf;
    for (int i = 0; i < len; ++i) {
        if (bytes[i] != (unsigned char)(i ^ 0x5a)) {
            callback_bad_args = 1;
            return -1;
        }
    }
    if (callback_mode == 3) setFrameReceiveCallback(NULL);
    return callback_mode == 2 ? -1 : 0;
}

#define FRAME(n) {1, n, n, 0, 0}
static const struct Event good[] = {FRAME(60), FRAME(60)};
static const struct Event timed[] = {{0, 0, 0, 0, 0}, FRAME(60)};
static const struct Event short_frame[] = {FRAME(13), FRAME(60)};
static const struct Event truncated[] = {{1, 40, 60, 0, 0}, FRAME(60)};
static const struct Event minimum[] = {FRAME(14)};
static const struct Event error[] = {{PCAP_ERROR, 0, 0, 0, 0}};
static const struct Event inactive[] = {{PCAP_ERROR_NOT_ACTIVATED, 0, 0, 0, 0}};
static const struct Event ended[] = {{PCAP_ERROR_BREAK, 0, 0, 0, 0}};
static const struct Event unknown[] = {{-99, 0, 0, 0, 0}};
static const struct Event partial[] = {FRAME(60), {PCAP_ERROR_BREAK, 0, 0, 0, 0}};
static const struct Event missing_header[] = {{1, 60, 60, 1, 0}};
static const struct Event missing_data[] = {{1, 60, 60, 0, 1}};
static const struct Event oversized[] = {
    {1, (unsigned int)INT_MAX + 1U, (unsigned int)INT_MAX + 1U, 0, 0}
};

struct Case {
    const char *name;
    int id;
    int count;
    int mode; /* 0: unregistered, 1: success, 2: fail, 3: unregister in callback */
    int datalink;
    const struct Event *sequence;
    size_t sequence_len;
    int expected_result;
    int expected_errno;
    int expected_callbacks;
    size_t expected_reads;
};
#define SEQ(a) a, sizeof(a) / sizeof(a[0])

int main(void) {
    const struct Case cases[] = {
        {"zero count", 0, 0, 1, DLT_EN10MB, SEQ(good), -1, EINVAL, 0, 0},
        {"negative count", 0, -1, 1, DLT_EN10MB, SEQ(good), -1, EINVAL, 0, 0},
        {"no callback", 0, 1, 0, DLT_EN10MB, SEQ(good), -1, EINVAL, 0, 0},
        {"negative device ID", -1, 1, 1, DLT_EN10MB, SEQ(good), -1, ENODEV, 0, 0},
        {"unregistered device ID", 99, 1, 1, DLT_EN10MB, SEQ(good), -1, ENODEV, 0, 0},
        {"non-Ethernet capture", 0, 1, 1, DLT_RAW, SEQ(good), -1, EPROTONOSUPPORT, 0, 0},
        {"datalink query fails", 0, 1, 1, PCAP_ERROR, SEQ(good), -1, EIO, 0, 0},
        {"capture error returns immediately", 0, 1, 1, DLT_EN10MB, SEQ(error), -1, EIO, 0, 1},
        {"inactive handle error", 0, 1, 1, DLT_EN10MB, SEQ(inactive), -1, EIO, 0, 1},
        {"capture ended early", 0, 1, 1, DLT_EN10MB, SEQ(ended), -1, EPIPE, 0, 1},
        {"unexpected capture result", 0, 1, 1, DLT_EN10MB, SEQ(unknown), -1, EIO, 0, 1},
        {"timeout does not count as a frame", 0, 1, 1, DLT_EN10MB, SEQ(timed), 0, 0, 1, 2},
        {"short frame is skipped", 0, 1, 1, DLT_EN10MB, SEQ(short_frame), 0, 0, 1, 2},
        {"truncated frame is skipped", 0, 1, 1, DLT_EN10MB, SEQ(truncated), 0, 0, 1, 2},
        {"14-byte header accepted", 0, 1, 1, DLT_EN10MB, SEQ(minimum), 0, 0, 1, 1},
        {"stop after one frame", 0, 1, 1, DLT_EN10MB, SEQ(good), 0, 0, 1, 1},
        {"two frames delivered", 0, 2, 1, DLT_EN10MB, SEQ(good), 0, 0, 2, 2},
        {"early end after one frame", 0, 2, 1, DLT_EN10MB, SEQ(partial), -1, EPIPE, 1, 2},
        {"callback failure stops reception", 0, 2, 2, DLT_EN10MB, SEQ(good), -1, EIO, 1, 1},
        {"missing header", 0, 1, 1, DLT_EN10MB, SEQ(missing_header), -1, EIO, 0, 1},
        {"missing data", 0, 1, 1, DLT_EN10MB, SEQ(missing_data), -1, EIO, 0, 1},
        {"callback length cannot overflow int", 0, 1, 1, DLT_EN10MB, SEQ(oversized), -1, EMSGSIZE, 0, 1},
        {"callback fixed for this receive call", 0, 2, 3, DLT_EN10MB, SEQ(good), 0, 0, 2, 2},
    };
    for (size_t i = 0; i < sizeof(packet); ++i) packet[i] = (unsigned char)(i ^ 0x5a);
    alarm(5); /* Stop a broken implementation that loops forever on errors. */
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        const struct Case *t = &cases[i];
        events = t->sequence;
        event_count = t->sequence_len;
        reads = 0;
        callbacks = callback_bad_args = 0;
        callback_mode = t->mode;
        link_type = t->datalink;
        if (setFrameReceiveCallback(on_frame) != 0 ||
            (t->mode == 0 && setFrameReceiveCallback(NULL) != 0)) {
            fputs("FAIL: callback registration\n", stderr);
            return 1;
        }
        errno = 0;
        int result = receiveFrames(t->id, t->count);
        int error_code = errno;
        if (result != t->expected_result ||
            (result == -1 && error_code != t->expected_errno) ||
            callbacks != t->expected_callbacks || reads != t->expected_reads || callback_bad_args) {
            fprintf(stderr, "FAIL: %s (result=%d errno=%d callbacks=%d reads=%zu)\n",
                    t->name, result, error_code, callbacks, reads);
            return 1;
        }
        printf("PASS: %s\n", t->name);
    }
    setFrameReceiveCallback(NULL);
    errno = 0;
    if (receiveFrames(0, 1) != -1 || errno != EINVAL) {
        fputs("FAIL: unregister callback\n", stderr);
        return 1;
    }
    puts("PASS: unregister callback");
    alarm(0);
    puts("All 24 receiveFrames/callback checks passed. No real traffic.");
    return 0;
}
