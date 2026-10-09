#include "packetio.h"
#include "device.h"
#include <errno.h>
#include <stdio.h>
#include <string.h>

/* Stub device access: argument tests do not open or send on real interfaces. */
static int handle_calls;
static int mac_calls;
static int mac_should_fail;
static unsigned char handle_token;
static int inject_calls;
static int inject_mode;
static size_t captured_len;
static unsigned char captured[1514];
static int capture_error;

/* Capture bytes while the caller's buffer is still alive. No real traffic. */
int pcap_inject(pcap_t *handle, const void *buf, size_t len) {
    ++inject_calls;
    if (handle != (pcap_t *)&handle_token || buf == NULL ||
        len > sizeof(captured)) {
        capture_error = 1;
        return -1;
    }
    captured_len = len;
    memcpy(captured, buf, len);
    if (inject_mode == 1) return -1;
    if (inject_mode == 2) return (int)len - 1;
    return (int)len;
}

char *pcap_geterr(pcap_t *handle) {
    (void)handle;
    static char message[] = "simulated injection failure";
    return message;
}

pcap_t *getDeviceHandle(int id) {
    ++handle_calls;
    return id == 0 ? (pcap_t *)&handle_token : NULL;
}

int getDeviceMAC(int id, unsigned char mac[6]) {
    ++mac_calls;
    if (id != 0 || mac == NULL || mac_should_fail) return -1;
    const unsigned char source[6] = {0x02, 0, 0, 0, 0, 1};
    memcpy(mac, source, 6);
    return 0;
}

struct TestCase {
    const char *name;
    const void *buf;
    int len;
    int type;
    const void *dest;
    int id;
    int error;
    int handles;
    int macs;
    int mac_fail;
    int sending_mode;
};

int main(void) {
    static unsigned char payload[1500];
    static const unsigned char dest[6] = {0x02, 0, 0, 0, 0, 2};
    for (size_t i = 0; i < sizeof(payload); ++i) {
        payload[i] = (unsigned char)((i * 37) & 0xff);
    }
    const struct TestCase cases[] = {
        {"negative length", payload, -1, 0x0800, dest, 0, EINVAL, 0, 0, 0, 0},
        {"oversized payload", payload, 1501, 0x0800, dest, 0, EMSGSIZE, 0, 0, 0, 0},
        {"missing payload", NULL, 1, 0x0800, dest, 0, EINVAL, 0, 0, 0, 0},
        {"missing destination", payload, 10, 0x0800, NULL, 0, EINVAL, 0, 0, 0, 0},
        {"negative EtherType", payload, 10, -1, dest, 0, EINVAL, 0, 0, 0, 0},
        {"length field instead of EtherType", payload, 10, 0x05ff, dest, 0, EINVAL, 0, 0, 0, 0},
        {"oversized EtherType", payload, 10, 0x10000, dest, 0, EINVAL, 0, 0, 0, 0},
        {"negative device ID", payload, 10, 0x0800, dest, -1, ENODEV, 1, 0, 0, 0},
        {"unregistered device ID", payload, 10, 0x0800, dest, 99, ENODEV, 1, 0, 0, 0},
        {"source MAC query failure", payload, 10, 0x0800, dest, 0, EIO, 1, 1, 1, 0},
        {"empty payload is valid", NULL, 0, 0x0800, dest, 0, 0, 1, 1, 0, 0},
        {"maximum payload is valid", payload, 1500, 0x0800, dest, 0, 0, 1, 1, 0, 0},
        {"minimum EtherType is valid", payload, 10, 0x0600, dest, 0, 0, 1, 1, 0, 0},
        {"maximum EtherType is valid", payload, 10, 0xffff, dest, 0, 0, 1, 1, 0, 0},
        {"45-byte payload needs padding", payload, 45, 0x88b5, dest, 0, 0, 1, 1, 0, 0},
        {"46-byte payload fits minimum frame", payload, 46, 0x88b5, dest, 0, 0, 1, 1, 0, 0},
        {"47-byte payload exceeds minimum frame", payload, 47, 0x88b5, dest, 0, 0, 1, 1, 0, 0},
        {"injection failure", payload, 10, 0x88b5, dest, 0, EIO, 1, 1, 0, 1},
        {"incomplete injection", payload, 10, 0x88b5, dest, 0, EIO, 1, 1, 0, 2},
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        const struct TestCase *t = &cases[i];
        handle_calls = mac_calls = 0;
        mac_should_fail = t->mac_fail;
        inject_mode = t->sending_mode;
        inject_calls = capture_error = 0;
        captured_len = 0;
        memset(captured, 0xa5, sizeof(captured));
        errno = 0;
        int result = sendFrame(t->buf, t->len, t->type, t->dest, t->id);
        int actual_error = errno;
        int expected_result = t->error == 0 ? 0 : -1;
        if (result != expected_result ||
            (expected_result == -1 && actual_error != t->error) ||
            handle_calls != t->handles || mac_calls != t->macs) {
            fprintf(stderr, "FAIL: %s (result=%d errno=%d handles=%d macs=%d)\n",
                    t->name, result, actual_error, handle_calls, mac_calls);
            return 1;
        }
        int expected_injections = t->handles == 1 && t->macs == 1 && !t->mac_fail;
        if (inject_calls != expected_injections || capture_error) {
            fprintf(stderr, "FAIL: %s (unexpected injection)\n", t->name);
            return 1;
        }
        if (expected_injections) {
            size_t length = 14 + (size_t)t->len;
            if (length < 60) length = 60;
            const unsigned char source[6] = {0x02, 0, 0, 0, 0, 1};
            if (captured_len != length || memcmp(captured, t->dest, 6) != 0 ||
                memcmp(captured + 6, source, 6) != 0 ||
                captured[12] != (unsigned char)(t->type >> 8) ||
                captured[13] != (unsigned char)(t->type & 0xff) ||
                (t->len > 0 && memcmp(captured + 14, t->buf, (size_t)t->len) != 0)) {
                fprintf(stderr, "FAIL: %s (frame length/header/payload)\n", t->name);
                return 1;
            }
            for (size_t j = 14 + (size_t)t->len; j < captured_len; ++j) {
                if (captured[j] != 0) {
                    fprintf(stderr, "FAIL: %s (nonzero padding)\n", t->name);
                    return 1;
                }
            }
        }
        printf("PASS: %s\n", t->name);
    }
    puts("All 19 sendFrame argument, frame-content and sending-result checks passed.");
    return 0;
}

/* Receive APIs are linked but must not be used by sendFrame tests. */
int pcap_datalink(pcap_t *handle) {
    (void)handle;
    return DLT_EN10MB;
}
int pcap_next_ex(pcap_t *handle, struct pcap_pkthdr **header,
                 const unsigned char **data) {
    (void)handle; (void)header; (void)data;
    return PCAP_ERROR_BREAK;
}
