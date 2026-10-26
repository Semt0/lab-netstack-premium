#include "ip.h"
#include "device.h"
#include "packetio.h"
#include "smtarp.h"
#include "smtroute.h"
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

/* Reference packets generated independently with Python's network-order packing. */
static const unsigned char valid_packet[] = {0x45,0x00,0x00,0x19,0x00,0x00,0x40,0x00,0x40,0xfd,0xb5,0xe4,0xc0,0x00,0x02,0x01,0xc0,0x00,0x02,0x02,0x68,0x65,0x6c,0x6c,0x6f};
static const unsigned char other_destination[] = {0x45,0x00,0x00,0x19,0x00,0x00,0x40,0x00,0x40,0xfd,0xb5,0xe3,0xc0,0x00,0x02,0x01,0xc0,0x00,0x02,0x03,0x68,0x65,0x6c,0x6c,0x6f};
static const unsigned char fragment[] = {0x45,0x00,0x00,0x19,0x00,0x00,0x20,0x00,0x40,0xfd,0xd5,0xe4,0xc0,0x00,0x02,0x01,0xc0,0x00,0x02,0x02,0x68,0x65,0x6c,0x6c,0x6f};
static const unsigned char with_options[] = {0x46,0x00,0x00,0x1d,0x00,0x00,0x40,0x00,0x40,0xfd,0xb3,0xdf,0xc0,0x00,0x02,0x01,0xc0,0x00,0x02,0x02,0x01,0x01,0x00,0x00,0x68,0x65,0x6c,0x6c,0x6f};
static const unsigned char empty_packet[] = {0x45,0x00,0x00,0x14,0x00,0x00,0x40,0x00,0x40,0xfd,0xb5,0xe9,0xc0,0x00,0x02,0x01,0xc0,0x00,0x02,0x02};

static int callback_calls, callback_len, callback_result;
static const void* callback_pointer;
static unsigned char delivered[80], transmitted[1500];
static int send_calls, transmitted_len, send_result, route_available = 1;
static RouteEntry route = {.nextHopMAC = {2,0,0,0,0,2}, .device = "test0"};

RouteEntry* findRouter(const struct in_addr ip) { (void)ip; return route_available ? &route : NULL; }
int findDevice(const char* name) { return strcmp(name, "test0") == 0 ? 0 : -1; }
int getDeviceip(int id, struct in_addr* ip) {
    if (id != 0) return -1;
    ip->s_addr = htonl(0xc0000202U);
    return 0;
}
int searchARPcache(const struct in_addr ip, uint8_t* mac) {
    (void)ip; (void)mac; assert(0 && "Known-MAC test must not query ARP"); return -1;
}
int sendARPRequest(const struct in_addr src, const struct in_addr dest, int id) {
    (void)src; (void)dest; (void)id; assert(0 && "Known-MAC test must not send ARP"); return -1;
}
int sendFrame(const void* buf, int len, int type, const void* mac, int id) {
    assert(type == ETHERTYPE_IP && id == 0 && len >= 20 && len <= 1500);
    assert(memcmp(mac, route.nextHopMAC, 6) == 0);
    ++send_calls;
    transmitted_len = len;
    memcpy(transmitted, buf, (size_t)len);
    if (send_result != 0) errno = EIO;
    return send_result;
}
static int on_packet(const void* buf, int len) {
    assert(len >= 20 && len <= (int)sizeof(delivered));
    ++callback_calls;
    callback_len = len;
    callback_pointer = buf;
    memcpy(delivered, buf, (size_t)len);
    return callback_result;
}
static void expect_drop(const void* buf, int len, int id) {
    callback_calls = 0;
    assert(handleIPPacket(buf, len, id) == 0 && callback_calls == 0);
}
int main(void) {
    assert(setIPPacketReceiveCallback(NULL) == 0);
    expect_drop(valid_packet, sizeof(valid_packet), 0);
    assert(setIPPacketReceiveCallback(on_packet) == 0);
    unsigned char storage[80] = {0};
    memcpy(storage + 1, valid_packet, sizeof(valid_packet));
    assert(handleIPPacket(storage + 1, 46, 0) == 0);
    assert(callback_calls == 1 && callback_len == (int)sizeof(valid_packet));
    assert(callback_pointer == storage + 1 && memcmp(delivered, valid_packet, sizeof(valid_packet)) == 0);
    puts("PASS: unaligned IPv4 packet reaches callback with IP length, excluding Ethernet padding");

    expect_drop(NULL, 25, 0);
    expect_drop(valid_packet, 19, 0);
    unsigned char bad[sizeof(valid_packet)];
    memcpy(bad, valid_packet, sizeof(bad)); bad[0] = 0x65; expect_drop(bad, sizeof(bad), 0);
    memcpy(bad, valid_packet, sizeof(bad)); bad[0] = 0x44; expect_drop(bad, sizeof(bad), 0);
    memcpy(bad, valid_packet, sizeof(bad)); bad[3] = 19; expect_drop(bad, sizeof(bad), 0);
    memcpy(bad, valid_packet, sizeof(bad)); bad[3] = 100; expect_drop(bad, sizeof(bad), 0);
    memcpy(bad, valid_packet, sizeof(bad)); bad[8] ^= 1; expect_drop(bad, sizeof(bad), 0);
    expect_drop(fragment, sizeof(fragment), 0);
    expect_drop(other_destination, sizeof(other_destination), 0);
    expect_drop(valid_packet, sizeof(valid_packet), -1);
    puts("PASS: invalid version, lengths, checksum, fragments, destination and interface are dropped");
    assert(handleIPPacket(with_options, sizeof(with_options), 0) == 0 && callback_len == (int)sizeof(with_options));
    callback_result = -1;
    assert(handleIPPacket(valid_packet, sizeof(valid_packet), 0) == -1);
    callback_result = 0;
    puts("PASS: header length/options and callback errors handled");

    struct in_addr src = {.s_addr = htonl(0xc0000201U)}, dst = {.s_addr = htonl(0xc0000202U)};
    assert(sendIPPacket(src, dst, 253, "hello", 5) == 0);
    assert(transmitted_len == (int)sizeof(valid_packet) && memcmp(transmitted, valid_packet, sizeof(valid_packet)) == 0);
    assert(sendIPPacket(src, dst, 253, NULL, 0) == 0);
    assert(transmitted_len == (int)sizeof(empty_packet) && memcmp(transmitted, empty_packet, sizeof(empty_packet)) == 0);
    puts("PASS: send bytes and checksum match independent reference, including empty payload");
    send_result = -1;
    assert(sendIPPacket(src, dst, 253, "hello", 5) == -1 && errno == EIO);
    send_result = 0;
    int previous_calls = send_calls;
    route_available = 0;
    assert(sendIPPacket(src, dst, 253, "hello", 5) == -1 && errno == ENETUNREACH);
    route_available = 1;
    assert(sendIPPacket(src, dst, 256, "hello", 5) == -1);
    assert(sendIPPacket(src, dst, 253, "hello", -1) == -1);
    assert(sendIPPacket(src, dst, 253, NULL, 1) == -1);
    assert(sendIPPacket(src, dst, 253, "hello", 1481) == -1);
    assert(send_calls == previous_calls);
    puts("PASS: send failure, missing route and invalid input return errors");
    return 0;
}
