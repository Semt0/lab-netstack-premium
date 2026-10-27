#include "device.h"
#include "ip.h"
#include "smtroute.h"
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int addRoute(const char* prefix, const char* mask,
                    const struct ether_addr* mac, const char* device) {
    struct in_addr dest, netmask;
    if (inet_pton(AF_INET, prefix, &dest) != 1 ||
        inet_pton(AF_INET, mask, &netmask) != 1) return -1;
    return setRoutingTable(dest, netmask, mac->ether_addr_octet, device);
}

static int checkRoute(const char* destination, const char* prefix,
                      const char* mask, const struct ether_addr* mac,
                      const char* device, const char* payload) {
    struct in_addr dest, expected_prefix, expected_mask;
    if (inet_pton(AF_INET, destination, &dest) != 1 ||
        inet_pton(AF_INET, prefix, &expected_prefix) != 1 ||
        inet_pton(AF_INET, mask, &expected_mask) != 1) return -1;

    RouteEntry* entry = findRouter(dest);
    if (entry == NULL || entry->dest.s_addr != expected_prefix.s_addr ||
        entry->mask.s_addr != expected_mask.s_addr ||
        strcmp(entry->device, device) != 0 ||
        memcmp(entry->nextHopMAC, mac->ether_addr_octet, 6) != 0) {
        fprintf(stderr, "LPM failed for %s\n", destination);
        return -1;
    }

    struct in_addr src;
    int id = findDevice(entry->device);
    if (getDeviceip(id, &src) != 0) return -1;
    if (sendIPPacket(src, dest, 253, payload, (int)strlen(payload)) != 0) {
        perror("sendIPPacket");
        return -1;
    }

    printf("PASS dst=%s prefix=%s mask=%s device=%s payload=%s\n",
           destination, prefix, mask, device, payload);
    return 0;
}

int main(int argc, char** argv) {
    if (argc != 5) {
        printf("Usage: %s <device-a> <device-b> <mac-a> <mac-b>\n", argv[0]);
        return -1;
    }
    setvbuf(stdout, NULL, _IONBF, 0);

    struct ether_addr mac_a, mac_b;
    if (ether_aton_r(argv[3], &mac_a) == NULL ||
        ether_aton_r(argv[4], &mac_b) == NULL) return -1;
    if (addDevice(argv[1]) < 0 || addDevice(argv[2]) < 0) return -1;

    struct in_addr unknown;
    if (inet_pton(AF_INET, "203.0.113.7", &unknown) != 1) return -1;
    if (findRouter(unknown) != NULL) return -1;
    printf("PASS empty table: no route for 203.0.113.7\n");

    // 按 /24、/0、/32、/16 的顺序插入，查询应选择最长匹配前缀。
    if (addRoute("10.60.1.0", "255.255.255.0", &mac_b, argv[2]) != 0 ||
        addRoute("0.0.0.0", "0.0.0.0", &mac_b, argv[2]) != 0 ||
        addRoute("10.60.1.42", "255.255.255.255", &mac_a, argv[1]) != 0 ||
        addRoute("10.60.0.0", "255.255.0.0", &mac_a, argv[1]) != 0) return -1;

    if (checkRoute("10.60.1.42", "10.60.1.42", "255.255.255.255",
                   &mac_a, argv[1], "cp6-host") != 0 ||
        checkRoute("10.60.1.43", "10.60.1.0", "255.255.255.0",
                   &mac_b, argv[2], "cp6-subnet") != 0 ||
        checkRoute("10.60.2.42", "10.60.0.0", "255.255.0.0",
                   &mac_a, argv[1], "cp6-network") != 0 ||
        checkRoute("203.0.113.7", "0.0.0.0", "0.0.0.0",
                   &mac_b, argv[2], "cp6-default") != 0) return -1;

    clearDevices();
    printf("CP6 LPM checks passed\n");
    return 0;
}
