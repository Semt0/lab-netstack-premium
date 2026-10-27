#include "device.h"
#include "ip.h"
#include "smtroute.h"
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char** argv) {
    if (argc != 4 && argc != 5) {
        printf("Usage: %s <interface> <destination-ip> <next-hop-mac> [payload]\n", argv[0]);
        return -1;
    }

    struct in_addr src_ip, dest_ip;
    if (inet_pton(AF_INET, argv[2], &dest_ip) != 1) {
        fprintf(stderr, "Invalid destination IPv4 address\n");
        return -1;
    }

    struct ether_addr nextHopMAC;
    if (ether_aton_r(argv[3], &nextHopMAC) == NULL) {
        fprintf(stderr, "Invalid next-hop MAC address\n");
        return -1;
    }

    const char* payload = argc == 5 ? argv[4] : "lab2-ipv4-test";
    size_t len = strlen(payload);
    if (len > 1480) {
        fprintf(stderr, "Payload must not exceed 1480 bytes\n");
        return -1;
    }

    int id = addDevice(argv[1]);
    if (id < 0) return -1;

    if (getDeviceip(id, &src_ip) != 0) {
        fprintf(stderr, "Cannot obtain IPv4 address on %s\n", argv[1]);
        clearDevices();
        return -1;
    }

    // 为目的地址添加 /32 路由，使用指定的下一跳 MAC。
    struct in_addr mask = {.s_addr = htonl(0xffffffffU)};
    if (setRoutingTable(dest_ip, mask, nextHopMAC.ether_addr_octet, argv[1]) != 0) {
        fprintf(stderr, "Cannot add the manual host route\n");
        clearDevices();
        return -1;
    }

    if (sendIPPacket(src_ip, dest_ip, 253, payload, (int)len) != 0) {
        perror("sendIPPacket");
        clearDevices();
        return -1;
    }

    char src_text[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &src_ip, src_text, sizeof(src_text));
    printf("IPv4 TX src=%s dst=%s length=%zu payload=%zu protocol=253\n",
           src_text, argv[2], len + 20, len);

    clearDevices();
    return 0;
}
