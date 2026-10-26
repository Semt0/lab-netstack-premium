#include "device.h"
#include "ip.h"
#include "smtroute.h"
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char** argv) {
    if (argc != 4 && argc != 5) {
        fprintf(stderr, "Usage: %s <interface> <destination-ip> <next-hop-mac> [payload]\n", argv[0]);
        return EXIT_FAILURE;
    }
    struct in_addr source, destination;
    struct ether_addr mac;
    if (inet_pton(AF_INET, argv[2], &destination) != 1 || ether_aton_r(argv[3], &mac) == NULL) {
        fprintf(stderr, "Invalid destination IPv4 address or next-hop MAC\n");
        return EXIT_FAILURE;
    }
    int id = addDevice(argv[1]);
    if (id < 0) return EXIT_FAILURE;
    int status = EXIT_FAILURE;
    if (getDeviceip(id, &source) != 0) {
        fprintf(stderr, "Interface %s has no cached IPv4 address\n", argv[1]);
        goto cleanup;
    }
    struct in_addr mask = {.s_addr = htonl(0xffffffffU)};
    if (setRoutingTable(destination, mask, mac.ether_addr_octet, argv[1]) != 0) {
        fprintf(stderr, "Cannot add the manual host route\n");
        goto cleanup;
    }
    const char* payload = argc == 5 ? argv[4] : "lab2-ipv4-test";
    size_t length = strlen(payload);
    if (length > 1480) {
        fprintf(stderr, "Payload must fit in one Ethernet frame (at most 1480 bytes)\n");
        goto cleanup;
    }
    if (sendIPPacket(source, destination, 253, payload, (int)length) != 0) {
        perror("sendIPPacket");
        goto cleanup;
    }
    char source_text[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &source, source_text, sizeof(source_text));
    printf("IPv4 TX src=%s dst=%s length=%zu payload=%zu protocol=253\n",
           source_text, argv[2], length + 20, length);
    status = EXIT_SUCCESS;
cleanup:
    clearDevices();
    return status;
}
