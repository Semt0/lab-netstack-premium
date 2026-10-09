#include "device.h"
#include "packetio.h"
#include <ctype.h>
#include <netinet/ether.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Require exactly six hexadecimal octets, without trailing characters. */
static int parseMAC(const char *text, struct ether_addr *address) {
    if (strlen(text) != 17) return -1;
    for (size_t i = 0; i < 17; ++i) {
        if (i % 3 == 2) {
            if (text[i] != ':') return -1;
        } else if (!isxdigit((unsigned char)text[i])) {
            return -1;
        }
    }
    return ether_aton_r(text, address) == NULL ? -1 : 0;
}

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <interface> <destination-MAC>\n", argv[0]);
        fprintf(stderr, "MAC format: 02:00:00:00:00:02\n");
        return EXIT_FAILURE;
    }

    struct ether_addr destination;
    if (parseMAC(argv[2], &destination) != 0) {
        fprintf(stderr, "Invalid destination MAC: %s\n", argv[2]);
        return EXIT_FAILURE;
    }

    int id = addDevice(argv[1]);
    if (id < 0) {
        fprintf(stderr, "Cannot register interface %s\n", argv[1]);
        clearDevices();
        return EXIT_FAILURE;
    }

    /* Inject only on Ethernet II interfaces. */
    pcap_t *handle = getDeviceHandle(id);
    if (handle == NULL || pcap_datalink(handle) != DLT_EN10MB) {
        fprintf(stderr, "Interface %s does not provide Ethernet frames\n", argv[1]);
        clearDevices();
        return EXIT_FAILURE;
    }

    const char payload[] = "lab1-test";
    const int ethtype = 0x88b5;
    int result = sendFrame(payload, (int)strlen(payload), ethtype,
                           destination.ether_addr_octet, id);
    if (result != 0) {
        /* sendFrame prints the detailed cause; perror adds the errno text. */
        perror("send_demo");
        clearDevices();
        return EXIT_FAILURE;
    }

    printf("Injected Ethernet frame on %s: destination=%s, "
           "EtherType=0x%04x, payload=\"%s\" (%zu bytes)\n",
           argv[1], argv[2], ethtype, payload, strlen(payload));
    clearDevices();
    return EXIT_SUCCESS;
}
