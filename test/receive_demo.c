#include "device.h"
#include "packetio.h"
#include <stdio.h>
#include <stdlib.h>

static void printMAC(const unsigned char *mac) {
    printf("%02x:%02x:%02x:%02x:%02x:%02x",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

static int printFrame(const void *buf, int len, int id) {
    if (buf == NULL || len < 14) {
        fprintf(stderr, "receive_demo: incomplete Ethernet header\n");
        return -1;
    }
    const unsigned char *frame = buf;
    unsigned int type = ((unsigned int)frame[12] << 8) | frame[13];

    printf("Received Ethernet frame: device=%d, length=%d bytes\n", id, len);
    printf("Source: ");
    printMAC(frame + 6);
    printf("\nDestination: ");
    printMAC(frame);
    printf("\nEtherType: 0x%04x\nFrame bytes:\n", type);
    for (int i = 0; i < len; ++i) {
        if (i % 16 == 0) printf("  %04x: ", (unsigned int)i);
        printf("%02x ", frame[i]);
        if ((i + 1) % 16 == 0 || i + 1 == len) putchar('\n');
    }
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <interface>\n", argv[0]);
        return EXIT_FAILURE;
    }
    int exit_status = EXIT_FAILURE;
    int id = addDevice(argv[1]);
    if (id < 0) {
        fprintf(stderr, "Cannot register interface %s\n", argv[1]);
        goto cleanup;
    }
    pcap_t *handle = getDeviceHandle(id);
    if (handle == NULL || pcap_datalink(handle) != DLT_EN10MB) {
        fprintf(stderr, "Interface %s does not provide Ethernet frames\n", argv[1]);
        goto cleanup;
    }

    struct bpf_program filter;
    if (pcap_compile(handle, &filter, "ether proto 0x88b5",
                     1, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "pcap_compile: %s\n", pcap_geterr(handle));
        goto cleanup;
    }
    int filter_result = pcap_setfilter(handle, &filter);
    pcap_freecode(&filter);
    if (filter_result == -1) {
        fprintf(stderr, "pcap_setfilter: %s\n", pcap_geterr(handle));
        goto cleanup;
    }

    if (setFrameReceiveCallback(printFrame) != 0) {
        fprintf(stderr, "Cannot register frame callback\n");
        goto cleanup;
    }
    printf("Waiting on %s for one frame with EtherType 0x88b5...\n", argv[1]);
    fflush(stdout);
    if (receiveFrames(id, 1) != 0) {
        perror("receive_demo");
        goto cleanup;
    }
    puts("Reception completed.");
    exit_status = EXIT_SUCCESS;

cleanup:
    setFrameReceiveCallback(NULL);
    clearDevices();
    return exit_status;
}
