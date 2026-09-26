#include <pcap.h>
#include <stdio.h>
#include "device.h"

int main(int argc, char **argv) {
    pcap_if_t *alldevs;
    char error_buffer[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&alldevs, error_buffer) == -1) {
        fprintf(stderr, "pcap_findalldevs: %s\n", error_buffer);
        return 1;
    }

    if (alldevs == NULL) {
        printf("No capture devices found.\n");
        return 0;
    }

    printf("Devices: %s\n", alldevs->name);

    addDevice(alldevs->name);
    printf("Device id: %d\n", findDevice(alldevs->name));

    clearDevices();
    pcap_freealldevs(alldevs);
    return 0;
}