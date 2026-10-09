#include "device.h"
#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <net/if_arp.h>
#include <netpacket/packet.h>

#define MAX_DEVICE_NUM 16

typedef struct {
    char name[128];
    unsigned char mac[6]; // Save raw bytes, convert to string only when printing
    pcap_t* handle;
} Device;

static Device devices_list[MAX_DEVICE_NUM];
static int num_devices = 0;

static int queryDeviceMAC(const char *name, unsigned char mac[6]) {
    if (name == NULL || mac == NULL) {
        return -1;
    }

    pcap_if_t *alldevs = NULL;
    char errbuf[PCAP_ERRBUF_SIZE];
    int result = -1;

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "pcap_findalldevs: %s\n", errbuf);
        return -1;
    }

    for (pcap_if_t *dev = alldevs; dev != NULL; dev = dev->next) {
        if (strcmp(name, dev->name) != 0) {
            continue;
        }

        for (pcap_addr_t *address = dev->addresses; address != NULL; address = address->next) {
            if (address->addr == NULL || address->addr->sa_family != AF_PACKET) {
                continue;
            }

            const struct sockaddr_ll *link = (const struct sockaddr_ll *)address->addr;

            if (link->sll_hatype == ARPHRD_ETHER && link->sll_halen == 6) {
                memcpy(mac, link->sll_addr, 6);
                result = 0;
                break;
            }
        }

        break;
    }

    pcap_freealldevs(alldevs);
    return result;
}

int findDevice(const char* device) {
    if (device == NULL || *device == '\0') {
        fprintf(stderr, "Error: Device name is NULL or empty!\n");
        return -1;
    }

    for (int i = 0; i < num_devices; i++) {
        if (strcmp(devices_list[i].name, device) == 0) {
            return i;
        }
    }

    return -1;
}

int addDevice(const char* device) {
    if (device == NULL || *device == '\0') {
        fprintf(stderr, "Error: Device name is NULL or empty!\n");
        return -1;
    }

    int id = findDevice(device);
    if (id != -1) {
        return id;
    }

    if (num_devices >= MAX_DEVICE_NUM) {
        fprintf(stderr, "Error: Device list is full!\n");
        return -1;
    }
    if (strlen(device) >= sizeof(devices_list[num_devices].name)) {
        fprintf(stderr, "Error: Device name is too long!\n");
        return -1;
    }

    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(
        device,
        65535,
        0,
        1000,
        error_buffer
    );

    if (handle == NULL) {
        fprintf(stderr, "Fail to open device %s: %s\n", device, error_buffer);
        return -1;
    }

    unsigned char mac[6];

    if (queryDeviceMAC(device, mac) == -1) {
        fprintf(stderr, "Cannot obtain Ethernet MAC for %s\n", device);
        pcap_close(handle);
        return -1;
    }

    id = num_devices;

    strcpy(devices_list[id].name, device);
    devices_list[id].handle = handle;
    memcpy(devices_list[id].mac, mac, 6);

    num_devices++;
    return id;
}

void clearDevices(void) {
    for (int i = 0; i < num_devices; i++) {
        pcap_close(devices_list[i].handle);
        devices_list[i].handle = NULL;
        devices_list[i].name[0] = '\0';
    }
    num_devices = 0;
}

pcap_t *getDeviceHandle(int id) {
    if (id < 0 || id >= num_devices) {
        return NULL;
    }

    return devices_list[id].handle;
}

int getDeviceMAC(int id, unsigned char mac[6]) {
    if (id < 0 || id >= num_devices || mac == NULL) {
        return -1;
    }

    memcpy(mac, devices_list[id].mac, 6);
    return 0;
}
