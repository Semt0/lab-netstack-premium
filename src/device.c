#include "device.h"
#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <net/if_arp.h>
#include <netpacket/packet.h>
#include <ifaddrs.h>

#define MAX_DEVICE_NUM 16

typedef struct {
    char name[128];
    unsigned char mac[6]; // Save raw bytes, convert to string only when printing
    struct in_addr ip;
    pcap_t* rx_handle;
    pcap_t* tx_handle;
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

// Cache the first IPv4 address configured on this interface.
static int queryDeviceIP(const char* name, struct in_addr* ip) {
    struct ifaddrs* addresses = NULL;
    if (getifaddrs(&addresses) == -1) return -1;

    int result = -1;
    for (struct ifaddrs* address = addresses; address != NULL; address = address->ifa_next) {
        if (address->ifa_addr == NULL || address->ifa_addr->sa_family != AF_INET ||
            strcmp(address->ifa_name, name) != 0) continue;

        const struct sockaddr_in* ipv4 = (const struct sockaddr_in*)address->ifa_addr;
        *ip = ipv4->sin_addr;
        result = 0;
        break;
    }

    freeifaddrs(addresses);
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

const char* getDeviceName(int id) {
    if (id < 0 || id >= num_devices) return NULL;
    return devices_list[id].name;
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
    pcap_t* rx_handle = pcap_open_live(device, 65535, 0, 1000, error_buffer);
    if (rx_handle == NULL) {
        fprintf(stderr, "Fail to open RX on %s: %s\n", device, error_buffer);
        return -1;
    }

    pcap_t* tx_handle = pcap_open_live(device, 65535, 0, 1000, error_buffer);
    if (tx_handle == NULL) {
        fprintf(stderr, "Fail to open TX on %s: %s\n", device, error_buffer);
        pcap_close(rx_handle);
        return -1;
    }

    unsigned char mac[6];

    if (queryDeviceMAC(device, mac) == -1) {
        fprintf(stderr, "Cannot obtain Ethernet MAC for %s\n", device);
        pcap_close(tx_handle);
        pcap_close(rx_handle);
        return -1;
    }

    // Ethernet-only interfaces may have no IPv4 address; registration still works.
    struct in_addr ip = {0};
    queryDeviceIP(device, &ip);

    id = num_devices;

    strcpy(devices_list[id].name, device);
    devices_list[id].rx_handle = rx_handle;
    devices_list[id].tx_handle = tx_handle;
    devices_list[id].ip = ip;
    memcpy(devices_list[id].mac, mac, 6);

    num_devices++;
    return id;
}

void clearDevices(void) {
    for (int i = 0; i < num_devices; i++) {
        pcap_close(devices_list[i].rx_handle);
        pcap_close(devices_list[i].tx_handle);
        devices_list[i].rx_handle = NULL;
        devices_list[i].tx_handle = NULL;
        devices_list[i].name[0] = '\0';
        devices_list[i].ip.s_addr = 0;
    }
    num_devices = 0;
}

pcap_t *getDeviceHandle(int id, DeviceHandleType direction) {
    if (id < 0 || id >= num_devices) return NULL;

    switch (direction) {
    case DEVICE_RX:
        return devices_list[id].rx_handle;
    case DEVICE_TX:
        return devices_list[id].tx_handle;
    default:
        return NULL;
    }
}

int getDeviceMAC(int id, unsigned char mac[6]) {
    if (id < 0 || id >= num_devices || mac == NULL) {
        return -1;
    }

    memcpy(mac, devices_list[id].mac, 6);
    return 0;
}

int getDeviceip(int id, struct in_addr* ip) {
    if (id < 0 || id >= num_devices || ip == NULL || devices_list[id].ip.s_addr == 0) {
        return -1;
    }

    *ip = devices_list[id].ip;
    return 0;
}

int isLocalIP(const struct in_addr ip) {
    if (ip.s_addr == 0) return 0;
    for (int i = 0; i < num_devices; i++) {
        if (devices_list[i].ip.s_addr == ip.s_addr) return 1;
    }
    return 0;
}
