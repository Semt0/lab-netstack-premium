#include "device.h"
#include <assert.h>
#include <ifaddrs.h>
#include <net/if_arp.h>
#include <netpacket/packet.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

/* Mock capture handles and interface metadata: no sockets or network traffic. */
static max_align_t tokens[2];
static int opens, closes, fail_open, fail_mac;
static int closed[2];
static struct sockaddr_ll link_address;
static pcap_addr_t address;
static pcap_if_t interface;
static char interface_name[] = "mock0";

pcap_t* pcap_open_live(const char* name, int snaplen, int promisc, int timeout, char* error) {
    assert(strcmp(name, interface_name) == 0);
    assert(snaplen == 65535 && promisc == 0 && timeout == 1000);
    int index = opens++;
    assert(index < 2);
    if (opens == fail_open) {
        snprintf(error, PCAP_ERRBUF_SIZE, "simulated open failure");
        return NULL;
    }
    return (pcap_t*)&tokens[index];
}

void pcap_close(pcap_t* handle) {
    int index = handle == (pcap_t*)&tokens[0] ? 0 : 1;
    assert(handle == (pcap_t*)&tokens[index]);
    assert(!closed[index]);
    closed[index] = 1;
    ++closes;
}

int pcap_findalldevs(pcap_if_t** devices, char* error) {
    if (fail_mac) {
        snprintf(error, PCAP_ERRBUF_SIZE, "simulated MAC query failure");
        return -1;
    }
    *devices = &interface;
    return 0;
}
void pcap_freealldevs(pcap_if_t* devices) {
    assert(devices == &interface);
}
int getifaddrs(struct ifaddrs** addresses) {
    *addresses = NULL;
    return 0;
}
void freeifaddrs(struct ifaddrs* addresses) {
    assert(addresses == NULL);
}

static void reset(void) {
    clearDevices();
    opens = closes = fail_open = fail_mac = 0;
    memset(closed, 0, sizeof(closed));
    memset(&link_address, 0, sizeof(link_address));
    link_address.sll_family = AF_PACKET;
    link_address.sll_hatype = ARPHRD_ETHER;
    link_address.sll_halen = 6;
    link_address.sll_addr[0] = 2;
    memset(&address, 0, sizeof(address));
    address.addr = (struct sockaddr*)&link_address;
    memset(&interface, 0, sizeof(interface));
    interface.name = interface_name;
    interface.addresses = &address;
}

int main(void) {
    reset();
    fail_open = 1;
    assert(addDevice(interface_name) == -1);
    assert(opens == 1 && closes == 0 && findDevice(interface_name) == -1);
    clearDevices();
    assert(closes == 0);
    puts("PASS: RX open failure leaves no registered device or open handles");

    reset();
    fail_open = 2;
    assert(addDevice(interface_name) == -1);
    assert(opens == 2 && closes == 1 && closed[0] && !closed[1]);
    assert(findDevice(interface_name) == -1);
    clearDevices();
    assert(closes == 1);
    puts("PASS: TX open failure closes RX without registering the device");

    reset();
    fail_mac = 1;
    assert(addDevice(interface_name) == -1);
    assert(opens == 2 && closes == 2 && closed[0] && closed[1]);
    assert(findDevice(interface_name) == -1);
    clearDevices();
    assert(closes == 2);
    puts("PASS: metadata failure closes both handles");

    reset();
    int id = addDevice(interface_name);
    assert(id == 0 && opens == 2 && closes == 0);
    assert(getDeviceHandle(id, DEVICE_RX) == (pcap_t*)&tokens[0]);
    assert(getDeviceHandle(id, DEVICE_TX) == (pcap_t*)&tokens[1]);
    assert(getDeviceHandle(-1, DEVICE_RX) == NULL);
    assert(getDeviceHandle(16, DEVICE_TX) == NULL);
    assert(getDeviceHandle(id, (DeviceHandleType)99) == NULL);
    assert(addDevice(interface_name) == id && opens == 2);
    puts("PASS: distinct RX/TX handles, direction checks and duplicate registration");

    clearDevices();
    assert(closes == 2 && closed[0] && closed[1]);
    assert(getDeviceHandle(id, DEVICE_RX) == NULL);
    assert(getDeviceHandle(id, DEVICE_TX) == NULL);
    clearDevices();
    assert(closes == 2);
    puts("PASS: cleanup closes both handles exactly once");

    reset();
    assert(addDevice(interface_name) == 0);
    clearDevices();
    assert(opens == 2 && closes == 2);
    puts("PASS: registration works again after failure and cleanup");
    return 0;
}
