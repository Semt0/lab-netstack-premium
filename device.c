#include "device.h"
#include <pcap.h>
#include <stdio.h>
#include <string.h>

#define MAX_DEVICE_NUM 16

typedef struct {
    char name[128];
    pcap_t* handle;
} Device;

static Device devices_list[MAX_DEVICE_NUM];
static int num_devices = 0;

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

    id = num_devices++;
    
    strcpy(devices_list[id].name, device);
    devices_list[id].handle = handle;
    
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
