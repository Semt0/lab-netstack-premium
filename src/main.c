#include "device.h"
#include "packetio.h"
#include "smtarp.h"
#include "ip.h"
#include "smtroute.h"
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>

#define DV_INTERVAL 1

void *thread_wrapper(void *arg) {
    int device_id = *(int *)arg;
    
    free(arg); 

    printf("thread begin, start to listen on device %d ...\n", device_id);
    fflush(stdout);
    
    int result = receiveFrames(device_id, -1);
    
    printf("thread end, device %d receiveFrames returned %d\n", device_id, result);
    
    return NULL;
}

static int dispatchFrame(const void* buf, int len, int id) {
    if (buf == NULL || len < (int)sizeof(struct ether_header)) {
        return 0; 
    }

    struct ether_header header;
    memcpy(&header, buf, sizeof(header));

    const uint8_t* payload = (const uint8_t*)buf + sizeof(header);
    int payload_len = len - (int)sizeof(header);

    switch (ntohs(header.ether_type)) {
    case ETHERTYPE_ARP:
        return handleARPframe(payload, payload_len, id);
    case ETHERTYPE_IP: {
        uint8_t local_mac[6];
        if (getDeviceMAC(id, local_mac) != 0) return 0;
        // 只处理发给本接口的单播，忽略抓到的本机发送帧。
        if (memcmp(header.ether_dhost, local_mac, 6) != 0 ||
            memcmp(header.ether_shost, local_mac, 6) == 0) return 0;
        return handleIPPacket(payload, payload_len, id);
    }
    case ETHERTYPE_DV:
        return handleDV(payload, payload_len, id, header.ether_shost);
    default:
        return 0; 
    }
}


int main(int argc, char** argv) {
    if (argc < 2) {
        printf("Usage: %s <device1> <device2> ...\n", argv[0]);
        return -1;
    }

    int id[argc];
    for (int i = 1; i < argc; i++) {
        id[i] = addDevice(argv[i]);
        if (id[i] < 0) return -1;
    }

    for (int i = 1; i < argc; i++) {
        if (initRoutingTable(id[i]) != 0) {
            fprintf(stderr, "initRoutingTable failed on %s\n", argv[i]);
            clearDevices();
            return -1;
        }
    }

    if (setFrameReceiveCallback(dispatchFrame) != 0) {
        return -1;
    }
    
    for (int i = 1; i < argc; i++) {
        int *id_ptr = (int *)malloc(sizeof(int));
        *id_ptr = id[i];

        pthread_t tid;

        if (pthread_create(&tid, NULL, thread_wrapper, id_ptr) != 0) {
            perror("create thread error");
            free(id_ptr); 
            continue;
        }

        // Detached thread, automatically reclaims resources after completion.
        pthread_detach(tid);
    }

    while(1) {
        if (updateRoutingTable() != 0) {
            fprintf(stderr, "updateRoutingTable failed\n");
        }
        // 启动后先发一次，此后每隔一秒遍历所有接口。
        for (int i = 1; i < argc; i++) {
            if (sendDV(id[i]) != 0) {
                fprintf(stderr, "sendDV failed on %s\n", argv[i]);
            }
        }
        sleep(DV_INTERVAL);
    }

    setFrameReceiveCallback(NULL);
    clearDevices();
    return 0;
}
