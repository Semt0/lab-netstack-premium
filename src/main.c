#include "device.h"
#include "packetio.h"
#include "smtarp.h"
#include "ip.h"
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>

void *thread_wrapper(void *arg) {
    int device_id = *(int *)arg;
    
    free(arg); 

    printf("thread begin, start to listen on device %d ...\n", device_id);
    fflush(stdout);
    
    int result = receiveFrames(device_id, -1);
    
    printf("thread end, device %d receiveFrames returned %d\n", device_id, result);
    
    return NULL;
}

static int printIPPacket(const void* buf, int len) {
    struct ip header;
    memcpy(&header, buf, sizeof(header));
    char source[INET_ADDRSTRLEN], destination[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &header.ip_src, source, sizeof(source));
    inet_ntop(AF_INET, &header.ip_dst, destination, sizeof(destination));
    unsigned int header_len = header.ip_hl * 4;
    printf("IPv4 RX src=%s dst=%s length=%d header=%u payload=%u protocol=%u ttl=%u\n",
           source, destination, len, header_len, (unsigned int)len - header_len,
           (unsigned int)header.ip_p, (unsigned int)header.ip_ttl);
    fflush(stdout);
    return 0;
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
    case ETHERTYPE_IP:
        return handleIPPacket(payload, payload_len, id);
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

    if (setIPPacketReceiveCallback(printIPPacket) != 0 ||
        setFrameReceiveCallback(dispatchFrame) != 0) {
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
        sleep(1);
    }

    setFrameReceiveCallback(NULL);
    clearDevices();
    return 0;
}
