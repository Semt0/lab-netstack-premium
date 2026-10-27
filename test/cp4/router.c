#include "device.h"
#include "packetio.h"
#include "smtarp.h"
#include "ip.h"
#include "smtroute.h"
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <time.h>
#include <unistd.h>

#define DV_INTERVAL 1

typedef struct {
    int* id;
    int count;
} RouterDevices;

static int dispatchFrame(const void* buf, int len, int id) {
    if (buf == NULL || len < (int)sizeof(struct ether_header)) return 0;

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

static int receiveIP(const void* buf, int len) {
    if (buf == NULL || len < (int)sizeof(struct ip)) return 0;

    struct ip header;
    memcpy(&header, buf, sizeof(header));
    int header_len = header.ip_hl * 4;
    if (header.ip_p != 253 || header_len < 20 || header_len > len) return 0;

    char src[INET_ADDRSTRLEN], dest[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &header.ip_src, src, sizeof(src));
    inet_ntop(AF_INET, &header.ip_dst, dest, sizeof(dest));

    printf("[%ld] RX src=%s dst=%s ttl=%u payload=%.*s\n",
           (long)time(NULL), src, dest, header.ip_ttl,
           len - header_len, (const char*)buf + header_len);
    return 0;
}

static void* receiveThread(void* arg) {
    int id = *(int*)arg;
    printf("start to listen on %s\n", getDeviceName(id));

    int result = receiveFrames(id, -1);
    fprintf(stderr, "receiveFrames returned %d on %s\n",
            result, getDeviceName(id));
    return NULL;
}

static void* routingThread(void* arg) {
    RouterDevices* devices = arg;

    while (1) {
        if (updateRoutingTable() != 0) {
            fprintf(stderr, "updateRoutingTable failed\n");
        }
        for (int i = 0; i < devices->count; i++) {
            if (sendDV(devices->id[i]) != 0) {
                fprintf(stderr, "sendDV failed on %s\n",
                        getDeviceName(devices->id[i]));
            }
        }
        sleep(DV_INTERVAL);
    }
    return NULL;
}

static void showRoute(struct in_addr dest) {
    char destination[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &dest, destination, sizeof(destination));

    RouteEntry* entry = findRouter(dest);
    if (entry == NULL) {
        printf("[%ld] UNREACHABLE dst=%s\n",
               (long)time(NULL), destination);
        return;
    }

    char prefix[INET_ADDRSTRLEN], mask[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &entry->dest, prefix, sizeof(prefix));
    inet_ntop(AF_INET, &entry->mask, mask, sizeof(mask));
    const uint8_t* mac = entry->nextHopMAC;

    printf("[%ld] ROUTE dst=%s prefix=%s mask=%s metric=%u device=%s "
           "next_hop_mac=%02x:%02x:%02x:%02x:%02x:%02x learned_from_dv=%d\n",
           (long)time(NULL), destination, prefix, mask, entry->metric,
           entry->device, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
           entry->learned_from_dv);
}

static void sendPacket(struct in_addr dest, const char* payload) {
    size_t len = strlen(payload);
    if (len > 1480) {
        fprintf(stderr, "Payload must not exceed 1480 bytes\n");
        return;
    }

    char destination[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &dest, destination, sizeof(destination));

    RouteEntry* entry = findRouter(dest);
    if (entry == NULL) {
        printf("[%ld] UNREACHABLE dst=%s\n",
               (long)time(NULL), destination);
        return;
    }

    // 从动态路由选出的出口获取源地址，不添加手工路由。
    int id = findDevice(entry->device);
    struct in_addr src;
    if (getDeviceip(id, &src) != 0) {
        fprintf(stderr, "Cannot obtain source IPv4 address\n");
        return;
    }

    if (sendIPPacket(src, dest, 253, payload, (int)len) != 0) {
        perror("sendIPPacket");
        return;
    }

    char source[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &src, source, sizeof(source));
    printf("[%ld] TX src=%s dst=%s payload=%s\n",
           (long)time(NULL), source, destination, payload);
}

int main(int argc, char** argv) {
    if (argc < 2) {
        printf("Usage: %s <device1> <device2> ...\n", argv[0]);
        return -1;
    }

    // 终端录制或重定向输出时也立即显示实验结果。
    setvbuf(stdout, NULL, _IONBF, 0);

    int id[argc - 1];
    for (int i = 0; i < argc - 1; i++) {
        id[i] = addDevice(argv[i + 1]);
        if (id[i] < 0) return -1;
    }
    for (int i = 0; i < argc - 1; i++) {
        if (initRoutingTable(id[i]) != 0) {
            fprintf(stderr, "initRoutingTable failed on %s\n", argv[i + 1]);
            return -1;
        }
    }

    if (setFrameReceiveCallback(dispatchFrame) != 0 ||
        setIPPacketReceiveCallback(receiveIP) != 0) return -1;

    for (int i = 0; i < argc - 1; i++) {
        pthread_t tid;
        if (pthread_create(&tid, NULL, receiveThread, &id[i]) != 0) {
            fprintf(stderr, "create receive thread failed\n");
            return -1;
        }
        pthread_detach(tid);
    }

    RouterDevices devices = {.id = id, .count = argc - 1};
    pthread_t tid;
    if (pthread_create(&tid, NULL, routingThread, &devices) != 0) {
        fprintf(stderr, "create routing thread failed\n");
        return -1;
    }
    pthread_detach(tid);

    printf("Commands: route <ip> | send <ip> <payload> | quit\n");
    char line[1600];
    while (fgets(line, sizeof(line), stdin) != NULL) {
        // 超长命令整行丢弃，避免剩余内容被当作下一条命令。
        if (strchr(line, '\n') == NULL && !feof(stdin)) {
            int ch;
            while ((ch = getchar()) != '\n' && ch != EOF) {}
            fprintf(stderr, "Command too long\n");
            continue;
        }

        char command[16], destination[INET_ADDRSTRLEN], payload[1600];
        int count = sscanf(line, "%15s %15s %1599[^\n]",
                           command, destination, payload);
        if (count < 1) continue;
        if (strcmp(command, "quit") == 0) break;
        if ((strcmp(command, "route") != 0 || count != 2) &&
            (strcmp(command, "send") != 0 || count != 3)) {
            fprintf(stderr, "Usage: route <ip> | send <ip> <payload> | quit\n");
            continue;
        }

        struct in_addr dest;
        if (inet_pton(AF_INET, destination, &dest) != 1) {
            fprintf(stderr, "Invalid destination IPv4 address\n");
            continue;
        }

        if (strcmp(command, "route") == 0) showRoute(dest);
        else sendPacket(dest, payload);
    }

    // 返回 main 结束整个进程，由系统回收仍在使用的 pcap 句柄。
    return 0;
}
