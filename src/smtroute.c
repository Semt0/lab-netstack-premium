#include "smtroute.h"
#include "device.h"
#include "packetio.h"
#include <string.h>
#include <stdlib.h>
#include <netinet/ip.h>
#include <pthread.h>
#include <time.h>

#define MAX_ROUTE_NUM 64

// 维护当前 host/router 的路由表
static RouteEntry RoutingTable[MAX_ROUTE_NUM];
static int Route_num = 0;
static pthread_mutex_t route_mutex = PTHREAD_MUTEX_INITIALIZER;

// snapshot
static int snapshotRoutingTable(RouteEntry snapshot[MAX_ROUTE_NUM]) {
    pthread_mutex_lock(&route_mutex);

    int count = Route_num;
    memcpy(snapshot, RoutingTable, (size_t)count * sizeof(snapshot[0]));
    pthread_mutex_unlock(&route_mutex);
    return count;
}

int setRoutingTable(const struct in_addr dest ,
const struct in_addr mask ,
const void* nextHopMAC , const char *device) {
   if (nextHopMAC == NULL || device == NULL) return -1;

   size_t name_len = strlen(device);
   if (name_len >= sizeof(RoutingTable[0].device)) return -1;

   pthread_mutex_lock(&route_mutex);

   if (Route_num >= MAX_ROUTE_NUM) {
        pthread_mutex_unlock(&route_mutex);
        return -1;
   }

   for (int i = 0; i < Route_num; i++) {
        if (dest.s_addr == RoutingTable[i].dest.s_addr && mask.s_addr == RoutingTable[i].mask.s_addr) {
            pthread_mutex_unlock(&route_mutex);
            return 0;
        }
   }

   RouteEntry* entry = &RoutingTable[Route_num];
   entry->dest = dest;
   entry->mask = mask;
   entry->nextHopIP.s_addr = 0;
   memcpy(entry->nextHopMAC, nextHopMAC, 6);
   memcpy(entry->device, device, name_len + 1);

   // 手工条目的通告代价默认 1，不参与动态超时。
   entry->metric = 1;
   entry->last_update = 0;
   entry->invalid_since = 0;
   entry->learned_from_dv = 0;
   entry->valid = 1;
   Route_num++;
   pthread_mutex_unlock(&route_mutex);

   return 0;
}

int initRoutingTable(int id) {
    const char* device = getDeviceName(id);
    struct in_addr ip;
    uint8_t mac[6];
    if (device == NULL || getDeviceip(id, &ip) != 0 || getDeviceMAC(id, mac) != 0) return -1;

    struct in_addr mask = {.s_addr = htonl(0xffffffffU)};
    pthread_mutex_lock(&route_mutex);
    int route_num = -1;
    for (int i = 0; i < Route_num; i++) {
        if (RoutingTable[i].dest.s_addr == ip.s_addr && RoutingTable[i].mask.s_addr == mask.s_addr) {
            route_num = i;
            break;
        }
    }

    if (route_num < 0) {
        if (Route_num >= MAX_ROUTE_NUM) {
            pthread_mutex_unlock(&route_mutex);
            return -1;
        }
        route_num = Route_num++;
    }

    RouteEntry* entry = &RoutingTable[route_num];
    memset(entry, 0, sizeof(RouteEntry));
    entry->dest = ip;
    entry->mask = mask;
    memcpy(entry->nextHopMAC, mac, 6);
    strcpy(entry->device, device);
    // 到本机的距离为 0，在所有接口正常通告，不参与动态超时。
    entry->metric = 0;
    entry->learned_from_dv = 0;
    entry->valid = 1;
    pthread_mutex_unlock(&route_mutex);
    return 0;
}

int updateRoutingTable(void) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) return -1;
    uint64_t current_time = (uint64_t)now.tv_sec;

    pthread_mutex_lock(&route_mutex);
    for (int i = 0; i < Route_num; ) {
        RouteEntry* entry = &RoutingTable[i];
        if (!entry->learned_from_dv) {
            i++;
            continue;
        }

        if (entry->valid && current_time >= entry->last_update &&
            current_time - entry->last_update >= DV_ROUTE_TIMEOUT) {
            entry->metric = DV_INFINITY;
            entry->valid = 0;
            entry->invalid_since = current_time;
        }

        if (!entry->valid && current_time >= entry->invalid_since &&
            current_time - entry->invalid_since >= DV_GARBAGE_TIME) {
            // 删除后把后续条目前移，继续检查当前位置，避免漏掉连续失效项。
            for (int j = i + 1; j < Route_num; j++) RoutingTable[j - 1] = RoutingTable[j];
            Route_num--;
            memset(&RoutingTable[Route_num], 0, sizeof(RouteEntry));
            continue;
        }
        i++;
    }
    pthread_mutex_unlock(&route_mutex);
    return 0;
}

// 使用最长前缀匹配寻找下一跳
RouteEntry* findRouter(const struct in_addr ip) {
    static _Thread_local RouteEntry result;
    pthread_mutex_lock(&route_mutex);

    int cur_mask_len = -1;
    int cur_router_num = -1;
    for (int i = 0; i < Route_num; i++) {
        if (!RoutingTable[i].valid || RoutingTable[i].metric >= DV_INFINITY) continue;
        struct in_addr dest = RoutingTable[i].dest;
        struct in_addr mask = RoutingTable[i].mask;
        if ((ip.s_addr & mask.s_addr) != dest.s_addr) continue;
        int mask_len = 0;
        for (int j = 31; j >= 0; j--) {
            if ((((unsigned int)1)<<j) & mask.s_addr) mask_len++;
        }
        if (cur_mask_len != -1 && cur_mask_len >= mask_len) continue;
        cur_mask_len = mask_len;
        cur_router_num = i;
    }
    if (cur_router_num >= 0) result = RoutingTable[cur_router_num];
    pthread_mutex_unlock(&route_mutex);
    return cur_router_num < 0 ? NULL : &result;
}

int sendDV(int id) {
    if (getDeviceHandle(id, DEVICE_TX) == NULL) {
        return -1;
    }

    RouteEntry snapshot[MAX_ROUTE_NUM];
    int snapshot_count = snapshotRoutingTable(snapshot);
    if (snapshot_count < 0) return -1;

    int packet_len = DV_HEADER_LEN + snapshot_count * DV_ENTRY_LEN;

    if (packet_len > 1500) {
        return -1;
    }

    uint8_t packet[DV_HEADER_LEN + MAX_ROUTE_NUM * DV_ENTRY_LEN] = {0};
    packet[0] = DV_VERSION;
    uint16_t count = htons((uint16_t)snapshot_count);
    memcpy(packet + 2, &count, 2);

    for (int i = 0; i < snapshot_count; i++) {
        RouteEntry* entry = &snapshot[i];
        uint32_t metric = entry->metric;
        if (!entry->valid || metric >= DV_INFINITY) metric = DV_INFINITY;

        // 本地起始条目不做毒性逆转。
        if (entry->learned_from_dv && findDevice(entry->device) == id) {
            metric = DV_INFINITY;
        }

        int offset = DV_HEADER_LEN + i * DV_ENTRY_LEN;
        memcpy(packet + offset, &entry->dest.s_addr, 4);
        memcpy(packet + offset + 4, &entry->mask.s_addr, 4);
        metric = htonl(metric);
        memcpy(packet + offset + 8, &metric, 4);
    }

    uint8_t broadcast_mac[6];
    for (int i = 0; i < 6; i++) broadcast_mac[i] = 0xff;

    return sendFrame(
        packet,
        packet_len,
        ETHERTYPE_DV,
        broadcast_mac,
        id
    );
}

int handleDV(const void* buf, int len, int id, const void* srcMAC) {
    if (buf == NULL || len < DV_HEADER_LEN || len > 1500) return 0;
    if (srcMAC == NULL) return -1;

    const char* device = getDeviceName(id);
    uint8_t local_mac[6];
    if (device == NULL || getDeviceMAC(id, local_mac) != 0) return -1;

    const uint8_t* source = srcMAC;
    int mac_sum = 0;
    for (int i = 0; i < 6; i++) mac_sum += source[i];
    if (mac_sum == 0 || (source[0] & 1) || memcmp(source, local_mac, 6) == 0) return 0;

    const uint8_t* packet = buf;
    if (packet[0] != DV_VERSION || packet[1] != 0) return 0;

    uint16_t count;
    memcpy(&count, packet + 2, 2);
    count = ntohs(count);
    if (count > MAX_ROUTE_NUM || len < DV_HEADER_LEN + count * DV_ENTRY_LEN) return 0;

    // 先检查整份通告，避免报文后半段损坏时已经改动了路由表。
    for (int i = 0; i < count; i++) {
        int offset = DV_HEADER_LEN + i * DV_ENTRY_LEN;
        struct in_addr dest, mask;
        uint32_t metric;
        memcpy(&dest.s_addr, packet + offset, 4);
        memcpy(&mask.s_addr, packet + offset + 4, 4);
        memcpy(&metric, packet + offset + 8, 4);
        uint32_t inverse = ~ntohl(mask.s_addr);
        if ((inverse & (inverse + 1)) != 0 ||
            (dest.s_addr & mask.s_addr) != dest.s_addr || ntohl(metric) > DV_INFINITY) return 0;
    }

    if (count == 0) return 0;
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) return -1;

    pthread_mutex_lock(&route_mutex);
    for (int i = 0; i < count; i++) {
        int offset = DV_HEADER_LEN + i * DV_ENTRY_LEN;
        struct in_addr dest, mask;
        uint32_t metric;
        memcpy(&dest.s_addr, packet + offset, 4);
        memcpy(&mask.s_addr, packet + offset + 4, 4);
        memcpy(&metric, packet + offset + 8, 4);
        metric = ntohl(metric);
        if (metric < DV_INFINITY) metric++;

        int route_num = -1;
        for (int j = 0; j < Route_num; j++) {
            if (RoutingTable[j].dest.s_addr == dest.s_addr &&
                RoutingTable[j].mask.s_addr == mask.s_addr) {
                route_num = j;
                break;
            }
        }

        if (route_num < 0) {
            if (metric >= DV_INFINITY || Route_num >= MAX_ROUTE_NUM) continue;
            route_num = Route_num++;
            memset(&RoutingTable[route_num], 0, sizeof(RouteEntry));
        } else {
            RouteEntry* entry = &RoutingTable[route_num];
            if (!entry->learned_from_dv) continue;

            int same_next_hop = strcmp(entry->device, device) == 0 &&
                memcmp(entry->nextHopMAC, source, 6) == 0;

            // 当前下一跳的坏消息也要接受，其他邻居只提供更好的可达路径。
            if (!same_next_hop && (metric >= DV_INFINITY ||
                (entry->valid && metric >= entry->metric))) continue;
        }

        RouteEntry* entry = &RoutingTable[route_num];
        entry->dest = dest;
        entry->mask = mask;
        entry->nextHopIP.s_addr = 0;
        memcpy(entry->nextHopMAC, source, 6);
        strcpy(entry->device, device);
        entry->metric = (uint8_t)metric;
        entry->learned_from_dv = 1;

        if (metric >= DV_INFINITY && entry->valid) entry->invalid_since = (uint64_t)now.tv_sec;
        entry->valid = metric < DV_INFINITY;

        if (entry->valid) {
            entry->last_update = (uint64_t)now.tv_sec;
            entry->invalid_since = 0;
        }
    }
    pthread_mutex_unlock(&route_mutex);
    return 0;
}
