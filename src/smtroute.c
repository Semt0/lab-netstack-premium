#include "smtroute.h"
#include <string.h>
#include <stdlib.h>
#include <netinet/ip.h>

#define MAX_ROUTE_NUM 64

// 维护当前 host/router 的路由表
static RouteEntry RoutingTable[64];
static int Route_num = 0;


int setRoutingTable(const struct in_addr dest ,
const struct in_addr mask ,
const void* nextHopMAC , const char *device) {
   if (Route_num >= MAX_ROUTE_NUM) return -1; 
   if (nextHopMAC == NULL || device == NULL) return -1;

   size_t name_len = strlen(device);
   if (name_len >= sizeof(RoutingTable[0].device)) return -1;

   for (int i = 0; i < Route_num; i++) {
        if (dest.s_addr == RoutingTable[i].dest.s_addr && mask.s_addr == RoutingTable[i].mask.s_addr) return 0;
   }

   RouteEntry* entry = &RoutingTable[Route_num];
   entry->dest = dest;
   entry->mask = mask;
   entry->nextHopIP.s_addr = 0;
   memcpy(entry->nextHopMAC, nextHopMAC, 6);
   memcpy(entry->device, device, name_len + 1);
   Route_num++;

   return 0;
}

// 使用最长前缀匹配寻找下一跳
RouteEntry* findRouter(const struct in_addr ip) {
    int cur_mask_len = -1;
    int cur_router_num = -1;
    for (int i = 0; i < Route_num; i++) {
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
    return cur_router_num < 0 ? NULL : &RoutingTable[cur_router_num];
}
