#ifndef SMTROUTE_H
#define SMTROUTE_H
#include <netinet/in.h>
#include <stdint.h>

typedef struct {
    struct in_addr dest;
    struct in_addr mask;
    struct in_addr nextHopIP;
    uint8_t nextHopMAC[6]; // {0, 0, 0, 0, 0, 0} 表示不提供
    char device[128];
} RouteEntry;

/**
* @brief Manully add an item to routing table. Useful when talking
with real Linux machines.
*
* @param dest The destination IP prefix.
* @param mask The subnet mask of the destination IP prefix.
* @param nextHopMAC MAC address of the next hop.
* @param device Name of device to send packets on.
* @return 0 on success , -1 on error
*/
int setRoutingTable(const struct in_addr dest ,
const struct in_addr mask ,
const void* nextHopMAC , const char *device);

// 使用最长前缀匹配寻找下一跳
RouteEntry* findRouter(const struct in_addr ip);

#endif
