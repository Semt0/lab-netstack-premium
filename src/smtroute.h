#ifndef SMTROUTE_H
#define SMTROUTE_H
#include <netinet/in.h>
#include <stdint.h>

#define ETHERTYPE_DV 0x88b6

#define DV_VERSION 1
#define DV_INFINITY 16
#define DV_HEADER_LEN 4
#define DV_ENTRY_LEN 12

#define DV_ROUTE_TIMEOUT 5
#define DV_GARBAGE_TIME 5

// DV 载荷：版本(1)、保留零(1)、网络序条目数(2)。
// 每项：目的前缀(4)、掩码(4)、网络序代价(4)。

typedef struct {
    struct in_addr dest;
    struct in_addr mask;
    struct in_addr nextHopIP;
    uint8_t nextHopMAC[6]; // {0, 0, 0, 0, 0, 0} 表示不提供
    char device[128];

    uint8_t metric;

    uint64_t last_update; // 最后采纳可达通告的时钟秒数
    uint64_t invalid_since; // 首次变为不可达的时钟秒数
    int learned_from_dv;
    int valid; // 路由有效性
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

// 初始化指定接口的本机 /32 路由
int initRoutingTable(int id);

// 检查动态路由超时，清理保留期结束的不可达条目。
int updateRoutingTable(void);

// 最长前缀匹配；返回当前线程的副本，下次同线程查询时覆盖
RouteEntry* findRouter(const struct in_addr ip);

// 在指定接口广播距离向量；成功返回 0，失败返回 -1。
int sendDV(int id);

// 处理 DV 载荷，邻居由接收接口和源 MAC 标识
int handleDV(const void* buf, int len, int id, const void* srcMAC);

#endif
