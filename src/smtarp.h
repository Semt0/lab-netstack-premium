#ifndef SMTARP_H
#define SMTARP_H
#include <netinet/ip.h>

// 发送 ARP Request
int sendARPRequest(const struct in_addr src_ip, 
    const struct in_addr target_ip, int id);

int sendARPReply(const struct in_addr src_ip, const struct in_addr target_ip, 
    uint8_t* target_mac, int id);

// 查 ARP 缓存
int searchARPcache(const struct in_addr target_ip, uint8_t* reture_mac);

// buf 从 ARP 头开始，len 为以太网载荷长度（可能包含填充），id 为接收接口。
int handleARPframe(const void* buf, int len, int id);

#endif

