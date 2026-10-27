#include "ip.h"
#include "device.h"
#include "packetio.h"
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <stdio.h>
#include <net/ethernet.h>
#include <net/if_arp.h>
#include <netinet/if_ether.h>
#include "smtarp.h"
#include <unistd.h>
#include "smtroute.h"

static IPPacketReceiveCallback ip_receive_callback = NULL;

int setIPPacketReceiveCallback(IPPacketReceiveCallback callback) {
    ip_receive_callback = callback;
    return 0;
}

// 构建 IP Datagram, 用 struct ip
static uint8_t *buildIPDatagram(const struct in_addr src_ip, const struct in_addr dest_ip,
int proto, const void *buf, int buf_len, size_t* out_total_len) {
    const size_t header_len = 20;
    size_t total_len = header_len + buf_len;
    uint8_t *packet = calloc(1, total_len);
    if (packet == NULL) return NULL;

    struct ip *iphdr = (struct ip *)packet;
    iphdr->ip_v = 4;
    iphdr->ip_hl = 5;
    iphdr->ip_tos = 0;
    iphdr->ip_len = htons((uint16_t)total_len);
    iphdr->ip_id = htons(0);
    iphdr->ip_off = htons(IP_DF);
    iphdr->ip_ttl = 64;
    iphdr->ip_p = proto;
    iphdr->ip_src = src_ip;
    iphdr->ip_dst = dest_ip;
    if (buf_len > 0) memcpy(packet + header_len, buf, (size_t)buf_len);
    iphdr->ip_sum = 0;

    uint32_t sum = 0;
    uint16_t *ptr = (uint16_t *)iphdr;
    for (int i = 0; i < 10; i++) {
        sum += ptr[i];
    }

    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    iphdr->ip_sum = (uint16_t)(~sum); 


    *out_total_len = total_len;
    return packet;
}


int sendIPPacket(const struct in_addr src_ip , const struct in_addr dest_ip ,
int proto , const void *buf , int len) {
    if (len < 0 || proto < 0 || proto > 255 || (len > 0 && buf == NULL)) {
        errno = EINVAL;
        return -1;
    }
    if (len > 1480) {
        errno = EMSGSIZE;
        return -1;
    }
    size_t total_len;
    uint8_t *packet = buildIPDatagram(src_ip, dest_ip, proto, buf, len, &total_len);
    if (packet == NULL) return -1;

    RouteEntry* entry = findRouter(dest_ip);
    if (entry == NULL) {
        free(packet);
        errno = ENETUNREACH;
        return -1;
    }
    uint8_t nextHopMAC[6];
    struct in_addr nextHopIP = entry->nextHopIP;
    int id = findDevice(entry->device);

    memcpy(nextHopMAC, entry->nextHopMAC, 6);

    // 没有 nextHopMAC 时，调用 ARP
    int check = 0;
    for (int i = 0; i < 6; i++) check += (int)nextHopMAC[i]; 
    if (check == 0) {
        int find = 0;
        for (int i = 0; i < 8; i++) {
            if (searchARPcache(nextHopIP, nextHopMAC) == -1) {
                sendARPRequest(src_ip, nextHopIP, id);

                sleep(1);
            } 
            else {
                find = 1;
                break;
            }
        }
        if (find == 0) {
            free(packet);
            return -1;
        }
    }

    int result = sendFrame(packet, (int)total_len, ETHERTYPE_IP, nextHopMAC, id);
    free(packet);
    return result;
}

int handleIPPacket(const void* buf, int len, int id) {
    if (buf == NULL || len < (int)sizeof(struct ip)) return 0;
    if (getDeviceName(id) == NULL) return 0;

    struct ip header;
    memcpy(&header, buf, sizeof(header));
    int header_len = header.ip_hl * 4;
    int total_len = ntohs(header.ip_len);

    if (header.ip_v != 4 || header_len < 20 || header_len > len ||
        total_len < header_len || total_len > len) return 0;
    if (ntohs(header.ip_off) & (IP_MF | IP_OFFMASK)) return 0;

    const uint8_t* bytes = buf;

    uint32_t sum = 0;
    for (int i = 0; i < header_len; i += 2)
        sum += ((uint32_t)bytes[i] << 8) | bytes[i + 1];
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    if (sum != 0xffff) return 0;

    if (isLocalIP(header.ip_dst)) {
        IPPacketReceiveCallback callback = ip_receive_callback;
        return callback == NULL ? 0 : callback(buf, total_len);
    }

    uint32_t destination = ntohl(header.ip_dst.s_addr);
    if ((destination >> 24) == 0 || (destination >> 24) == 127 ||
        (destination >> 28) >= 14) return 0;
    if (header.ip_ttl <= 1 || total_len > 1500) return 0;

    RouteEntry* entry = findRouter(header.ip_dst);
    if (entry == NULL) return 0;
    int out_id = findDevice(entry->device);
    if (out_id < 0) return 0;

    uint8_t nextHopMAC[6];
    memcpy(nextHopMAC, entry->nextHopMAC, 6);
    int mac_sum = 0;
    for (int i = 0; i < 6; i++) mac_sum += nextHopMAC[i];
    if (mac_sum == 0 || (nextHopMAC[0] & 1)) return 0;

    // 保留原数据报，只修改 TTL 和首部校验和，不改接收缓冲区。
    uint8_t packet[1500];
    memcpy(packet, buf, (size_t)total_len);
    packet[8]--;
    packet[10] = 0;
    packet[11] = 0;
    sum = 0;
    for (int i = 0; i < header_len; i += 2)
        sum += ((uint32_t)packet[i] << 8) | packet[i + 1];
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    uint16_t checksum = (uint16_t)(~sum);
    packet[10] = (uint8_t)(checksum >> 8);
    packet[11] = (uint8_t)checksum;

    if (sendFrame(packet, total_len, ETHERTYPE_IP, nextHopMAC, out_id) != 0) {
        fprintf(stderr, "forward IP packet failed on %s\n", entry->device);
    }
    return 0;
}
