#include "ip.h"
#include "device.h"
#include "packetio.h"
#include <string.h>
#include <stdlib.h>
#include <errno.h>
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

    // Simple local delivery only; forwarding is not implemented here.
    struct in_addr local_ip;
    if (getDeviceip(id, &local_ip) != 0 || header.ip_dst.s_addr != local_ip.s_addr) return 0;

    IPPacketReceiveCallback callback = ip_receive_callback;
    // Pass the whole IP datagram, trimming Ethernet padding.
    return callback == NULL ? 0 : callback(buf, total_len);
}
