#include "smtarp.h"
#include <string.h>
#include <stdlib.h>
#include <net/ethernet.h>
#include <net/if_arp.h>
#include <netinet/if_ether.h>
#include "device.h"
#include "packetio.h"
#include <pthread.h>
#include <arpa/inet.h>

#define MAX_ARP_SIZE 128

typedef struct {
    struct in_addr ip;
    uint8_t mac[6];
} arpentry;

static arpentry arplist[MAX_ARP_SIZE];
static int arp_num = 0;

static pthread_mutex_t arp_mutex = PTHREAD_MUTEX_INITIALIZER;

int sendARPRequest(const struct in_addr src_ip, 
    const struct in_addr target_ip, int id) {

    uint8_t broadcast_mac[6];
    for (int i = 0; i < 6; i++) broadcast_mac[i] = 0xff;

    unsigned char src_mac[6];
    if (getDeviceMAC(id, src_mac) == -1) return -1;

    struct ether_arp arp = {0};
    arp.ea_hdr.ar_hrd = htons(ARPHRD_ETHER);
    arp.ea_hdr.ar_pro = htons(ETHERTYPE_IP);
    arp.ea_hdr.ar_hln = 6;
    arp.ea_hdr.ar_pln = 4;
    arp.ea_hdr.ar_op = htons(ARPOP_REQUEST);

    memcpy(arp.arp_sha, src_mac, 6);
    memcpy(arp.arp_spa, &src_ip.s_addr, 4);
    memcpy(arp.arp_tpa, &target_ip.s_addr, 4);

    return sendFrame(
        &arp,
        sizeof(arp),
        ETHERTYPE_ARP,
        broadcast_mac,
        id
    );
}

int sendARPReply(const struct in_addr src_ip, const struct in_addr target_ip, 
uint8_t* target_mac, int id) {
    if (target_mac == NULL) return -1;

    unsigned char src_mac[6];
    if (getDeviceMAC(id, src_mac) == -1) return -1;

    struct ether_arp arp = {0};
    arp.ea_hdr.ar_hrd = htons(ARPHRD_ETHER);
    arp.ea_hdr.ar_pro = htons(ETHERTYPE_IP);
    arp.ea_hdr.ar_hln = 6;
    arp.ea_hdr.ar_pln = 4;
    arp.ea_hdr.ar_op = htons(ARPOP_REPLY);

    memcpy(arp.arp_sha, src_mac, 6);
    memcpy(arp.arp_spa, &src_ip.s_addr, 4);
    memcpy(arp.arp_tha, target_mac, 6);
    memcpy(arp.arp_tpa, &target_ip.s_addr, 4);

    return sendFrame(
        &arp,
        sizeof(arp),
        ETHERTYPE_ARP,
        target_mac,
        id
    );
}

int searchARPcache(const struct in_addr target_ip, uint8_t* return_mac) {
    if (return_mac == NULL) return -1;

    int result = -1;
    pthread_mutex_lock(&arp_mutex);
    for (int i = 0; i < arp_num; i++) {
        if (arplist[i].ip.s_addr == target_ip.s_addr) {
            memcpy(return_mac, arplist[i].mac, 6);
            result = 0;
            break;
        }
    }
    pthread_mutex_unlock(&arp_mutex);
    return result;
}

int handleARPframe(const void* buf, int len, int id) { 
    if (buf == NULL || len < (int)sizeof(struct ether_arp)) return -1;

    struct ether_arp arp;
    memcpy(&arp, buf, sizeof(arp));

    struct in_addr sender_ip;
    struct in_addr target_ip;
    memcpy(&sender_ip.s_addr, arp.arp_spa, 4);
    memcpy(&target_ip.s_addr, arp.arp_tpa, 4);
    
    uint8_t sender_mac[6];
    memcpy(&sender_mac, arp.arp_sha, 6);

    uint16_t op = ntohs(arp.ea_hdr.ar_op);
    struct in_addr src_ip;
    if (getDeviceip(id, &src_ip) == -1) return -1;

    switch (op) {
        case ARPOP_REQUEST:
            if (src_ip.s_addr != target_ip.s_addr) return 0;
            sendARPReply(src_ip, sender_ip, sender_mac, id);
            /* fall through */
        case ARPOP_REPLY:
            pthread_mutex_lock(&arp_mutex);
            for (int i = 0; i < arp_num; i++) {
                if (sender_ip.s_addr == arplist[i].ip.s_addr) {
                    memcpy(arplist[i].mac, sender_mac, 6);
                    pthread_mutex_unlock(&arp_mutex);
                    return 0;
                }
            }
            if (arp_num >= MAX_ARP_SIZE) {
                pthread_mutex_unlock(&arp_mutex);
                return -1;
            }
            arplist[arp_num].ip = sender_ip;
            memcpy(arplist[arp_num].mac, sender_mac, 6);
            arp_num++;
            pthread_mutex_unlock(&arp_mutex);
            return 0;
        default:
            return 0;
    }    

}
