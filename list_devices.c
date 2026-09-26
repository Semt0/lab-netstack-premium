#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>

int main(void) {
    pcap_if_t *alldevs = NULL;
    char error_buffer[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&alldevs, error_buffer) == -1) {
        fprintf(stderr, "pcap_findalldevs: %s\n", error_buffer);
        return 1;
    }

    if (alldevs == NULL) {
        printf("No capture devices found.\n");
        return 0;
    }

    int id = 0;

    for (pcap_if_t *dev = alldevs;
         dev != NULL;
         dev = dev->next) {

        printf("\nDevice %d: %s\n", id++, dev->name);

        bpf_u_int32 network_raw;
        bpf_u_int32 mask_raw;

        if (pcap_lookupnet(
                dev->name,
                &network_raw,
                &mask_raw,
                error_buffer
            ) == -1) {

            fprintf(stderr,
                    "Cannot query %s: %s\n",
                    dev->name,
                    error_buffer);
            continue;
        }

        char network[INET_ADDRSTRLEN];
        char subnet_mask[INET_ADDRSTRLEN];
        struct in_addr address;

        address.s_addr = network_raw;

        if (inet_ntop(
                AF_INET,
                &address,
                network,
                sizeof(network)
            ) == NULL) {
            perror("inet_ntop");
            continue;
        }

        address.s_addr = mask_raw;

        if (inet_ntop(
                AF_INET,
                &address,
                subnet_mask,
                sizeof(subnet_mask)
            ) == NULL) {
            perror("inet_ntop");
            continue;
        }

        printf("Network: %s\n", network);
        printf("Subnet mask: %s\n", subnet_mask);
    }

    pcap_freealldevs(alldevs);
    return 0;
}