#ifndef ARP_FLOOD_WINPCAP_NETWORK_UTILS_H
#define ARP_FLOOD_WINPCAP_NETWORK_UTILS_H

#include "libraries.h"
#include "struct.h"
#include "address_fetchers.h"
#include "display_functions.h"

pcap_if_t *selectDevice(pcap_if_t ** all_devices);

void buildEthernetHeader(struct ether_hdr *ether_header, unsigned char *src_mac, unsigned char *dst_mac);

void buildArpHeader(struct arp_hdr *arp_header, unsigned char *sender_mac, unsigned char *sender_ip,
                    unsigned char *target_mac, unsigned char *target_ip);

int sendPacketViaWinPcap(pcap_t *handle, unsigned char *packet, int packet_size);

void performArpFloodAttack(pcap_if_t *dev, unsigned char *src_mac, unsigned char *src_ip, int num_packets_to_send);

#endif //ARP_FLOOD_WINPCAP_NETWORK_UTILS_H
