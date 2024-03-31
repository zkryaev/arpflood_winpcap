#ifndef ARP_FLOOD_WINPCAP_DISPLAY_FUNCTIONS_H
#define ARP_FLOOD_WINPCAP_DISPLAY_FUNCTIONS_H

#include "libraries.h"
#include "struct.h"

void printDeviceInfo(unsigned char *mac, unsigned char *ip, pcap_if_t *dev);

void printHexDump(const unsigned char *packet, int packet_size);

#endif //ARP_FLOOD_WINPCAP_DISPLAY_FUNCTIONS_H
