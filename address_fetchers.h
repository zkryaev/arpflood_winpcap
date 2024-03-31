#ifndef ARP_FLOOD_WINPCAP_ADDRESS_FETCHERS_H
#define ARP_FLOOD_WINPCAP_ADDRESS_FETCHERS_H

#include "libraries.h"
#include "struct.h"

// return 0 - success, 1 - error
int getMacAddressOfAdapter(unsigned char *mac, pcap_if_t *dev);

// returns the number of IP addresses of the given device
int getIPv4ListOfAdapter(pcap_if_t *dev, unsigned char ***ip4list);

void init_random();

void generateRandomMAC(unsigned char *mac);

void generateRandomIPv4(unsigned char *ip);


#endif //ARP_FLOOD_WINPCAP_ADDRESS_FETCHERS_H
