#include "display_functions.h"

void printDeviceInfo(unsigned char *mac, unsigned char *ip, pcap_if_t *dev) {
    if (dev == NULL) {
        return;
    }
    printf("Network Card Information:\n");
    printf("->  Adapter-Name:   %s\n", dev->name);
    printf("->  Adapter-Desc:   %s\n", dev->description);
    printf("->  Adapter-MAC:\n");
    printf("                dec:   %u.%u.%u.%u.%u.%u\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    printf("                hex:   %02X.%02X.%02X.%02X.%02X.%02X\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    printf("->  Adapter-IPv4:\n");
    printf("                dec:   %u.%u.%u.%u\n", ip[0], ip[1], ip[2], ip[3]);
    printf("                hex:   %02X.%02X.%02X.%02X\n", ip[0], ip[1], ip[2], ip[3]);
}

void printHexDump(const unsigned char *data, int size) {
    printf("-------------------------------\n");
    for (int i = 0; i < size; i++) {
        printf("%02X ", data[i]); // Print each byte in hexadecimal format
        if ((i + 1) % 16 == 0) {
            printf("\n"); // Print newline after every 16 bytes
        }
    }
    printf("\n-------------------------------\n");
}