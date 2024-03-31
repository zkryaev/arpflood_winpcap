#ifndef ARP_FLOOD_WINPCAP_STRUCT_H
#define ARP_FLOOD_WINPCAP_STRUCT_H

#define ETHER_ADDR_LEN 6
#define IP_ADDR_LEN 4

struct ether_hdr {
    unsigned char dst[ETHER_ADDR_LEN];
    unsigned char src[ETHER_ADDR_LEN];
    unsigned short type;
};

struct arp_hdr {
    unsigned short htype;   // Hardware Type, 1 = Ethernet
    unsigned short ptype;   // Protocol Type, IPv4 = 0x0800
    unsigned char hlen;     // Hardware Address Length
    unsigned char plen;     // Protocol Address Length
    unsigned short oper;    // Operation Code: 1 - ARP_request, 2 - ARP_reply
    unsigned char sha[ETHER_ADDR_LEN];  // Source MAC-Address
    unsigned char spa[IP_ADDR_LEN];  // Source IP Address
    unsigned char tha[ETHER_ADDR_LEN];   // Target MAC Address
    unsigned char tpa[IP_ADDR_LEN];  // Target IP Address
};

#endif //ARP_FLOOD_WINPCAP_STRUCT_H
