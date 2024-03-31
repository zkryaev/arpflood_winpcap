#ifndef ARP_FLOOD_WINPCAP_LIBRARIES_H
#define ARP_FLOOD_WINPCAP_LIBRARIES_H

#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <winsock2.h>
#include <iphlpapi.h>

#define HAVE_REMOTE 1 // to ensure compatibility with certain constants

#include "./Include/pcap.h"

#define FRAME_SIZE_TO_SEND 60
#define ARP_REQUEST 1
#define ARP_REPLY 2
#define ETHERNET_TYPE 0x0001
#define ARP_ETHERNET_TYPE 0x0806
#define ARP_PROTO_TYPE_IP 0x0800
#define ARP_HW_TYPE_ETH 1
#define ARP_HW_SIZE 6
#define ARP_PROTO_SIZE 4
#define FAILURE_SEND 1
#define FAILED_MAC_RETRIEVAL 1
#endif //ARP_FLOOD_WINPCAP_LIBRARIES_H
