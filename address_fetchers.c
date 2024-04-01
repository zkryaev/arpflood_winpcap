#include "address_fetchers.h"

#define IP_STR_LEN 16
#define ETHER_STR_LEN 24

int getMacAddressOfAdapter(unsigned char *mac, pcap_if_t *dev) {
    ULONG bufferSize = 0;
    PIP_ADAPTER_ADDRESSES adapterInfo = NULL;
    DWORD dwRetVal = 0;

    // Getting the buffer size
    if (GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_ALL_INTERFACES, NULL, adapterInfo, &bufferSize) !=
        ERROR_BUFFER_OVERFLOW) {
        printf("Error when getting the buffer size\n");
        return 1;
    }

    adapterInfo = (PIP_ADAPTER_ADDRESSES) malloc(bufferSize);
    if (!adapterInfo) {
        printf("Memory allocation error\n");
        return 1;
    }

    // Getting information about network adapters
    if ((dwRetVal = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_ALL_INTERFACES, NULL, adapterInfo, &bufferSize)) ==
        NO_ERROR) {
        PIP_ADAPTER_ADDRESSES adapter = adapterInfo;
        while (adapter) {
            if (adapter->PhysicalAddressLength > 0) {
                // Check if the current adapter matches the device you need
                char *selectedAdapterName = strstr(dev->name, adapter->AdapterName);
                if (selectedAdapterName != NULL && strcmp(adapter->AdapterName, selectedAdapterName) == 0) {
                    memcpy(mac, adapter->PhysicalAddress, adapter->PhysicalAddressLength);
                    free(adapterInfo);
                    return 0;
                }
            }
            adapter = adapter->Next;
        }
    } else {
        printf("Error when getting information about network adapters\n");
    }
    free(adapterInfo);
    return 0;
}

int getIPv4ListOfAdapter(pcap_if_t *dev, unsigned char ***ip4list) {
    if (dev == NULL) {
        return 0;
    }
    pcap_addr_t *addr;

    // Counting the number of IP addresses on -dev-
    int ip4_count = 0;
    for (addr = dev->addresses; addr != NULL; addr = addr->next) {
        if (addr->addr->sa_family == AF_INET) {
            ip4_count++;
        }
    }

    (*ip4list) = malloc(ip4_count * sizeof(unsigned char *));
    for (int i = 0; i < ip4_count; i++) {
        (*ip4list)[i] = (unsigned char *) malloc(IP_ADDR_LEN * sizeof(unsigned char));
    }

    int i = 0;
    char ip_str[IP_STR_LEN];
    char *token;
    for (addr = dev->addresses; addr != NULL; addr = addr->next) {
        if (addr->addr->sa_family == AF_INET) {
            // snprintf returns a string, and strtok is used to extract the corresponding IP octets by index
            snprintf(ip_str, 16, "%s", inet_ntoa(((struct sockaddr_in *) addr->addr)->sin_addr));
            token = strtok(ip_str, ".");
            int j = 0;
            while (token != NULL && j < 4) {
                (*ip4list)[i][j] = atoi(token);
                token = strtok(NULL, ".");
                j++;
            }
            i++;
        }
    }
    if (i < 0 || ip4_count <= 0) {
        return 0;
    }
    return ip4_count;
}

void init_random() {
    unsigned int seed = (unsigned int)(time(NULL) * clock());
    seed ^= (unsigned int) clock();
    srand(seed);
}

void generateRandomMAC(unsigned char *mac) {
    for (int i = 0; i < 6; i++) {
        mac[i] = rand() % 256;
    }
}

void generateRandomIPv4(unsigned char *ip) {
    ip[0] = 192;
    ip[1] = 162;
    ip[2] = (unsigned char) (rand() % 256);
    ip[3] = (unsigned char) (rand() % 256);
}
