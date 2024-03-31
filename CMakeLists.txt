cmake_minimum_required(VERSION 3.27)
project(arp_flood_winpcap C)

set(CMAKE_C_STANDARD 11)

# Path to WinPcap header files
include_directories(Include)

# Path to the directory with the WinPcap library
link_directories(Lib/x64)

# Path to the directory with the IPHLPAPI library
link_directories(path/to/IPHLPAPI/lib)

add_executable(arp_flood_winpcap main.c
        struct.h
        libraries.h
        address_fetchers.h
        address_fetchers.c
        display_functions.h
        display_functions.c
        network_utils.h
        network_utils.c)

# Library references (for linking)
target_link_libraries(arp_flood_winpcap PRIVATE wpcap ws2_32 IPHLPAPI)
