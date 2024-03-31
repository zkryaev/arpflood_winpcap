# ARP Flood using WinPcap

This project implements ARP Flood attack using the WinPcap library.

## Project Structure

- `address_fetchers.c` and `address_fetchers.h`: Functions to fetch network interface addresses.
- `display_functions.c` and `display_functions.h`: Functions for displaying information in the console.
- `network_utils.c` and `network_utils.h`: Utilities for networking.
- `libraries.h`: Header file containing the list of libraries used (`winpcap`, `ws2_32`, `iphlpapi`) and main constants.
- `struct.h`: Header file containing data structure definitions.
- `CMakeLists.txt`: CMake build script.
- `makefile`: Makefile for building the project without CMake.

## Usage

Simply compile and execute the program. Ensure that you have WinPcap library installed on your system.

## Dependencies

This project depends on the WinPcap library.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
