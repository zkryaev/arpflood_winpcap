# ARP Flood using WinPcap

This project implements ARP Flood attack using the WinPcap library. ARP Flood is a network attack where the attacker sends a large number of fake ARP requests to overload the ARP table of devices in the network.

## Project Structure

- `address_fetchers.c` and `address_fetchers.h`: Functions to fetch network interface addresses.
- `display_functions.c` and `display_functions.h`: Functions for displaying information in the console.
- `network_utils.c` and `network_utils.h`: Utilities for networking.
- `main.c`: Main program file.
- `struct.h`: Header file containing data structure definitions.
- `CMakeLists.txt`: CMake build script.
- `makefile`: Makefile for building the project without CMake.

## Usage

Simply compile and execute the program. Ensure that you have WinPcap library installed on your system.

## Dependencies

This project depends on the WinPcap library.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
