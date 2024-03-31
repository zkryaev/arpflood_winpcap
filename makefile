# Just in case you're using a makefile and not cmake :)
# Compiler
CC = gcc

# Compiler flags
CFLAGS = -std=c11 -IInclude

# Linker flags
LDFLAGS = -LLib/x64 -L/path/to/IPHLPAPI/lib

# Libraries to link
LIBS = -lwpcap -lws2_32 -lIPHLPAPI

# Source files
SRCS = main.c \
       address_fetchers.c \
       display_functions.c \
       network_utils.c

# Object files
OBJS = $(SRCS:.c=.o)

# Executable
TARGET = arp_flood_winpcap

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(OBJS) -o $(TARGET) $(LDFLAGS) $(LIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)
