

CC = gcc
RM = rm -rf
ECHO = @echo
IF = if
FI = fi


NCURSESW_PATH = ./Third/ncursesw
PCAP_PATH = ./Third/pcap


CFLAGS = -O0 -g
CFLAGS += -Wall
CFLAGS += -Wno-unused-function

# -DTRACE -DTOPTRACE 
# the log switch needs to be turned on or off simultaneously.
CFLAGS += -DTRACE
CFLAGS += -DTOPTRACE

CFLAGS += -I ./
CFLAGS += -I ${NCURSESW_PATH}/include
CFLAGS += -I ${PCAP_PATH}/include
CFLAGS += -I ${PCAP_PATH}/include/pcap


STATIC = -Wl,-Bstatic

STATIC_LIB = 
STATIC_LIB += -lmenuw
STATIC_LIB += -lpanelw
STATIC_LIB += -lncursesw
STATIC_LIB += -lpcap

STATIC_LIB_PATH = 
STATIC_LIB_PATH += -L ${NCURSESW_PATH}/lib
STATIC_LIB_PATH += -L ${PCAP_PATH}/lib


DYNAMIC = -Wl,-Bdynamic

DYNAMIC_LIB = -lrt


LDFLAGS += $(STATIC) $(STATIC_LIB_PATH) $(STATIC_LIB) $(DYNAMIC) $(DYNAMIC_LIB)


SRCS = $(wildcard *.c)
SRCS += $(wildcard ./a-f/*.c)
OBJS = $(SRCS:.c=.o)

LOG_FILES = $(wildcard trace[0-9]*.log)


TARGET = netdump


all: ${TARGET}


$(TARGET): $(OBJS)
	$(CC) $(OBJS) -o $@ $(LDFLAGS)
	$(RM) $(OBJS)


%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@


clean:
	$(RM) $(OBJS) $(TARGET)
	$(IF) [ -n "$(LOG_FILES)" ]; then \
		$(RM) $(LOG_FILES); \
	$(FI)


debug:
	$(ECHO) "Source files: $(SRCS)"
	$(ECHO) "Object files: $(OBJS)"


.PHONY: all clean debug

