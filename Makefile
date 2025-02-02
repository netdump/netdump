

CC = gcc
RM = rm -rf
ECHO = @echo


NCURSESW_PATH = ./Third/ncursesw
PCAP_PATH = ./Third/pcap


CFLAGS = -O0 -g
CFLAGS += -Wall
CFLAGS += -DTRACE
CFLAGS += -DTOPTRACE
CFLAGS += -I ./
CFLAGS += -I ${NCURSESW_PATH}/include
CFLAGS += -I ${PCAP_PATH}/include
CFLAGS += -I ${PCAP_PATH}/include/pcap


LDFLAGS = 
LDFLAGS = -L ${NCURSESW_PATH}/lib
LDFLAGS = -L ${PCAP_PATH}/lib



LINKLIB = 
LINKLIB += -lmenuw
LINKLIB += -lpanelw
LINKLIB += -lncursesw


LDFLAGS += $(LINKLIB)


SRCS = $(wildcard *.c)
OBJS = $(SRCS:.c=.o)


TARGET = netdump


all: ${TARGET}


$(TARGET): $(OBJS)
	$(CC) $(OBJS) -o $@ $(LDFLAGS)
	$(RM) $(OBJS)


%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@


clean:
	$(RM) $(OBJS) $(TARGET)


debug:
	$(ECHO) "Source files: $(SRCS)"
	$(ECHO) "Object files: $(OBJS)"


.PHONY: all clean debug

