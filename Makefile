

CC = gcc
RM = rm -rf
ECHO = @echo


NCURSESW_PATH = ./Third/ncursesw


CFLAGS = -O0 -g
CFLAGS += -Wall
CFLAGS += -DTRACE
CFLAGS += -DTOPTRACE
CFLAGS += -I ./
CFLAGS += -I ${NCURSESW_PATH}/include


LDFLAGS = 
LDFLAGS = -L ${NCURSESW_PATH}/lib


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


%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@


clean:
	$(RM) $(OBJS) $(TARGET)


debug:
	$(ECHO) "Source files: $(SRCS)"
	$(ECHO) "Object files: $(OBJS)"


.PHONY: all clean debug

