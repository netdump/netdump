

CC = gcc
RM = rm -rf
ECHO = @echo


NCURSESW_PATH = ./Third/ncursesw


CFLAGS = -O0 -g
CFLAGS += -Wall
CFLAGS += -I ./
CFLAGS += -I ${NCURSESW_PATH}/include


LDFLAGS = 
LDFLAGS = -L ${NCURSESW_PATH}/lib


LINKLIB = 
LINKLIB += -lncursesw
LINKLIB += -lmenuw
LINKLIB += -lpanelw


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

