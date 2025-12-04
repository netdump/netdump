

CC ?= gcc
RM = rm -rf
ECHO = @echo
IF = if
FI = fi
ELSE = else

PROJECT_PATH = $(shell pwd)
THIRD_PATH = $(PROJECT_PATH)/Third

NCURSESW_DIR = ncurses-6.5
PCAP_DIR = libpcap-1.10.5

NCURSESW_TAR = $(NCURSESW_DIR).tar.gz
PCAP_TAR = $(PCAP_DIR).tar.xz

NCURSESW_PATH = $(THIRD_PATH)/ncursesw
PCAP_PATH = $(THIRD_PATH)/pcap


#CFLAGS = -O0 -g
CFLAGS = -O3
CFLAGS += -Wall
#CFLAGS += -fPIE
CFLAGS += -Wno-unused-function
#CFLAGS += -fsanitize=address -g

# -DTRACE -DTOPTRACE 
# the log switch needs to be turned on or off simultaneously.
# -DTRACE -DTOPTRACE 全部打开可以开启记录日志的功能
#CFLAGS += -DTRACE
#CFLAGS += -DTOPTRACE

CFLAGS += -I ./
CFLAGS += -I ${NCURSESW_PATH}/include
CFLAGS += -I ${NCURSESW_PATH}/include/ncursesw/
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

LDFLAGS =
#LDFLAGS += -no-pie
#LDFLAGS += -fsanitize=address
LDFLAGS += $(STATIC) $(STATIC_LIB_PATH) $(STATIC_LIB) $(DYNAMIC) $(DYNAMIC_LIB)

LINK_SCRIPT := link.ld

SRCS = $(wildcard *.c)
SRCS += $(wildcard ./a-f/*.c)
OBJS = $(SRCS:.c=.o)

LOG_FILES = $(wildcard trace[0-9]*.log)

ERROR_COUNT := 0

define check_cmd
	$(if $(shell command -v $(1) 2>/dev/null),\
		$(info "$(1) installed"),\
		$(eval ERROR_COUNT := $$(shell echo $$(($(ERROR_COUNT)+1)))\
		$(info "$(1) not installed")))
endef


TARGET = netdump

.PHONY: all build_deps

all: build_deps $(TARGET)

build_deps:

	$(call check_cmd,gcc)
	$(call check_cmd,make)
	$(call check_cmd,flex)
	$(call check_cmd,bison)

	@$(IF) [ $(ERROR_COUNT) -gt 0 ]; then \
		echo "$(ERROR_COUNT) required tools are not installed"; \
		echo "please install the tools marked as not installed above before continuing."; \
		exit 1; \
	$(ELSE) \
		echo "all required tools are installed"; \
	$(FI)

	@cd $(THIRD_PATH)

	@$(IF) [ ! -f $(THIRD_PATH)/$(NCURSESW_TAR) ]; then \
		echo "Error:  $(THIRD_PATH)/$(NCURSESW_TAR) does not exist"; \
		exit 1; \
	$(FI)

	@$(IF) [ ! -f  $(THIRD_PATH)/$(PCAP_TAR) ]; then \
		echo "Error:  $(THIRD_PATH)/$(PCAP_TAR) does not exist"; \
		exit 1; \
	$(FI)

	@$(IF) [ -d  ${NCURSESW_PATH} ]; then \
		$(RM)  ${NCURSESW_PATH}; \
	$(FI)
	@mkdir -p  ${NCURSESW_PATH}

	@$(IF) [ -d  ${PCAP_PATH} ]; then \
		$(RM)  ${PCAP_PATH}; \
	$(FI)
	@mkdir -p  ${PCAP_PATH}

	tar -xf $(THIRD_PATH)/$(NCURSESW_TAR) -C $(THIRD_PATH)

	cd $(THIRD_PATH)/$(NCURSESW_DIR) && ./configure --prefix=${NCURSESW_PATH} --with-static --without-shared && \
	make && make install

	@cd $(THIRD_PATH)

	tar -xf $(THIRD_PATH)/$(PCAP_TAR) -C $(THIRD_PATH)

	cd $(THIRD_PATH)/$(PCAP_DIR) && ./configure --prefix=${PCAP_PATH} --enable-static --disable-shared --disable-rdma --disable-dbus && \
	make && make install

	$(RM) $(THIRD_PATH)/$(NCURSESW_DIR)

	$(RM) $(THIRD_PATH)/$(PCAP_DIR)

	@cd $(PROJECT_PATH)



$(TARGET): $(OBJS)
	@$(CC) $(OBJS) -o $@ $(LDFLAGS) -T $(LINK_SCRIPT)
	@$(RM) $(OBJS)


%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@


clean:
	@$(RM) $(OBJS) $(TARGET) 
	$(IF) [ -n "$(LOG_FILES)" ]; then \
		$(RM) $(LOG_FILES); \
	$(FI)


debug:
	$(ECHO) "Source files: $(SRCS)"
	$(ECHO) "Object files: $(OBJS)"


.PHONY: all clean debug

