TOP_DIR = .
INC_DIR = $(TOP_DIR)/inc
SRC_DIR = $(TOP_DIR)/src
BUILD_DIR = $(TOP_DIR)/build

CC=gcc
PROFILE ?= rdt
ifeq ($(PROFILE),rdt)
PROFILE_FLAGS = -DTJU_RDT_PROFILE=1
else ifeq ($(PROFILE),reno)
PROFILE_FLAGS = -DTJU_RDT_PROFILE=0 -DTJU_FULL_RENO=1
else ifeq ($(PROFILE),basic)
PROFILE_FLAGS = -DTJU_RDT_PROFILE=0 -DTJU_FULL_RENO=0
else
$(error PROFILE must be rdt, reno or basic)
endif
FLAGS = -pthread -g -ggdb -DDEBUG -I$(INC_DIR) $(PROFILE_FLAGS)
OBJS = $(BUILD_DIR)/tju_packet.o \
	   $(BUILD_DIR)/kernel.o \
	   $(BUILD_DIR)/tju_tcp.o 



default:all

all: clean server client

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c 
	$(CC) $(FLAGS) -c -o $@ $<

clean:
	-rm -f ./build/*.o client server

server: $(OBJS)
	$(CC) $(FLAGS) ./src/server.c -o server $(OBJS)

client:
	$(CC) $(FLAGS) ./src/client.c -o client $(OBJS) 



	
