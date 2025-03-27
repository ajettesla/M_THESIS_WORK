# Makefile for resource monitor

# Variables
KERNEL_HEADERS ?= /lib/modules/$(shell uname -r)/source/
CLANG ?= clang
LLVM_STRIP ?= llvm-strip
CC ?= gcc

# BPF Compiler flags
# Update BPF_CFLAGS in Makefile
BPF_CFLAGS = -g -O2 -target bpf -D__TARGET_ARCH_x86 
BPF_CFLAGS += -I$(KERNEL_HEADERS)/include
BPF_CFLAGS += -I$(KERNEL_HEADERS)/arch/x86/include
BPF_CFLAGS += -I$(KERNEL_HEADERS)/arch/x86/include/generated
BPF_CFLAGS += -I/usr/include/$(shell uname -m)-linux-gnu  # Critical fix
# Add these to BPF_CFLAGS
BPF_CFLAGS += -I/lib/modules/$(shell uname -r)/build/include/trace/events
BPF_CFLAGS += -I/lib/modules/$(shell uname -r)/build/include/uapi
# Add these flags to BPF_CFLAGS
BPF_CFLAGS += -D__TARGET_ARCH_$(shell uname -m | sed 's/x86_64/x86/')
BPF_CFLAGS += -I$(shell pwd)  # For local vmlinux.h



# User space compiler flags
CFLAGS = -g -O2 -Wall
CFLAGS += -I$(KERNEL_HEADERS)/include
CFLAGS += -I$(KERNEL_HEADERS)/tools/lib
LDFLAGS = -lbpf

# Output files
BPF_OBJ = ebpf_program.o
USER_BIN = monitor

.PHONY: all clean

all: $(USER_BIN)

$(BPF_OBJ): ebpf_program.c
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@
	$(LLVM_STRIP) -g $@

$(USER_BIN): monitor.c $(BPF_OBJ)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

clean:
	rm -f $(BPF_OBJ) $(USER_BIN)
