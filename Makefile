#
# aix-user: a public-domain PoC/attempt to run 32-bit AIX binaries
# on Linux via Unicorn, same idea as 'qemu-user', but for AIX+PPC
# Made by Theldus, 2025
#

CC     ?= cc
#CFLAGS += $(shell pkg-config --cflags unicorn) -g3 -Wall -Wno-unused-variable -fsanitize=address
#LDLIBS += $(shell pkg-config --libs unicorn) -fsanitize=address
CFLAGS += -I$(CURDIR) -I$(CURDIR)/milicodes -I$(CURDIR)/syscalls
CFLAGS += $(shell pkg-config --cflags unicorn) -g3 -Wall -Wno-unused-variable
LDLIBS += $(shell pkg-config --libs unicorn) 
MILIS   = milicodes/strlen.h  milicodes/memcmp.h milicodes/memmove.h
MILIS  += milicodes/strcmp.h  milicodes/strcpy.h milicodes/strstr.h
MILIS  += milicodes/memccpy.h milicodes/memset.h milicodes/fill.h

OBJS  = vm.o unix.o xcoff.o gdb.o loader.o mm.o bigar.o
OBJS += util.o milicodes/milicode.o 

# Syscalls
OBJS += syscalls/syscalls.o
OBJS += syscalls/kwrite.o
OBJS += syscalls/__exit.o

.PHONY: all clean
all: $(MILIS) aix-user tools/ar tools/dump

# Rules for milicode build
# Binaries are generated via:
# (AIX)   gcc strlen.c -c -O3 (copy object to Linux)
# (Linux) powerpc64-linux-gnu-objcopy -O binary --only-section=.text \
#             strlen.o strlen.bin
# (Linux) (Optional): to see flat bin contents:
#         powerpc64-linux-gnu-objdump \
#            -b binary -m powerpc:common -EB -D strlen.bin
# Obs:
# (Linux) file strlen.o
# strlen.o: executable (RISC System/6000 V3.1) or obj module not stripped
#          
milicodes/%.h: milicodes/%.bin
	xxd -c 4 -i $< > $@

aix-user: $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)

tools/ar: tools/ar.o bigar.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

tools/dump: tools/dump.o xcoff.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

clean:
	rm -f $(OBJS)
	rm -f tools/*.o
	rm -f aix-user
	rm -f tools/ar
	rm -f tools/dump
