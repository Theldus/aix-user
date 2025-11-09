#
# aix-user: a public-domain PoC/attempt to run 32-bit AIX binaries
# on Linux via Unicorn, same idea as 'qemu-user', but for AIX+PPC
# Made by Theldus, 2025
#

CC     ?= cc
CFLAGS += $(shell pkg-config --cflags unicorn) -g3 -Wall -Wno-unused-variable
LDLIBS += $(shell pkg-config --libs unicorn) 

.PHONY: all clean
all: aix-user tools/ar tools/dump

aix-user: vm.o xcoff.o gdb.o loader.o mm.o bigar.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)

tools/ar: tools/ar.o bigar.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

tools/dump: tools/dump.o xcoff.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

clean:
	rm -f *.o
	rm -f tools/*.o
	rm -f aix-user
	rm -f tools/ar
	rm -f tools/dump
