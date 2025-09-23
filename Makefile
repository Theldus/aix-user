#
# aix-user: a public-domain PoC/attempt to run 32-bit AIX binaries
# on Linux via Unicorn, same idea as 'qemu-user', but for AIX+PPC
# Made by Theldus, 2025
#

CC     ?= cc
CFLAGS += $(shell pkg-config --cflags unicorn)
LDLIBS += $(shell pkg-config --libs unicorn)

.PHONY: all clean
all: aix-user

aix-user: vm.o xcoff.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)

clean:
	rm -f *.o
	rm -f aix-user
