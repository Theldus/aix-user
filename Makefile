#
# aix-user: a public-domain PoC/attempt to run 32-bit AIX binaries
# on Linux via Unicorn, same idea as 'qemu-user', but for AIX+PPC
# Made by Theldus, 2025
#

CC     ?= cc
#CFLAGS += $(shell pkg-config --cflags unicorn) -g3 -Wall -Wno-unused-variable -fsanitize=address
#LDLIBS += $(shell pkg-config --libs unicorn) -fsanitize=address
CFLAGS += -I$(CURDIR) -I$(CURDIR)/milicodes -I$(CURDIR)/syscalls
CFLAGS += $(shell pkg-config --cflags unicorn) -O3 -Wall -Wno-unused-variable
LDLIBS += $(shell pkg-config --libs unicorn) 
MILIS   = milicodes/strlen.h  milicodes/memcmp.h milicodes/memmove.h
MILIS  += milicodes/strcmp.h  milicodes/strcpy.h milicodes/strstr.h
MILIS  += milicodes/memccpy.h milicodes/memset.h milicodes/fill.h

OBJS  = aix-user.o unix.o xcoff.o gdb.o loader.o mm.o bigar.o
OBJS += util.o milicodes/milicode.o insn_emu.o

# Syscalls
OBJS += syscalls/syscalls.o
OBJS += syscalls/kwrite.o
OBJS += syscalls/__exit.o
OBJS += syscalls/kioctl.o
OBJS += syscalls/read_sysconfig.o
OBJS += syscalls/__loadx.o
OBJS += syscalls/kfcntl.o
OBJS += syscalls/vmgetinfo.o
OBJS += syscalls/brk.o

# Pretty print
Q := @
ifeq ($(V), 1)
	Q :=
endif

.PHONY: all clean test install
all: $(MILIS) aix-user tools/aix-ar tools/aix-dump tools/aix-ldd

# Paths
BINDIR = $(PREFIX)/bin
MANDIR = $(PREFIX)/man
ifeq ($(PREFIX),)
    PREFIX := /usr/local
endif

# Objects
%.o: %.c
	@echo "  CC      $@"
	$(Q)$(CC) $(CFLAGS) -c -o $@ $<

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
	@echo "  MILICODE      $@"
	$(Q)xxd -c 4 -i $< > $@

aix-user: $(OBJS)
	@echo "  LINK    $@"
	$(Q)$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)

tools/aix-ar: tools/aix-ar.o bigar.o
	@echo "  LINK    $@"
	$(Q)$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

tools/aix-dump: tools/aix-dump.o xcoff.o
	@echo "  LINK    $@"
	$(Q)$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

tools/aix-ldd: tools/aix-ldd.o xcoff.o bigar.o
	@echo "  LINK    $@"
	$(Q)$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^

test: aix-user
	@echo "[+] Running tests..."
	$(Q)bash $(CURDIR)/examples/test.sh

install: aix-user tools/aix-ar tools/aix-dump tools/aix-ldd
	@echo "  INSTALL    $@"
	install -d $(DESTDIR)$(BINDIR)
	install -m 755 aix-user $(DESTDIR)$(BINDIR)
	install -m 755 tools/aix-ar   $(DESTDIR)$(BINDIR)
	install -m 755 tools/aix-dump $(DESTDIR)$(BINDIR)
	install -m 755 tools/aix-ldd  $(DESTDIR)$(BINDIR)

uninstall:
	@echo "  UNINSTALL    $@"
	rm -f $(DESTDIR)$(BINDIR)/aix-user
	rm -f $(DESTDIR)$(BINDIR)/aix-ar
	rm -f $(DESTDIR)$(BINDIR)/aix-dump
	rm -f $(DESTDIR)$(BINDIR)/aix-ldd

clean:
	rm -f $(OBJS)
	rm -f tools/*.o
	rm -f aix-user
	rm -f tools/ar
	rm -f tools/dump
	rm -f tools/ldd
