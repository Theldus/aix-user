#
# aix-user: a public-domain PoC/attempt to run 32-bit AIX binaries
# on Linux via Unicorn, same idea as 'qemu-user', but for AIX+PPC
# Made by Theldus, 2025-2026
#

CC     ?= cc
#CFLAGS += -I$(CURDIR)/.deps-unicorn/include -g3 -Wall -Wno-unused-variable -fsanitize=address
#LDLIBS +=   $(CURDIR)/.deps-unicorn/lib/libunicorn.a -fsanitize=address
CFLAGS += -I$(CURDIR) -I$(CURDIR)/milicodes
CFLAGS += -I$(CURDIR)/syscalls -I$(CURDIR)/syscalls/include
CFLAGS += -I$(CURDIR)/.deps-unicorn/include -O3 -Wall -Wno-unused-variable
LDLIBS +=   $(CURDIR)/.deps-unicorn/lib/libunicorn.a

OBJS  = aix-user.o unix.o xcoff.o gdb.o loader.o mm.o bigar.o
OBJS += util.o milicodes/milicode.o insn_emu.o

# Syscalls
OBJS += syscalls/syscalls.o syscalls/errno.o
OBJS += syscalls/kwrite.o
OBJS += syscalls/__exit.o
OBJS += syscalls/kioctl.o
OBJS += syscalls/read_sysconfig.o
OBJS += syscalls/__loadx.o
OBJS += syscalls/kfcntl.o
OBJS += syscalls/vmgetinfo.o
OBJS += syscalls/brk.o
OBJS += syscalls/get{ug}idx.o
OBJS += syscalls/statx.o
OBJS += syscalls/kopen.o
OBJS += syscalls/close.o
OBJS += syscalls/kread.o
OBJS += syscalls/klseek_lseek.o
OBJS += syscalls/getdirent.o
OBJS += syscalls/mntctl.o
OBJS += syscalls/sys_parm.o
OBJS += syscalls/_getpid.o
OBJS += syscalls/access.o
OBJS += syscalls/unlink.o
OBJS += syscalls/rmdir.o
OBJS += syscalls/times.o
OBJS += syscalls/appgetrlimit.o
OBJS += syscalls/chmod.o
OBJS += syscalls/umask.o
OBJS += syscalls/chown.o
OBJS += syscalls/chdir.o
OBJS += syscalls/uname.o
OBJS += syscalls/kill.o
OBJS += syscalls/nanosleep.o
OBJS += syscalls/truncate.o
OBJS += syscalls/mmap.o
OBJS += syscalls/kpread.o
OBJS += syscalls/kpwrite.o
OBJS += syscalls/fchmod.o
OBJS += syscalls/fchown.o
OBJS += syscalls/shmat.o
OBJS += syscalls/pipe.o
OBJS += syscalls/kfork.o
OBJS += syscalls/kwaitpid.o

# Pretty print
Q := @
ifeq ($(V), 1)
	Q :=
endif

.PHONY: all clean test-syscalls test-coreutils install
all: aix-user tools/aix-ar tools/aix-dump tools/aix-ldd

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

#
# Unicorn submodule build
#
.deps-unicorn/lib/libunicorn.a:
	@echo "  UNICORN CONFIGURE"
	$(Q)cmake -B unicorn/build -S unicorn \
		-DUNICORN_ARCH=ppc \
		-DCMAKE_BUILD_TYPE=Release \
		-DUNICORN_BUILD_TESTS=OFF \
		-DCMAKE_INSTALL_LIBDIR=lib \
		-DCMAKE_INSTALL_PREFIX="$(CURDIR)/.deps-unicorn"
	@echo "  UNICORN BUILD"
	$(Q)cmake --build unicorn/build -j$$(nproc)
	@echo "  UNICORN INSTALL"
	$(Q)cmake --install unicorn/build

TOOL_OBJS = tools/aix-ar.o tools/aix-dump.o tools/aix-ldd.o
$(OBJS) $(TOOL_OBJS): | .deps-unicorn/lib/libunicorn.a

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

tests/statx/reference: tests/statx/reference.c
	@echo "  LINK    $@"
	$(Q)$(CC) -o $@ $^

test-syscalls: aix-user tests/syscalls/statx/reference tests/syscalls/getdirent/reference
	@echo "[+] Running syscalls tests..."
	$(Q)bash $(CURDIR)/tests/syscalls/tests.sh

test-coreutils:
	@echo "[+] Running coreutils tests..."
	$(Q)bash $(CURDIR)/tests/coreutils/test_coreutils.sh

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
	rm -f tests/syscalls/statx/reference
	rm -f tests/syscalls/getdirent/reference
