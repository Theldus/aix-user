#!/usr/bin/env bash

#
# aix-user: a public-domain PoC/attempt to run 32-bit AIX binaries
# on Linux via Unicorn, same idea as 'qemu-user', but for AIX+PPC
# Made by Theldus, 2025-2026
#

TEST_AIX72=y
TEST_AIX73=y

# sort tests
#
# Many of the tests might require signal processing, such as
# _sigaction syscalls. However, this is only needed for edge
# cases, such as an abrupt interruption and etc, not being
# used in the 'happy path'.
#
# Since aix-user still do not suppots these syscalls, I'm
# ignoring them at the moment.
#

function do_test() {
	au=$(printf "z\nf\nww\na\n" | aix-user ${BIN} 2>/dev/null)
	ln=$(printf "z\nf\nww\na\n" | sort)

	if [[ ${au} != ${ln} ]]; then
		failed "sort test failed, outputs differ!"
		return 1
	fi
}
