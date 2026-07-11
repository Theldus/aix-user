#!/usr/bin/env bash

#
# aix-user: a public-domain PoC/attempt to run 32-bit AIX binaries
# on Linux via Unicorn, same idea as 'qemu-user', but for AIX+PPC
# Made by Theldus, 2025-2026
#

TEST_AIX72=y
TEST_AIX73=n

#
# awk tests
# Sadly awk for AIX 7.3 makes use of some instructions not supported
# by the chosen CPU on Unicorn. I'll pollyfill this later.
#
# Note: Since 'awk' requires _sigaction and __ksetjmp (for whatever)
# reason, I'm simply omitting these errors.
#

function cleanup() {
	rm -rf .temp
	rm -rf out
}

function do_test() {
	out=$(printf "a:b:c:d" | aix-user ${BIN} -F':' '{printf $3}' 2>/dev/null)

	# Compare with baseline
	if [[ "${out}" != "c" ]]; then
		cleanup
		failed "awk failed to extract field"
		return 1
	fi

	cleanup
}
