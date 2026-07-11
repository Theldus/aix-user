#!/usr/bin/env bash

#
# aix-user: a public-domain PoC/attempt to run 32-bit AIX binaries
# on Linux via Unicorn, same idea as 'qemu-user', but for AIX+PPC
# Made by Theldus, 2025-2026
#

TEST_AIX72=y
TEST_AIX73=y

#
# ar tests
# AR is also interesting: since AIX uses big-ar archives, they're
# not compatible with the Linux ar tool, so having the possibility
# to run the original ar tool is pretty cool
#

function cleanup() {
	rm -rf .temp
	rm -rf out
}

function do_test() {
	# Extract libc to a temp dir
	mkdir .temp && cd .temp
	aix-user ${BIN} -x ../../../../.libs72/libc.a
	cd ../

	# Check for its contents
	sha256sum .temp/* > out

	# Compare with baseline
	if ! cmp -s out out_ref; then
		cleanup
		failed "extracted objects do not match reference!"
		return 1
	fi

	cleanup
}
