#!/usr/bin/env bash

#
# aix-user: a public-domain PoC/attempt to run 32-bit AIX binaries
# on Linux via Unicorn, same idea as 'qemu-user', but for AIX+PPC
# Made by Theldus, 2025-2026
#

TEST_AIX72=y
TEST_AIX73=y

# date tests

function do_test() {
	# Seconds test (epoch)
	au=$(TZ=UTC aix-user ${BIN} +"%s")
	ln=$(TZ=UTC date +"%s")

	diff=$((au-ln))
	diff=$((diff * ((diff>0) - (diff<0))))
	if [[ ${diff} > 10 ]]; then
		failed "epoch difference is greater than 10s: (${au} / ${ln})"
		return 1
	fi

	# Some flags test (e.g., Fri 10 Jul 26)
	au=$(TZ=UTC aix-user ${BIN} +"%a %d %h %y")
	ln=$(TZ=UTC date +"%a %d %h %y")
	if [[ "${au}" != ${ln} ]]; then
		failed "formatted date does not match! (${au}) / (${ln})"
		return 1
	fi
}
