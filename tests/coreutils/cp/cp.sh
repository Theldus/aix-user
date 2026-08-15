#!/usr/bin/env bash

#
# aix-user: a public-domain PoC/attempt to run 32-bit AIX binaries
# on Linux via Unicorn, same idea as 'qemu-user', but for AIX+PPC
# Made by Theldus, 2025-2026
#

TEST_AIX72=y
TEST_AIX73=y

function check_file() {
	h1=$(md5sum "$1" | awk '{print $1}')
	h2=$(md5sum "$2" | awk '{print $1}')

	# Check copy result
	if [[ ${h1} != ${h2} ]]; then
		return 1
	fi
}

#
# cp tests
#
# This test also test 'mv' and 'rm'
#

function do_test() {
	# Copy file
	aix-user ${BIN} ../test_coreutils.sh test.sh

	# Check copy result
	check_file test.sh ../test_coreutils.sh
	if [[ "$?" = 1 ]]; then
		failed "cp test failed, output file differ!"
		return 1
	fi

	# Move/rename file
	aix-user ${BINS}/mv test.sh test2.sh

	# Check copy result
	check_file test2.sh ../test_coreutils.sh
	if [[ "$?" = 1 ]]; then
		failed "mv test failed, output file differ!"
		return 1
	fi

	# Remove file
	aix-user ${BINS}/rm test2.sh
	if [[ -f "test2.sh" ]]; then
		failed "rm test failed, file still exists!"
		return 1
	fi
}
