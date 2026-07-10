#!/usr/bin/env bash

#
# aix-user: a public-domain PoC/attempt to run 32-bit AIX binaries
# on Linux via Unicorn, same idea as 'qemu-user', but for AIX+PPC
# Made by Theldus, 2025-2026
#

TEST_AIX72=y
TEST_AIX73=n # sadly we dont have 'as' nor 'bind' (32-bit) on AIX 7.3

#
# as+bind tests
# A 'bind' test does not make sense without 'as', and a simple 'as'
# test is not as much fun as a 'as'+'bind' test, so lets do both
# here =)
#

#
# Note: At the moment, 'as' and 'bind' requires sigaction(),
# thats why I'm silencing stderr too, since sigaction() is
# not *really* required
#

function cleanup() {
	rm -f hello_world
	rm -f hello_world.o
	rm -f hello_world.s
}

function do_test() {
	# Copy template file and make some mod
	cp hello_world-template.s hello_world.s
	sed -i "s/<placeholder>/$(whoami), at: $(date)/g" hello_world.s

	# Assemble the file
	aix-user ${BINS}/as -a32 -u -mpwr7 -many -o hello_world.o \
	   hello_world.s &>/dev/null

	if [[ ! -f hello_world.o ]]; then
		failed "error while assembling the test file, aborting..."
	fi

	# Link the file
	aix-user ${BIN} < binder_in &>/dev/null
	if [[ ! -f hello_world ]]; then
		cleanup
		failed "error while linking the test file, aborting..."
	fi

	# Execute the program and show its output
	out=$(aix-user hello_world)
	if [[ ${out} != *"Hello, World!"* ]]; then
		cleanup
		failed "failed to execute 'hello_world' binary test"
	fi

	echo ${out}
	cleanup
}
