#!/usr/bin/env bash

#
# aix-user: a public-domain PoC/attempt to run 32-bit AIX binaries
# on Linux via Unicorn, same idea as 'qemu-user', but for AIX+PPC
# Made by Theldus, 2025-2026
#

TEST_AIX72=y
TEST_AIX73=y

# kill tests
#
# Three things are checked here:
#   a) 'kill -l', both the full list and the signal number form
#   b) the actual signal delivery, against a plain Linux process
#      and against another process running under aix-user
#   c) the error paths (unknown signal name/no such process), which
#      exercise errno conversion.
#

function do_test() {
	# a) 'kill -l': the full signal list.
	lst=$(aix-user ${BIN} -l)
	for sig in HUP INT KILL TERM SEGV; do
		if [[ "${lst}" != *"${sig}"* ]]; then
			failed "kill test failed: '-l' does not list ${sig}!"
			return 1
		fi
	done

	# a) 'kill -l signal number'
	if [[ "$(aix-user ${BIN} -l 15)" != "TERM" ]]; then
		failed "kill test failed: '-l 15' should report TERM!"
		return 1
	fi

	# b) Signal delivery to a regular Linux process.
	sleep 30 &
	pid=$!
	if ! aix-user ${BIN} -TERM ${pid}; then
		failed "kill test failed: unable to signal pid ${pid}!"
		kill -9 ${pid} 2>/dev/null
		return 1
	fi

	wait ${pid} 2>/dev/null
	ret=$?
	if [[ ${ret} != 143 ]]; then
		failed "kill test failed: process not terminated by SIGTERM! (got ${ret})"
		return 1
	fi

	# b) Same thing, but signaling a process running inside the VM,
	# and with the '-s' flavour this time.
	aix-user ${BINS}/sleep 30 &
	pid=$!
	sleep 1

	if ! aix-user ${BIN} -s HUP ${pid}; then
		failed "kill test failed: unable to signal aix-user pid ${pid}!"
		kill -9 ${pid} 2>/dev/null
		return 1
	fi

	wait ${pid} 2>/dev/null
	ret=$?
	if [[ ${ret} != 129 ]]; then
		failed "kill test failed: aix-user not terminated by SIGHUP! (got ${ret})"
		return 1
	fi

	# c) Error paths: unknown signal name and a pid that does not
	# exist, both should fail with status 2.
	aix-user ${BIN} -NOPE 1 2>/dev/null
	if [[ $? != 2 ]]; then
		failed "kill test failed: bad signal name should exit with 2!"
		return 1
	fi

	# 0x7ffffffe: high enough to (hopefully) never be a live pid,
	# but still below AIX's PID_MAX.
	aix-user ${BIN} -TERM 2147483646 2>/dev/null
	if [[ $? != 2 ]]; then
		failed "kill test failed: unknown pid should exit with 2!"
		return 1
	fi
}
