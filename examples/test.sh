#!/usr/bin/env bash

#
# aix-user: a public-domain PoC/attempt to run 32-bit AIX binaries
# on Linux via Unicorn, same idea as 'qemu-user', but for AIX+PPC
# Made by Theldus, 2025-2026
#

CURDIR="$( cd "$(dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
ROOTDIR="${CURDIR}/../"
any_error=0
test_num=0

function do_test() {
	local name="$1"     # Test name
	shift
	local exp_rc="$1"   # Expected return code
	shift

	printf "Test #${test_num} (${name})... ret code:"

	pushd . &>/dev/null
	cd "${CURDIR}/${name}"
	"${ROOTDIR}/aix-user" -L "${ROOTDIR}/.libs" "${name}" "$@" > out
	rc="$?"
	if [ "${rc}" -ne "${exp_rc}" ]; then
		echo "[${name}] produced wrong ret code, expected: ${exp_rc}"
		echo "[${name}] found ${rc}!"
		any_error=1
	fi

	if ! cmp -s out out_ref; then
		echo "[${name}] produced wrong output, see diff:"
		diff -u out out_ref
		any_error=1
	fi
	popd &>/dev/null
	printf "${rc}\n"
	test_num=$((test_num+1))
}

function do_script_test() {
	local name="$1"     # Test name
	shift
	local exp_rc="$1"   # Expected return 
	shift

	echo "Test (via script) #${test_num} (${name})..."

	pushd . &>/dev/null
	cd "${CURDIR}/${name}"
	bash "${name}" "$@"
	rc="$?"
	if [ "${rc}" -ne "${exp_rc}" ]; then
		echo "[${name}] produced wrong ret code, expected: ${exp_rc}"
		echo "[${name}] found ${rc}!"
		any_error=1
	fi
	popd &>/dev/null
	test_num=$((test_num+1))
	echo "  Ret code: ${rc}"
}

do_test "args_env" 42 a b c d
do_test "sbrk" 0
do_script_test "statx" 0

if [ "${any_error}" -eq 1 ]; then
	echo "One or more tests have failed!"
	exit 1
else
	echo "All tests succeeded!"
fi
