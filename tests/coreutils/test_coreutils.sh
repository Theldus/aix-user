#!/usr/bin/env bash

#
# aix-user: a public-domain PoC/attempt to run 32-bit AIX binaries
# on Linux via Unicorn, same idea as 'qemu-user', but for AIX+PPC
# Made by Theldus, 2025-2026
#

#
# Note: Not exactly/entirely 'coreutils', but for the lack of a better
# name, I'm calling all 'native'/'standard' AIX tools as coreutils.
#
# Note 2: This is not a full test suite and should *not* be considered
# one. The main objective here is: make sure aix-user still runs
# the tools I know it runs with the flags I've tested, i.e., avoid
# regressions =)
#
# Note 3: Yes, I know, for the most part, GNU coreutils is a superset
# of the 'original' "coreutils", so mostly all commands are available
# with minor cosmetic differences. Someone then might say that my
# VM is useless, then I bring to them:
#
# - ar:   uses big-ar archive, not the same archive found for the ar on Linux
# - bind: AIX's linker, this is not the same as GNU ld.
# - as:   AIX's assembler, this is not the same as the GNU as.
# - dump: similar in spirit to 'readelf', but exclusive to AIX and only
#         works for XCOFF32/64 files; very useful to have in hand.
# - restore/restbyname: Extracts files from archives that are created with
#                       the backup command, again, AIX stuff.
# <others>
#

# Paths
CURDIR="$( cd "$(dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
ROOT_DIR="$(realpath ${CURDIR}/../..)"

cd "${CURDIR}"

echo "Coreutils tests for aix-user"
echo "----------------------------"
echo "> Current dir     : ${CURDIR}"
echo "> Root project dir: ${ROOT_DIR}"
echo

if [[ ! -d ${ROOT_DIR}/.libs72 ]] || [[ ! -d "${ROOT_DIR}/.libs73" ]]; then
	echo "The folders .libs72/.libs73 are required in the root"
	echo "directory, aborting..."
	exit 1
fi

LIBS72="${ROOT_DIR}/.libs72"
BINS72="${ROOT_DIR}/.bins72"
BINS73="${ROOT_DIR}/.bins73"
LIBS73="${ROOT_DIR}/.libs73"
export PATH="${PATH}:${ROOT_DIR}"

tests=0
errors=0
function failed() {
	echo ">>>> FAIL: $1 <<<<" 1>&2
	errors=$((errors+1))
	return 1
}

function file_info() {
	echo "Binary: ${1}"
	echo "SHA256: $(sha256sum ${1} | cut -d' ' -f1)"
	echo "Size:   $(wc -c ${1}     | cut -d' ' -f1) bytes"
	echo "File:   $(file ${1}      | grep -Po "${1}: \K.+")"
}

#
# For each folder in the PORTS directory, invoke the build.sh
# When each 'do_test()' function is called:
#
# - The code runs inside its own test folder
# - There's a 'BINS' var pointing to the right folder where that
#   binary would be found
# - The AIX_USER_LIB_PATH is already exported, so aix-user knows which libs
#   to read
# - 'aix-user' is also add to the PATH, so no need to any extra shenanigans
#   here
#
test_num=1
for folder in *; do
	if [[ ! -d ${folder} ]]; then
		continue
	fi

	test_file="${folder}/${folder}.sh"
	if [[ ! -f ${test_file} ]]; then
		printf "Expected test_file does not exist, skipping (${test_file})\n"
		continue
	fi

	printf "[${test_num}] Running ${test_file}...\n"
	source ${test_file}

	if [[ ${TEST_AIX72} = "y" ]]; then
		BINS="${BINS72}"
		BIN="${BINS}/${folder}"
		VER="72"

		printf "=> AIX 7.2 tests enabled, executing test...\n"
		export AIX_USER_LIB_PATH="${LIBS72}"
		file_info ${BIN}

		cd "${folder}"
		do_test
		if [[ $? = 0 ]]; then
			printf "Result: SUCCESS\n"
		else
			printf "Result: FAILED\n"
		fi
		cd ../
		tests=$((tests+1))
	fi

	if [[ ${TEST_AIX73} = "y" ]]; then
		BINS="${BINS73}"
		BIN="${BINS}/${folder}"
		VER="73"

		printf "\n=> AIX 7.3 tests enabled, executing test...\n"
		export AIX_USER_LIB_PATH="${LIBS73}"
		file_info ${BIN}

		cd "${folder}"
		do_test
		if [[ $? = 0 ]]; then
			printf "Result: SUCCESS\n"
		else
			printf "Result: FAILED\n"
		fi
		cd ../
		tests=$((tests+1))
	fi

	echo
	test_num=$((test_num+1))
done

if [[ ${errors} != 0 ]]; then
	failed "${errors} tests have failed (out of ${tests})"
	exit 1
fi

echo "All tests have succeeded!"
