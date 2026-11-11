#!/usr/bin/env bash
#
# aix-user: a public-domain PoC/attempt to run 32-bit AIX binaries
# on Linux via Unicorn, same idea as 'qemu-user', but for AIX+PPC
# Made by Theldus, 2025-2026
#

# User-configurable env vars
AIX_USER_BIN=${AIX_USER_BIN:-/usr/local/bin/aix-user}
AIX_RESCUE_CD_SYSROOT=${AIX_RESCUE_CD_SYSROOT:-notfound}
AIX_TARGET_SYSROOT=${AIX_TARGET_SYSROOT:-notfound}
AIX_ISO_MOUNT=${AIX_ISO_MOUNT:-notfound}

# Misc variables
RESTBYNAME_BIN="${AIX_RESCUE_CD_SYSROOT}/usr/sbin/restbyname"
CURFOLD=$(pwd)
BCKUSER=$(whoami)
GCC="${AIX_TARGET_SYSROOT}/usr/bin/gcc"

# Links
TOOLBOX_URL="https://public.dhe.ibm.com/aix/freeSoftware/aixtoolbox/RPMS"
LINKS=(
	${TOOLBOX_URL}/ppc-7.2/gcc13/gcc13-13.3.0-1.aix7.2.ppc.rpm
	${TOOLBOX_URL}/ppc-7.2/gcc13/gcc13-cpp-13.3.0-1.aix7.2.ppc.rpm
	${TOOLBOX_URL}/ppc-7.2/gcc13/libgcc13-13.3.0-1.aix7.2.ppc.rpm
	${TOOLBOX_URL}/ppc-7.2/gcc13/libgomp13-13.3.0-1.aix7.2.ppc.rpm
	${TOOLBOX_URL}/ppc-7.2/gcc/libgcc-13-2.aix7.2.ppc.rpm
	${TOOLBOX_URL}/ppc-7.2/gcc/gcc-13-2.aix7.2.ppc.rpm
	${TOOLBOX_URL}/ppc-7.2/gcc/libgomp-13-2.aix7.2.ppc.rpm
	${TOOLBOX_URL}/ppc/mpfr/mpfr-4.2.2-1.aix7.1.ppc.rpm
	${TOOLBOX_URL}/ppc/gmp/gmp-6.3.0-2.aix7.1.ppc.rpm
	${TOOLBOX_URL}/ppc/libmpc/libmpc-1.4.1-1.aix7.1.ppc.rpm
	${TOOLBOX_URL}/ppc/zstd/libzstd-1.5.7-100.aix7.1.ppc.rpm
)

# aix-user exports options
export AIX_USER_LOG_OFF=1   # ignore missing _sigaction, this is harmless
export AIX_USER_LIB_PATH="${AIX_RESCUE_CD_SYSROOT}/usr/lib"

function abort() {
	printf "$@, aborting...\n"
	exit 1
}
function log() {
	printf "=> $@\n"
}
function warn() {
	printf "=> WARNING: $@\n" 1>&2
}

function check_environment() {
	if [[ ! -f "${AIX_USER_BIN}" ]]; then
		abort "aix-user not found in (${AIX_USER_BIN})!"
	fi
	if [[ ! -f "${RESTBYNAME_BIN}" ]]; then
		abort "restbyname not found in (${RESTBYNAME_BIN})!"
	fi
	if [[ ! -f "${AIX_RESCUE_CD_SYSROOT}/usr/lib/libc.a" ||
	      ! -f "${AIX_RESCUE_CD_SYSROOT}/usr/lib/libefs.a" ||
	      ! -f "${AIX_RESCUE_CD_SYSROOT}/usr/lib/libcrypt.a" ]]; then
		abort "libc.a, libefs.a or libcrypt.a not found at Rescue CD sysroot!"
	fi
	if [[ ! -d "${AIX_TARGET_SYSROOT}" ]]; then
		abort "AIX_TARGET_SYSROOT not defined and/or not exist!"
	fi
	if [[ ! -f "${AIX_ISO_MOUNT}/installp/ppc/bos.adt" ||
	      ! -f "${AIX_ISO_MOUNT}/installp/ppc/bos" ]]; then
		abort "'bos.adt' and 'bos' not found at the specified ISO MOUNT!"
	fi
	if ! command -v wget > /dev/null; then
		abort "wget must exist in order to download the RPM files!"
	fi
	if ! command -v rpm2cpio > /dev/null; then
		abort "rpm2cpio must exist in order to extract the RPM files!"
	fi
	if ! command -v sh > /dev/null; then
		abort "sh must exist in order to run fixincl!"
	fi
	# Remove trailing '/', if any.
	if [[ "${AIX_TARGET_SYSROOT}" != "/" ]]; then
		AIX_TARGET_SYSROOT="${AIX_TARGET_SYSROOT%/}"
	fi
}

#
# Call or skip a certain setup step
#  $1 = description
#  $2 = function name
#
function call_or_skip() {
	local answer=""
	printf "\n[+] $1\n"
	printf "  Do you want to proceed (ENTER) or skip? (s): "
	read -r answer
	if [[ "${answer}" = "s" ]]; then
		printf "skipped\n"
		return
	fi
	$2
}

function configure_binfmt() {
	if mount | grep -q "/proc/sys/fs/binfmt_misc"; then
		printf "  already configured...\n"
		return
	fi
	sudo mount binfmt_misc -t binfmt_misc /proc/sys/fs/binfmt_misc
	printf ":AIX:M::\x01\xdf::${AIX_USER_BIN}:" | \
		sudo tee /proc/sys/fs/binfmt_misc/register > /dev/null
}

function extract_headers_binaries() {
	log "Extracting headers..."
	cd "${AIX_TARGET_SYSROOT}"
	sudo -E "${RESTBYNAME_BIN}" -xnvqf "${AIX_ISO_MOUNT}/installp/ppc/bos.adt"

	log "Extracting bins + libs..."
	sudo -E "${RESTBYNAME_BIN}" -xnvqf "${AIX_ISO_MOUNT}/installp/ppc/bos"

	log "Changing folders perms: from 5XX to 7XX"
	sudo find "${AIX_TARGET_SYSROOT}" -type d -perm -u=rx ! -perm -u=w -exec chmod u+w {} +

	log "Changing ownership back to the current user (${BCKUSER})"
	sudo chown -R "${BCKUSER}:" .

	log "Cleaning up some uneeded files/folders/symlinks"
	rm -rf bosinst.data image.data lpp_name
	rm -rf usr/{adm,aix,lbin,lost+found,lpd,lpp,man,share,spool,sys,sysv,ucb,usg,websm}
	rm -rf usr/ccs/bin/bind64   # ld priorizes bind64 over bind
	rm -rf usr/lib/{bind64,cron,expreserve,exrecover,makewhatis,mkwhatis,terminfo}
	rm -rf usr/bin/{cancel,lp,lpq,lpr,lprm,lpstat}

	log "Converting symlinks from absolute to relative path..."
	find "${AIX_TARGET_SYSROOT}" -type l -lname '/*' | while IFS= read -r link; do
		target=$(readlink "$link")
		rel=$(realpath -ms --relative-to="$(dirname "$link")" "$AIX_TARGET_SYSROOT$target")
		echo "$link -> $rel"
		ln -sfn "$rel" "$link"
	done

	# AIX does other things while installing these RPMs... since we're
	# installing them 'by hand', we need to mimick these too.
	log "Headers symlinks..."
	ln -s sys/errno.h    usr/include/
	ln -s sys/inttypes.h usr/include/
	ln -s sys/stdint.h   usr/include/
	ln -s ../acl.h       usr/include/sys/acl.h
	ln -s ../errlog.h    usr/include/sys/errlog.h
	ln -s corral.h       usr/include/sys/wpar.h
	ln -s corralid.h     usr/include/sys/wparid.h
	ln -s sys/timeb.h    usr/include/

	log "Minor details..."
	mkdir home
	mkdir tmp
	ln -s usr/lib lib
}

function download_gcc() {
	cd "${CURFOLD}"
	mkdir -p download_gcc
	for link in ${LINKS[@]}; do
		local file=${link##*/}
		if [[ -f "download_gcc/${file}" ]]; then
			log "File (${file}) already exists, skipping download..."
			continue
		fi
		log "Downloading (${file}):"
		wget "${link}" -O "download_gcc/${file}"
	done
}

function extract_and_patch_gcc() {
	cd "${CURFOLD}/download_gcc" || abort "'download_gcc' folder must exist!"
	cd "${AIX_TARGET_SYSROOT}"   || abort "AIX_TARGET_SYSROOT must exist!"
	for link in ${LINKS[@]}; do
		local file=${link##*/}
		if [[ ! -f "${CURFOLD}/download_gcc/${file}" ]]; then
			warn "RPM file (${file}) do NOT existing, skipping extraction..."
			warn "Please verify why there is a missing file!!!"
			continue
		fi
		log "Extracting RPM (${file})..."
		rpm2cpio "${CURFOLD}/download_gcc/${file}" | cpio -idmv
	done

	log "Creating some useful GCC symlinks"
	ln -s ../../opt/freeware/bin/gcc-13     usr/bin/gcc
	ln -s ../../opt/freeware/lib/libmpc.a   usr/lib
	ln -s ../../opt/freeware/lib/libmpfr.a  usr/lib
	ln -s ../../opt/freeware/lib/libgmp.a   usr/lib
	ln -s ../../opt/freeware/lib/libgcc_s.a usr/lib
	ln -s ../../opt/freeware/lib/libzstd.a  usr/lib
	ln -s ../ccs/bin/as   usr/bin
	ln -s ../ccs/bin/bind usr/bin
}

function gcc_fixincludes() {
	cd "${AIX_TARGET_SYSROOT}" || abort "AIX_TARGET_SYSROOT must exist!"

	# Create a symlink so host paths work inside aix-user too:
	#  Since aix-user in sysroot-mode expect paths all guest-relative,
	#  creating this symlink makes it possible to refer to the sysroot
	#  using the host-relative path. This is specially useful when
	#  tools running on host need to call AIX tools.
	#
	# We need this for the fixincl: the shell scripts will be run in the
	# host, and thus, all paths are host-relative.
	local S="${AIX_TARGET_SYSROOT}"
	mkdir -p "$S$(dirname "$S")"
	ln -s "$(realpath --relative-to="$S$(dirname "$S")" "$S")" "$S$S"

	# fixincl calls /bin/sh.
	# Since we're unable (ATM) to run shells directly on aix-user, we copy
	# the host shell into our sysroot
	mkdir bin
	cp $(command -v sh) bin

	# fixincl attempts to call sed in a place it didnt exist
	ln -sf ../../../usr/bin/sed opt/freeware/bin/sed

	# Change libraries and aix-sysroot to our new sysroot, instead of the
	# Rescue CD
	export AIX_USER_LIB_PATH="${AIX_TARGET_SYSROOT}/usr/lib"
	export AIX_USER_SYSROOT_PATH="${AIX_TARGET_SYSROOT}"

	# fix headers =)
	log "Fixing headers (via mkheaders)..."
	./opt/freeware/libexec/gcc/powerpc-ibm-aix7.2.0.0/13/install-tools/mkheaders "$S/opt/freeware" "$S"
}

function test_gcc() {
	cd "${AIX_TARGET_SYSROOT}/home" || abort "home folder must exist!"
	cat <<EOF > hello.c
#include <stdio.h>
int main(void) {
	puts("Hello, World!, from aix-user");
}
EOF
	if [[ ! -e ${GCC} ]]; then
		abort "GCC binary not found, something went very wrong!"
	fi

	# Change libraries and aix-sysroot to our new sysroot, instead of the
	# Rescue CD
	export AIX_USER_LIB_PATH="${AIX_TARGET_SYSROOT}/usr/lib"
	export AIX_USER_SYSROOT_PATH="${AIX_TARGET_SYSROOT}"

	log "GCC version:"
	"${GCC}" --version
	log "GCC binary format:"
	file -L "${GCC}"
	log "Building hello world..."
	"${GCC}" hello.c -o hello
	log "File type:"
	file hello
	log "Executing file:"
	./hello  # works, due to binfmt xD
}

check_environment
call_or_skip "Binfmt: this is needed in order to call AIX binaries (requires root)" \
             configure_binfmt

call_or_skip "AIX headers + binaries extraction for ISO image (requires root)" \
             extract_headers_binaries

call_or_skip "Download GCC files (~41.5 MiB)" download_gcc

call_or_skip "Extract and patch GCC .rpm files" extract_and_patch_gcc

call_or_skip "Fix GCC include headers" gcc_fixincludes

call_or_skip "Test GCC" test_gcc
