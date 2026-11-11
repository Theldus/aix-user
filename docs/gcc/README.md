# Running AIX's GCC via `aix-user`
An unaware user might question the usefulness of executing the AIX's GCC port on `aix-user`: "if the intention is to build binaries native to AIX on a Linux machine, wouldn't it be better to just use a cross compiler?". Yes, definitely! The thing is, as of this writing (2026-11-10) there is no way to do so.

To be more specific: both GCC and Clang/LLVM have only partial support for AIX. GCC, for instance, relies on binutils for the assembler and linker, and even so, its support is limited:

>_The native as and ld are recommended for bootstrapping on AIX. The GNU Assembler, GNU Linker, and GNU Binutils version 2.20 is the minimum level that supports bootstrap on AIX 5. The GNU Assembler has not been updated to support AIX 6 or AIX 7. The native AIX tools do interoperate with GCC._
>
> Source: https://gcc.gnu.org/install/specific.html#x-ibm-aix

Clang/LLVM, on the other hand, is able to generate object files for AIX, but its linker, `lld`, also does not supports AIX (XCOFF format):

>_The linker supports ELF (Unix), PE/COFF (Windows), Mach-O (macOS) and WebAssembly in descending order of completeness. Internally, LLD consists of several different linkers. The ELF port is the one that will be described in this document. The PE/COFF port is complete, including Windows debug info (PDB) support._
>
> Source: https://lld.llvm.org/

Interestingly enough, both compilers work fine on AIX itself: the hardest part for both compilers is the linker, and on AIX they use the native one.

`aix-user` is able to run GCC from beginning to end, including the AIX tools: `as`, `ar`, `bind`, and `ld`.

## Preparing the sysroot
In order to be able to cross-compile for AIX, it is needed to have access to the system headers, libraries, binaries, and etc. The steps described in [Minimal setup via Standalone Diagnostics CD]are not enough: you really need access to a full system, or at least to the setup media. How to get access to an AIX environment is beyond the scope of this tutorial, but I can recommend the IBM Cloud.

There are many ways to build a sysroot and here I'll list two: a) via ISO image and b) via a 'Live System', i.e., from a real AIX.

> [!WARNING]
> More recent environments, such as the AIX 7.3 TL03 SP2, ship the `bind` tool only for 64-bit, so it is not supported. The most recent AIX version that ships 32-bit binaries (as of now) is the 7.2 TL05 SP13 (7200-05-13), released on 2026-08-14.

### a) via ISO image
In case you have no access to a live AIX but do have an ISO image of the DVD setup, it is possible to extract the binaries from there and configure a sysroot.

> [!NOTE]
> Before following this step, it is needed to first follow the steps described in [Minimal setup via Standalone Diagnostics CD], and the reason is simple: the packages inside the ISO image are in the format "AIX backup/restore format file" or "BFF": a proprietary IBM's format, similar to a tarball. In order to extract these files, we can use the `restbyname` tool, provided in the Diagonistics CD, which can be executed via `aix-user`.

Once the 'mini-sysroot' is set up via SD-CD, run the script available in [make_aix_sysroot_gcc_iso.sh]. This script is partially interactive, and does the following steps:
1. Configure binfmt
2. Extract the headers and programs from the ISO image
3. Download GCC, CPP and their dependencies (~41.5MiB).
4. Extract GCC, configure the paths and fix GCC includes via `mkheaders`.

Before executing, the following environment variables need to be exported:
```text
export AIX_RESCUE_CD_SYSROOT= <Rescue CD's sysroot folder>
export AIX_TARGET_SYSROOT=    <final folder where the sysroot will be created, the folder must exist>
export AIX_ISO_MOUNT=         <folder where the AIX ISO image is currently mounted>
```

and execute with (simplified output):

```bash
$ ./docs/gcc/make_aix_sysroot_gcc_iso.sh
[+] Binfmt: this is needed in order to call AIX binaries (requires root)
  Do you want to proceed (ENTER) or skip? (s):
Password:

[+] AIX headers + binaries extraction for ISO image (requires root)
  Do you want to proceed (ENTER) or skip? (s):
=> Extracting headers...
New volume on /media/pen/installp/ppc/bos.adt:
 Cluster 51200 bytes (100 blocks).
    Volume number 1
    Date of backup: Thu Apr 16 17:26:51 2020
    Files backed up by name
    User BUILD
[...]
    total size: 11600623
    files restored: 839
=> Extracting bins + libs...
New volume on /media/pen/installp/ppc/bos:
 Cluster 51200 bytes (100 blocks).
    Volume number 1
    Date of backup: Mon Jun  8 17:00:21 2020
    Files backed up by name
    User BUILD
[...]
    total size: 151901391
    files restored: 2585
=> Changing folders perms: from 5XX to 7XX
=> Changing ownership back to the current user (david)
=> Cleaning up some uneeded files/folders/symlinks
=> Converting symlinks from absolute to relative path...
[...]
=> Headers symlinks...
=> Minor details...

[+] Download GCC files (~41.5 MiB)
  Do you want to proceed (ENTER) or skip? (s): s
[...]

[+] Extract and patch GCC .rpm files
  Do you want to proceed (ENTER) or skip? (s):
=> Extracting RPM (gcc13-13.3.0-1.aix7.2.ppc.rpm)...
[...]
90761 blocks
=> Extracting RPM (gcc13-cpp-13.3.0-1.aix7.2.ppc.rpm)...
[...]
85135 blocks
=> Extracting RPM (libgcc13-13.3.0-1.aix7.2.ppc.rpm)...
[...]
15073 blocks
=> Extracting RPM (libgomp13-13.3.0-1.aix7.2.ppc.rpm)...
[...]
39209 blocks
=> Extracting RPM (libgcc-13-2.aix7.2.ppc.rpm)...
[...]
4 blocks
=> Extracting RPM (gcc-13-2.aix7.2.ppc.rpm)...
[...]
4 blocks
=> Extracting RPM (libgomp-13-2.aix7.2.ppc.rpm)...
[...]
2 blocks
=> Extracting RPM (mpfr-4.2.2-1.aix7.1.ppc.rpm)...
[...]
10322 blocks
=> Extracting RPM (gmp-6.3.0-2.aix7.1.ppc.rpm)...
[...]
6175 blocks
=> Extracting RPM (libmpc-1.4.1-1.aix7.1.ppc.rpm)...
[...]
1812 blocks
=> Extracting RPM (libzstd-1.5.7-100.aix7.1.ppc.rpm)...
[...]
=> Creating some useful GCC symlinks

[+] Fix GCC include headers
  Do you want to proceed (ENTER) or skip? (s):
=> Fixing headers (via mkheaders)...

[+] Test GCC
  Do you want to proceed (ENTER) or skip? (s):
=> GCC version:
gcc (GCC) 13.3.0
Copyright (C) 2023 Free Software Foundation, Inc.
This is free software; see the source for copying conditions.  There is NO
warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

=> GCC binary format:
gcc: RISC System/6000 COFF executable, no relocation info, no line number info, stripped, 15 sections, optional header size 72, created Mon Jun  9 11:24:29 2025, 2nd section name ".data"
=> Building hello world...
=> File type:
hello: RISC System/6000 COFF executable, not stripped, 10 sections, symbol offset=0x43e8, 228 symbols, optional header size 72, created Sun Nov  8 19:26:18 2026, 2nd section name ".data"
=> Executing file:
Hello, World!, from aix-user
```

You can skip steps with 's' and/or proceed with '\<ENTER\>'.

At the end, if everything went well, you will be greeted with `Hello, World!, from aix-user`, from a freshly built AIX program running on your Linux machine.

**Note**: The initial extraction steps needs root for two reasons:
- Binfmt setup: binfmt is very convenient during setup, specially during the `mkheader` phase, where nothing needs to be mocked, patched, and etc.
- `restbyname`: this tool creates folder with the `555` perms (r-x), so a non-root user cannot create files inside them.

### b) via Live System
If you have access to an AIX system with 32-bit binaries (`as`, `ar`, `ld`, `bind`, and etc), and a 32-bit with GCC already installed, you just need to copy the files to your computer and make a few adjustments.

First, copy the file lists [system_files.txt] and [gcc_files.txt] to the AIX machine. These lists, as their name implies, contain the paths for the binaries, libraries and folders needed to create a minimal sysroot, capable of running GCC. Copy them to `/tmp` on the AIX machine.

Assuming you have SSH access from your workstation and the AIX, copy the system files as follows:

```bash
# Linux
$ mkdir aix_sysroot
$ ssh aix 'tar -cBRf - -L /tmp/system_files.txt' | tar -xf - -C ./aix_sysroot
$ ssh aix 'tar -cBRf - -L /tmp/gcc_files.txt'    | tar -xf - -C ./aix_sysroot
```

Fix the broken symlinks with:
```bash
export SYSROOT=$PWD/aix_sysroot
find "${SYSROOT}" -type l -lname '/*' | while IFS= read -r link; do
	target=$(readlink "$link")
	rel=$(realpath -ms --relative-to="$(dirname "$link")" "$SYSROOT$target")
	echo "$link -> $rel"
	ln -sfn "$rel" "$link"
done
```

A few more adjustments:

```bash
cd aix_sysroot
mkdir home tmp
ln -s usr/lib lib
ln -s ../../opt/freeware/bin/gcc-13     usr/bin/gcc
ln -s ../../opt/freeware/lib/libmpc.a   usr/lib
ln -s ../../opt/freeware/lib/libmpfr.a  usr/lib
ln -s ../../opt/freeware/lib/libgmp.a   usr/lib
ln -s ../../opt/freeware/lib/libgcc_s.a usr/lib
ln -s ../../opt/freeware/lib/libzstd.a  usr/lib
ln -s ../ccs/bin/as   usr/bin
ln -s ../ccs/bin/bind usr/bin
```

That's it, you can now use GCC, just remember to set the sysroot and the library path before using `aix-user`:
```bash
$ export AIX_USER_LOG_OFF=1
$ export AIX_USER_SYSROOT_PATH=/your/path/here/aix_sysroot
$ export AIX_USER_LIB_PATH="${AIX_USER_SYSROOT_PATH}/usr/lib"

$ cd "${AIX_USER_SYSROOT_PATH}"
$ aix-user usr/bin/gcc --version
gcc (GCC) 13.3.0
Copyright (C) 2023 Free Software Foundation, Inc.
This is free software; see the source for copying conditions.  There is NO
warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

$ aix-user usr/bin/gcc -v
Using built-in specs.
COLLECT_GCC=usr/bin/gcc
COLLECT_LTO_WRAPPER=/opt/freeware/libexec/gcc/powerpc-ibm-aix7.2.0.0/13/lto-wrapper
Target: powerpc-ibm-aix7.2.0.0
Configured with: ../gcc-13.3.0/configure --prefix=/opt/freeware --mandir=/opt/freeware/man --infodir=/opt/freeware/info --with-local-prefix=/opt/freeware --enable-languages=c,c++,fortran,go --enable-version-specific-runtime-libs --disable-nls --disable-libstdcxx-pch --disable-werror --enable-libstdcxx-filesystem-ts --with-gcc-major-version-only --program-suffix=-13 --with-cpu=default32 --host=powerpc-ibm-aix7.2.0.0 --with-libiconv-prefix=/opt/freeware/libiconv_static --with-libiconv-type=static --with-included-gettext
Thread model: aix
Supported LTO compression algorithms: zlib zstd
gcc version 13.3.0 (GCC)
```

## Extra: hybrid approach with `clang`
As said earlier, `clang` _can_ generate object files for PowerPC/AIX. What it cannot do yet is linking, `lld` simply does not support AIX/XCOFF yet.

But here we have a very interesting approach: it is perfectly possible to use clang (native) with ld/bind (AIX) running via `aix-user`. With this hybrid approach, the build times are very close to a native build, or at least *way* faster than a full-system emulation (e.g., QEMU).

Before proceeding, you might question: 'why clang and not GCC?'. Although I'm a GCC fan, Clang has a few advantages here, one of them being multi-target support, among them, PowerPC:
```bash
$ clang --print-targets | grep -P "[a-z0-9-_]+\s+-" | wc -l
44
$ clang --print-targets | grep -i power
    ppc32       - PowerPC 32
    ppc32le     - PowerPC 32 LE
    ppc64       - PowerPC 64
    ppc64le     - PowerPC 64 LE
```

So there is no reason to download and build clang yourself (unless you're like me and use Slackware!). Even Termux's version supports PowerPC!

### Configuring `clang` and sysroot
Our sysroot needs a small adjustment: since `clang` delivers host-relative paths to our VM, our VM must understand them. However, we also need to run `aix-user` in "sysroot-mode", which only accepts sysroot-relative paths.

#### 1) Symlinking the sysroot
Recreate the sysroot's host path inside the sysroot itself: create the directories up to the parent, then make the last component a symlink pointing back to the sysroot root:
```bash
$ S=<sysroot>
$ mkdir -p "$S$(dirname "$S")"
$ ln -s "$(realpath --relative-to="$S$(dirname "$S")" "$S")" "$S$S"
```

For instance:
```bash
$ pwd
/home/david/aix-sysroot
$ tree
.
└── home
    └── david
        └── aix-sysroot -> ../..

4 directories, 0 files
$ ls -l home/david/
total 0
lrwxrwxrwx 1 david users 5 Nov  9 21:45 aix-sysroot -> ../..
```

Neat, right? This way, our VM can access any file inside the sysroot, regardless of whether the provided path is host or guest-relative.

#### 2) .cfg file and symlink to the right target
Clang lets you select a target triple by invoking it through a symlink. Additionally, if a `.cfg` file with the same name is placed next to the clang binary, clang uses it as a configuration file.

Thus, create a symlink as follows:
```bash
$ sudo ln -s $(which clang) /usr/bin/powerpc-ibm-aix7.2-clang
$ ls -l /usr/bin/powerpc-ibm-aix7.2-clang
lrwxrwxrwx 1 root root 14 Nov 10 01:08 /usr/bin/powerpc-ibm-aix7.2-clang -> /usr/bin/clang
```

Next, create the following cfg file (`powerpc-ibm-aix7.2.cfg`), replacing the sysroot path with yours (relative paths are also allowed, via `<CFGDIR>`):
```text
--sysroot=/your-aix-sysroot/here
--ld-path=/your-aix-sysroot/here/usr/bin/ld
-rtlib=libgcc
-static-libgcc
-nostartfiles
-L/your-aix-sysroot/here/usr/lib
-L/your-aix-sysroot/here/opt/freeware/lib/gcc/powerpc-ibm-aix7.2.0.0/13
$/your-aix-sysroot/here/usr/lib/crt0.o
$/your-aix-sysroot/here/opt/freeware/lib/gcc/powerpc-ibm-aix7.2.0.0/13/crtcxa.o
$/your-aix-sysroot/here/opt/freeware/lib/gcc/powerpc-ibm-aix7.2.0.0/13/crtdbase.o
```

This file need to be saved next to the actual `clang` binary, not the symlink, i.e., in `dirname $(readlink -f $(which clang))`.

Ensure that clang now sees the .cfg file and is configured for the right target:

```bash
$ powerpc-ibm-aix7.2-clang --version
Ubuntu clang version 18.1.3 (1ubuntu1)
Target: powerpc-ibm-aix7.2
Thread model: posix
InstalledDir: /usr/bin
Configuration file: /usr/lib/llvm-18/bin/powerpc-ibm-aix7.2.cfg
```

`Target` and `Configuration file` must match exactly what was configured earlier.

#### 3) `tmp` folder and final env vars
Since Clang writes temporary files into the tmp dir, we need to point it to a directory acessible to both clang and aix-user. After that, export a few more env vars and you're ready to go:
```bash
$ cd /your-aix-sysroot/here
$ mkdir tmp
$ export TMPDIR="${PWD}/tmp"
$ export AIX_USER_SYSROOT_PATH="${PWD}"
$ export AIX_USER_LIB_PATH="${PWD}/usr/lib"
$ export AIX_USER_LOG_OFF=1
$ cd home
$ powerpc-ibm-aix7.2-clang hello.c -o hello
```

Alternatively, instead of creating a symlink, it is also possible to create a small script that points to the right config file, which can also set TMPDIR automatically:
```bash
#!/bin/sh
S="/your-aix-sysroot/here"
D="$(dirname "$(readlink -f "$0")")"
export TMPDIR="$S/tmp"
exec /usr/bin/clang --target=powerpc-ibm-aix7.2 --config="$D/powerpc-ibm-aix7.2.cfg" "$@"
```

[system_files.txt]: system_files.txt
[gcc_files.txt]: gcc_files.txt
[make_aix_sysroot_gcc_iso.sh]: make_aix_sysroot_gcc_iso.sh
[Minimal setup via Standalone Diagnostics CD]: https://github.com/Theldus/aix-user/blob/master/docs/MINIMAL_SETUP_THROUGH_SD_CD.md
