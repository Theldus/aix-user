# aix-user <img align="right" src="docs/logo.png" width="13%"/>
[![License: Unlicense](https://img.shields.io/badge/License-Unlicense-8af7ff.svg)](https://opensource.org/licenses/Unlicense)
[![Build Status](https://github.com/Theldus/aix-user/actions/workflows/c-cpp.yml/badge.svg)](https://github.com/Theldus/aix-user/actions/workflows/c-cpp.yml)
<br/>
<br/>
A public-domain PoC/attempt to run 32-bit AIX binaries on Linux via Unicorn, 
same idea as qemu-user, but for AIX+PPC

## Why?
The idea came when I participated in a project where we needed to move an 
entire AIX environment to Linux while keeping the behavior exactly the same. 
Everything went well, I had access to the AIX environment and so on, but one 
thought wouldn't leave my mind: "if I had a userspace emulator (like 
[qemu-user] [^1]) all of this would be so much easier..." (for testing, 
debugging, etc.).

And that's how `aix-user` was born: I wanted a userspace AIX emulator to exist, 
didn't find one, so I made my own.

[^1]: It is possible to [emulate it via Qemu], but it's a full-system 
emulation, not userspace!

## How it works?
`aix-user` uses [Unicorn] underneath to emulate a 32-bit PowerPC CPU. It parses 
XCOFF32 binaries and Big-AR archives, implements a dynamic loader for symbol 
resolution and relocations, and translates AIX syscalls to their Linux 
equivalents. Milicode functions (optimized library routines) are also emulated.

For detailed information on the internals, see the [docs/](docs/) directory 
(WIP).

## Usage
The simplest way to use `aix-user` is to just point it to an AIX binary:

```bash
$ ./aix-user <aix_binary> [arguments...]
```

> [!IMPORTANT]
> Unlike Linux, AIX is an OS where *all binaries* are dynamically linked, there 
are no static binaries. Due to that, in order to run AIX binaries on 
`aix-user`, it is required to provide the dependencies the binary requires 
first!.

The usual minimal set of libs required for most binaries is:
- `libc.a` - AIX C library (despite the `.a` extension, this is a shared 
library)
- `libcrypt.a` - AIX crypt library (also a shared library)

By default, `aix-user` searches for libraries in the current directory. If your 
AIX libraries are located elsewhere, you can specify the library path with `-L`:

```bash
$ ./aix-user -L /path/to/aix/libs <aix_binary> [arguments...]
```

### Examples
Running a simple test binary that prints arguments and environment variables:
```bash
$ file examples/args_env/args_env
examples/args_env/args_env: executable (RISC System/6000 V3.1) or obj module 
not stripped

$ ./aix-user examples/args_env/args_env a b c d
argv[0] = (args_env)
argv[1] = (a)
argv[2] = (b)
argv[3] = (c)
argv[4] = (d)
Shell (through env var loop): (SHELL=/bin/bash)
SHELL is bash!

$ echo $?
42
```

### Tracing and debugging options
For debugging purposes, `aix-user` offers a few trace options:

```bash
# Enable syscall trace
$ ./aix-user -s <aix_binary>

# Enable loader/binder/milicode/syscall trace (verbose)
$ ./aix-user -l <aix_binary>

# Both
$ ./aix-user -s -l <aix_binary>
```

More information about the available options can be found with `-h`:
```bash
$ ./aix-user -h
```

## Tools
`aix-user` includes three useful utilities for working with AIX binaries:

### aix-dump
XCOFF file inspector that displays file headers, auxiliary headers, section 
headers, and loader section information.

**Usage:**
```bash
$ ./tools/aix-dump <xcoff_file> [option]

Options:
  -h    Show file header only
  -a    Show auxiliary header only
  -s    Show section headers only
  -l    Show loader header
  -A    Show all information (default)
```

### aix-ar
Big-AR archive extractor that lists and extracts members from AIX archive files 
(`.a` files).

**Usage:**
```bash
$ ./tools/aix-ar <archive_file> <option>

Options:
  -l              List all members
  -x <output_dir> Extract all members to directory
```

**Example:**
```bash
# List all members in libc.a
$ ./tools/aix-ar /usr/lib/libc.a -l

# Extract all members
$ ./tools/aix-ar /usr/lib/libc.a -x ./extracted/
```

### aix-ldd
AIX ldd-like dependency viewer that recursively displays shared library 
dependencies.

**Usage:**
```bash
$ ./tools/aix-ldd [options] <binary_file> [archive_member]

Options:
  -L <path>  Override library search path

Examples:
  ./tools/aix-ldd examples/args_env/args_env
  ./tools/aix-ldd /usr/lib/libc.a shr.o
  ./tools/aix-ldd -L /custom/libs examples/args_env/args_env
```

## Current Status
> [!NOTE]
> The intent of this project is not to run *everything*, but rather to support 
small AIX tools, such as AIX "coreutils" and other similar terminal utilities. 
Since the scope is huge and AIX has hundreds of undocumented syscalls (and 
other features), the approach is 'binary-based': when the support for a new 
binary is wanted, new features are brought in to support that specific binary. 
There's simply no way to implement everything.

**What should work:**
- 32-bit AIX binaries doing syscalls, environment access, and basic output
- Dynamic library loading whether via Big-AR archives or pure XCOFF32 libraries.
- Symbol resolution and relocations.
- Milicode routines (strlen, memcpy, strcmp, etc.)

**Currently supported binaries:**
- `args_env` - Test binary for arguments, environment variables, and exit codes

**In progress:**
- AIX coreutils support (targeting `pwd` as the first utility)

<details><summary>Implemented Syscalls (click to expand)</summary>

| Syscall Number | Name               | Implementation Status |
|:--------------:|:------------------:|:---------------------:|
| 5              | close              | Implemented           |
| 7              | kread              | Implemented           |
| 10             | kwrite             | Implemented           |
| 112            | getuidx            | Implemented           |
| 113            | getgidx            | Implemented           |
| 149            | _exit              | Implemented           |
| 454            | kioctl             | Partial               |
| 472            | kopen              | Partial/Good enough   |
| 481            | statx              | Partial               |
| 542            | read_sysconfig     | Stub                  |
| 559            | __libc_sbrk        | Implemented           |
| 560            | sbrk               | Implemented           |
| 561            | brk                | Implemented           |
| 688            | vmgetinfo          | Partial               |
| 827            | kfcntl             | Partial               |
| 837            | __loadx            | Stub                  |

</details>

AIX has hundreds of syscalls (669+ discovered so far), many of which do not 
have direct Linux equivalents and are not documented anywhere. A complete 
syscall table is available at [blog.theldus.moe/aix-user].

### Limitations
- **No 64-bit support:** Only 32-bit XCOFF binaries are supported. XCOFF64 is 
not implemented.
- **Limited syscalls:** Only essential syscalls are implemented (on a demand 
basis). Complex programs requiring advanced syscalls won't work yet!.

## Debugging
`aix-user` provides a built-in GDB server for debugging AIX binaries. This 
allows you to use GDB to step through code, set breakpoints, inspect registers, 
and more.

To enable the GDB server, use the `-d` flag:

```bash
$ ./aix-user -d <aix_binary>
# GDB server listening on port 1234 (default)
```

You can specify a custom port with `-g`:

```bash
$ ./aix-user -d -g 5555 <aix_binary>
```

Then connect with a multi-arch GDB build (`--enable-targets=all`).

## Building
`aix-user` requires only a C99-compatible compiler and the [Unicorn] Engine 
library (v2.1.4+). Building is straightforward:

```bash
$ git clone https://github.com/Theldus/aix-user.git
$ cd aix-user/
$ make
```

Optionally, you can install `aix-user` and its tools to your system:

```bash
$ make install              # Install to /usr/local (default)
$ make install PREFIX=/usr  # Install to /usr
```

This will install:
- `aix-user` - Main emulator
- `aix-dump` - XCOFF inspector
- `aix-ar` - Big-AR archive extractor
- `aix-ldd` - Dependency viewer

## Contributing
`aix-user` is always open to the community and willing to accept contributions, 
whether with issues, documentation, testing, new features, bugfixes, typos, and 
etc. Welcome aboard.

This project is largely built through reverse engineering due to limited public 
documentation on AIX internals. If you have real-world AIX experience, or 
knowledge of AIX's internals (such as ABI, syscall behavior, XCOFF formats, and 
etc), your contributions would be particularly valuable.

## License
`aix-user` is licensed under the Unlicense (public domain). Written by Davidson 
Francis and
(hopefully) other contributors.

[emulate it via Qemu]: https://astr0baby.wordpress.com/2018/11/04/running-aix-7-2-tl3sp1-on-x86_64-via-qemu-system-ppc64/
[Unicorn]: https://github.com/unicorn-engine/unicorn
[qemu-user]: https://www.qemu.org/docs/master/user/main.html
[blog.theldus.moe/aix-user]: https://blog.theldus.moe/aix-user
