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
equivalents.

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
`aix-user` includes three utilities for working with AIX binaries:

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

**Currently tested binaries:** All binaries under [examples/], plus: `ar`,
`cal`, `cat`, `chmod`, `cut`, `date`, `dump`, `echo`, `grep`, `head`,
`kill`, `od`, `printf`, `pwd`, `rm`, `sed`, `sleep`, `tail`, `tee`, `test`,
`tr`, `uname`, `uniq`, `wc`, `yes`.

**Binaries that works, but with possible caveats**: The list below contains
binaries that works but might have some hidden issues due to features
not-implemented, and etc:

| Binary      | Reason                                                     |
|:-----------:|:----------------------------------------------------------:|
| as          | `_sigaction` not-implemented yet                           |
| find        | `_sigaction`, `execve` and `kfork` not-implemented yet     |
| sort        | `_sigaction` not-implemented yet                           |

[examples/]: examples/

**Note:** These lists is (as one might expect) non-exhaustive and certainly
other tools might or not work as expected. It is also worth noting that
the list above was _manually_ tested, so there might be non-tested
edge cases too.

<details><summary>Implemented Syscalls (click to expand)</summary>

| Syscall Number | Name               | Implementation Status |
|:--------------:|:------------------:|:---------------------:|
| 5              | close              | Implemented           |
| 7              | kread              | Implemented           |
| 10             | kwrite             | Implemented           |
| 17             | _clock_nanosleep   | Implemented           |
| 18             | _nsleep            | Implemented           |
| 107            | kill               | Implemented           |
| 112            | getuidx            | Implemented           |
| 113            | getgidx            | Implemented           |
| 149            | _exit              | Implemented           |
| 174            | appgetrlimit       | Implemented           |
| 179            | getrlimit64        | Implemented           |
| 399            | klseek             | Implemented           |
| 401            | lseek              | Implemented           |
| 411            | sys_parm           | Partial               |
| 412            | chdir              | Implemented           |
| 413            | fchdir             | Implemented           |
| 418            | chown              | Implemented           |
| 451            | getdirent64        | Implemented           |
| 454            | kioctl             | Partial               |
| 464            | mntctl             | Stub                  |
| 472            | kopen              | Partial/Good enough   |
| 480            | fstatx             | Partial               |
| 489            | umask              | Implemented           |
| 493            | unamex             | Implemented           |
| 494            | uname              | Implemented           |
| 495            | rmdir              | Implemented           |
| 497            | unlink             | Implemented           |
| 481            | statx              | Partial               |
| 542            | read_sysconfig     | Stub                  |
| 559            | __libc_sbrk        | Implemented           |
| 560            | sbrk               | Implemented           |
| 561            | brk                | Implemented           |
| 574            | _getpgrp           | Implemented           |
| 575            | _getppid           | Implemented           |
| 578            | _getpid            | Implemented           |
| 688            | vmgetinfo          | Partial               |
| 825            | access             | Implemented           |
| 827            | kfcntl             | Partial               |
| 837            | __loadx            | Stub                  |
| 848            | accessx            | Partial/Good enough   |

**Note:** The syscall number is for informational purposes only,
since `aix-user` does not use it to handle them.

</details>

AIX has hundreds of syscalls (669+ discovered so far), many of which do not 
have direct Linux equivalents and are not documented anywhere. A complete 
syscall table is available at [blog.theldus.moe/aix-user].

### Limitations
`aix-user` is a simple project that doesn't intend to run *all* possible 32-bit
AIX binaries.

Considering this, the following limitations apply:
- Limited number of syscalls (always under development)
- No 64-bit support and there never will be.
- No thread support (and probably never will be either: there are simply
*too many* other things I need to address first).
- No ctors/dtors (yet): C++ programs probably won't work yet.

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
