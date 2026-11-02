# Minimal setup via Standalone Diagnostics CD
As everyone knows, AIX is a closed-source, proprietary IBM OS.

Unlike Windows and macOS, there are no official images available for download: you either get access through your employer or through IBM Cloud, for instance: [PowerVS2500: Try IBM Power Virtual Server - Free for Up to 90 Days].

I _could_ attempt to write AIX's libraries myself, and then, there would be no dependency on AIX whatsoever, similar to what Wine does. However, I already have too many headaches with the VM itself, I dont want to have _more_ things to worry about.

But there is a way...

## Enter: [Standalone Diagnostics CD]
IBM ships, for free, without any registration, small ISO images with a tiny bootable AIX, with diagnostics tools, meant for recovering an existing installation, among other things.

 Despite being small, these images contain an interesting set of libraries and programs which `aix-user` can then run, such as:
```bash
$ ls usr/bin/
awk       compress  dd        dspmsg     find    kill   mv         odmget  rpm2cpio       sleep   tty
bootlist  cp        df        echo       fold    ksh    nvmemgr    pg      sed            smitty  uname
bsh       cpio      dosdir    egrep      getopt  ln     odmadd     ps      sh             tail    uncompress
cat       cut       dosread   errpt      grep    ls     odmcreate  rm      sisraidmgr     tar     wc
chramfs   date      doswrite  errupdate  head    mkdir  odmdelete  rmdir   sissasraidmgr  time    what
$ ls usr/sbin/
backbyname  cfgmgr  drslot     halt    lscfg   lsmcode     lsslot  mkramdisk  restbyname  slibclean  umount
backup      chdev   execerror  lkdev   lsconn  lsparent    mkdev   mount      restore     strload
bootinfo    diag    format     lsattr  lsdev   lsresource  mkfs    reboot     rmdev       sync
$ ls usr/lib/
IbBaseLib    capi      libbind.a  libcfgscsi.a    libdiag.a     libiconv.a       libpthread.a   libs.a        methods
IbBaseLib.a  drivers   libbsd.a   libcorcfg.a     libdl.a       libmbx.a         libpthreads.a  libsncrypt.a  microcode
IbMxLib      errdemon  libc.a     libcrypt.a      libdr_chrp.a  libodm.a         librdiag.a     libsrc.a      nls
asw          libC.a    libc_r.a   libcrypt4769.a  libefs.a      libpdiag.a       libric.a       libxml2.a     objrepos
boot         libasl.a  libcfg.a   libcur.a        liberrlog.a   libpslog_wrap.a  librtl.a       liby4crypt.a
```

The remaining question is: how to extract these files from the ISO image?

> [!WARNING]
> The extracted files are IBM's copyrighted binaries, this is meant for local use only, do not redistribute them!.

### Extracting all the sysroot
I would like to say that all that's needed is to mount the ISO image, copy the files and call it a day, but unfortunately it is not this way: the most interesting part resides inside a file named 'bootfile.exe'. This file contains the kernel and ramdisk inside, so it is similar to vmlinux+initramfs all in one place. Unfortunately, I don't know how to mount or extract the files inside it, so the only thing left is to actually boot this image and extract them inside the live system.

For this, we need to:
- QEMU (tested with v10.2.1), built for `ppc64-softmmu`, or `--target-list=all` (default).
- [CD72580.ISO]
- Xorriso (optional)

QEMU build is pretty simple:
```bash
$ wget https://download.qemu.org/qemu-10.2.1.tar.xz
$ tar xf qemu-10.2.1.tar.xz
$ cd qemu-10.2.1
$ mkdir build
$ cd build
$ ../configure --target-list="ppc64-softmmu"
$ make -j$(nproc)
```

Before booting the image, there's a need to apply a small patch: by default, the diagnostics disc, as the name implies, will load a diagnostic tool, namely, Dctrl, while what we actually want is to have a shell. The fix is actually simple: find where inside the ISO this file is stored and replace its contents with a small shell script that starts a shell.

With Xorriso, use the below commands to retrieve the sector number inside the ISO that contains the file:
```bash
$ xorriso -indev CD72580.iso -find . -exec report_lba | grep "Dctrl'"
GNU xorriso 1.5.6.pl02 : RockRidge filesystem manipulator, libburnia project.

xorriso : NOTE : Loading ISO image tree from LBA 0
xorriso : UPDATE :    1069 nodes read in 1 seconds
Drive current: -indev 'CD72580.iso'
Media current: stdio file, overwriteable
Media status : is written , is appendable
Boot record  : (system area only) , MBR CHRP cyl-align-off
Media summary: 1 session, 82777 data blocks,  162m data, 3532m free
Volume id    : 'CDROM'
File data lba:  0 ,    62414 ,      282 ,   576863 , './usr/lpp/diagnostics/bin/Dctrl'
```

The number `62414` is the sector number where the contents of Dctrl is stored. All we need to do is write a few bytes in that offset (ISO images have sectors of 2048 bytes!):

```bash
cp CD72580.iso CD72580-mod.iso
printf '#!/bin/sh\n/bin/sh\nexit\n' | dd of=CD72580-mod.iso bs=2048 seek=62414 conv=notrunc
```

Now QEMU can be launched in the following way:
```bash
qemu-system-ppc64 -cpu POWER8 -machine pseries -m 2G -serial mon:stdio \
	-cdrom CD72580-mod.iso \
	-chardev file,id=xfer,path=serial-out.tar,append=on \
	-device spapr-vty,chardev=xfer \
	-d guest_errors \
	-prom-env "input-device=/vdevice/vty@71000000" \
	-prom-env "output-device=/vdevice/vty@71000000" \
	-prom-env "boot-command=dev / 0 0 s\" ibm,aix-diagnostics\" property boot cdrom:\ppc\chrp\bootfile.exe -s verbose"
```

This starts QEMU with two serial devices: one to control the terminal (/dev/vty0) and a secondary that would be used for the file transfer (/dev/vty1).

After a few minutes, the following text will appear:
```text
 ******* Please define the System Console. *******

Type a 1 and press Enter to use this terminal as the
  system console.
Pour definir ce terminal comme console systeme, appuyez
  sur 1 puis sur Entree.
Taste 1 und anschliessend die Eingabetaste druecken, um
  diese Datenstation als Systemkonsole zu verwenden.
Premere il tasto 1 ed Invio per usare questo terminal
  come console.
Escriba 1 y pulse Intro para utilizar esta terminal como
  consola del sistema.
Escriviu 1 1 i premeu Intro per utilitzar aquest
  terminal com a consola del sistema.
Digite um 1 e pressione Enter para utilizar este terminal
  como console do sistema.




 cfgcon
0c31
```

press '1' and then 'ENTER' (it won't show on screen). Wait a few minutes for the system to finish booting.

Once loaded, execute the following command in the VM:
```bash
# AIX
# chdev -l vty1 -a runmodes='hupcl,cread'
```

By default, `/dev/vty1` will 'post-process' the output, putting `\r\n` where it is `\n`, expading tabs into spaces, and tc. While this is fine for text, we should transmit the data as-is. The command above deactivates all output processing of `/dev/vty1`, clearing all of its flags, leaving only `hupcl|cread`, and thus, every content sent into the serial device is not interpreted.

In the host machine (Linux), clear the `serial-out.tar` contents, if not empty:
```bash
# Linux
$ truncate -s 0 serial-out.tar
```

In the VM again, finally, transfers the contents of '/' into a tar file, redirecting it into the serial device. This will be saved in the host machine as `serial-out.tar`. This takes about ~2 minutes, wait for the shell prompt to return and the file stopped growing:
```bash
# AIX
# cd /
# tar -cvf /dev/vty1 bin lib sbin usr
```

In the Linux machine, the .tar file finally can be extracted into some place of your choice:
```bash
# Linux
$ mkdir aix_sysroot
$ tar xvf serial-out.tar -C aix_sysroot
```

Finally, `aix-user` can be executed, for example:
```bash
# Linux
$ cd aix_sysroot
$ export AIX_USER_LIB_PATH=$PWD/usr/lib
$ cd usr/bin
$ file sed
sed: RISC System/6000 COFF executable, no relocation info, no line number info, not stripped, 4 sections, optional header size 72, created Sun Jul  2 13:49:15 2017, 2nd section name ".data"
$ printf "Hello World\n" | aix-user sed "s/World/$(whoami)/g"
Hello david
```

> [!NOTE]
> A good part of this section is based in the blog post [Worth Doing Badly - Tutorial - emulate AIX 7.2 in QEMU], so please check it out, it's very interesting.

[PowerVS2500: Try IBM Power Virtual Server - Free for Up to 90 Days]: https://community.ibm.com/community/user/blogs/val-besong/2026/01/13/powervs2500-try-ibm-power-virtual-server-free-for
[Standalone Diagnostics CD]: https://www.ibm.com/support/pages/node/6474531
[Worth Doing Badly - Tutorial - emulate AIX 7.2 in QEMU]: https://worthdoingbadly.com/aixqemu/
[CD72580.ISO]: https://public.dhe.ibm.com/systems/power/docs/hw/images/p10ga5/cd.diag7.2.5.80.iso
