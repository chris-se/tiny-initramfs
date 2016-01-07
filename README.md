tiny-initramfs - A minimalistic initramfs implementation
========================================================

This is a very minimalistic [initramfs](https://en.wikipedia.org/wiki/Initramfs)
implementation for booting Linux systems. It has nearly no features,
but is very small and very fast. It is written purely in C, but uses
only parts of the standard library.

 * It is designed for systems where an initramfs is typically not
   necessary (block device drivers + root file system compiled into the
   kernel, no  separate /usr file system), but where an initramfs is
   required for microcode upgrades. Instead of having to use a full
   initramfs, which is larger (more time spent in the boot loader
   loading it) and slower (because it does more), `tiny-initramfs` will
   add next to no overhead.
 * In systems with a split `/usr` file system, it is necessary to mount
   that in the initramfs already, else subtle problems may occur. If
   `/usr` resides on a simple block device already known to the kernel
   (without user space helpers such as udev), `tiny-initramfs` provides
   a mechanism with very little overhead to mount it before the system
   is started.

Features
--------

 * Simplicity: the implementation is really simple and very linear.
   It's most likely easier to understand than other initramfs
   implementations. The entire program is less than 1000 LoC, and that
   includes the License headers in the files.
 * Size: the implementation is really small (see below).
 * Speed: there is no noticeable performance penalty, because very
   little is done before execution is handed over to the operating
   system proper.
 * Supports mounting the `/` file system for kernel-named devices, for
   example `root=/dev/sda1`.
 * Supports parsing `/etc/fstab` to determine if a separate `/usr`
   partition exists and mounting that - as long as the entry there also
   specifies a kernel-named device as the source.
 * Supports the `root=`, `rootflags=`, `rootfstype=`, `rootdelay=`,
   `rootwait`, `ro`, `rw` and `init=` parameters.
 * Default timeout of 180 seconds to wait for the root device to appear
   (starts after the `rootdelay=` delay is over), after which a kernel
   panic is caused; if `rootwait` is specified it will wait
   indefinitely. (Recompilation is necessary for a larger timeout.)

On an x86_64 system with the default `-O2 -fstack-protector=strong`
compiler flags, statically linked with the binary stripped, and the
resulting initramfs compressed with default `gzip`, the images produced
have the following size for different libcs tested:

| libc implementation | `initrd.img` size (bytes) |
| ------------------- | -------------------------:|
| musl 1.1.5          |                     11272 |
| dietlibc 0.33       |                      9397 |
| glibc 2.19          |                    323688 |

The size of an initramfs using `tiny-initramfs` is thus about 10 KiB if
one doesn't use glibc.

Requirements
------------

 * The kernel must have the necessary block device drivers built-in
   that are required to access the root and `/usr` file systems.
   **Warning:** this is not true for most default kernels of mainstream
   distributions, as they require a full initramfs to load the modules
   required to mount the root file system.
 * The kernel must have `CONFIG_DEVTMPFS` built-in, because this
   implementation assumes the kernel will just create the devices by
   itself. (This is true for most distribution kernels.)

When not to use
---------------

 * `tiny-initramfs` does not support `UUID=` nor `PARTUUID=` for
   mounting the root or `/usr` file systems. It also doesn't support
   symlinks created by udev (such as `/dev/disk/by-label/...`). Only
   the kernel names themselves, such as `/dev/sda1` are supported.
 * No modules can be loaded in the initramfs, everything that's
   required needs to be compiled in.
 * `/` or `/usr` on network file systems are currently not supported.
 * Booting from USB storage is not recommended, because the device
   names aren't stable. (It could work regardless if there is only one
   USB storage device attached at all times.)
 * `/usr` on a FUSE file system, as they require user space helpers
   running to be able to mount. Generally speaking, any file system
   that can't be mounted with just a trivial `mount` syscall, but
   requires a userspace helper, will not work.

If your setup falls into one of these cases, please use a full
initramfs instead of `tiny-initramfs`. It is not meant to replace
those, but provide a light-weight solution in cases where the
complexities of a full initramfs are unnecessary.

Caveats
-------

 * Since the initramfs is supposed to be small, `fsck` will not be
   executed by `tiny-initramfs`. For the `/` file system this is
   perfectly fine, as most distributions support checking the root file
   system at boot outside of the initramfs. But this doesn't work for
   `/usr`, because e.g. `e2fsck` will not check a mounted file system
   other than the root file system; and e.g. systemd passes `-M` to
   `fsck` by default for non-root file systems, so mounted file systems
   are excluded anyway. It shouldn't be too difficult to special-case
   `/usr` here as well, but that work needs to be done if a file system
   check at boot is to be performed for `/usr` with `tiny-initramfs`.
   (Note that `e2fsck` plus the required libraries are about 2.5 MiB in
   size, so having `fsck` present in the initramfs image is not in the
   scope of `tiny-initramfs`, because it would remove all the
   advantages.)
 * If you use anything other than systemd as the init system, you need
   to make sure that a split-`/usr` file system is remounted read-write
   if the `ro` option is passed on the kernel command line (because
   `tiny-initramfs` will also mount `/usr` read-only then) - otherwise
   `/usr` will remain read-only after boot. `tiny-initramfs` itself
   doesn't care about which init system is used, but the init system
   must be able to cope with the state that `tiny-initramfs` leaves the
   `/usr` file system in. This may require changes to some scripts.
 * If `/usr` is a bind mount in `/etc/fstab`, this will currently fail,
   even though it should be supportable. (It's on the TODO list, as
   long as that doesn't require yet another file system.)
 * Overlay-type file systems for `/usr` are untested, but they should
   work if they are compiled into the kernel. What is *not* supported
   are overlay-type file systems for `/` and/or if something has to be
   done prior to mounting these file systems (such as creating a
   directory, or mounting an additional tmpfs or similar).
 * Old-style `root=MAJ:MIN` is currently not supported, but on the TODO
   list.

HOWTO
-----

Install an alternative libc implementation that's designed for embedded
use cases, such as [musl](http://www.musl-libc.org/) or
[dietlibc](http://www.fefe.de/dietlibc/). This is strictly speaking not
required, as the default glibc will also work, but then the binary size
of the resulting binary will be far larger. If `tiny-initramfs` doesn't
work with your favorite libc implementation, please report this, so
that it may be fixed.

Find out the compile command required to use your C library. For
example, with musl it's `musl-gcc`, with dietlibc it's `diet gcc`.

Use

    CC=musl-gcc make

to compile the `tiny_initramfs` binary and

    CC=musl-gcc make initrd.img

to auto-create the initramfs image. Replace `musl-gcc` with the
appropriate command for your libc implementation.

The initramfs creation is really simple, you may also do so manually:

 1. create an empty directory, let's call it `initramfs/`
 2. copy `tiny_initramfs` to the directory, call it `init` (you can
    call it something else, but then you also need to pass the
    `rdinit=/newname` option to the kernel command line)
 3. strip the binary to reduce it's size (optional)
 4. create the `dev`, `proc` and `target` subdirectories
 5. cpio the directory and compress it

The following commands do just that:

    mkdir initramfs
    cp tiny_initramfs initramfs/init
    strip initramfs/init
    mkdir initramfs/dev initramfs/proc initramfs/target
    cd initramfs ; find . | cpio -o --quiet -R 0:0 -H newc | gzip > ../initrd.img

With this there's now a (kernel-independent) initramfs image that may
be used to boot the system. Note that as of now there is no integration
with distributions, so configuring the boot loader etc. has to be done
manually.

Design considerations
---------------------

The design of `tiny-initramfs` is as minimalistic as possible. The
buffered I/O functions from the `stdio.h` standard library are
completely avoided, because they can increase the code size quite a
bit, depending on the libc implementation. At one point an own
minimalistic buffered I/O routine is implemented (much smaller than the
full standard library linked in).

Dynamic allocations are avoided and buffers on the stack are used. Code
that properly handles dynamic allocations tends to be longer, so this
reduces code size. The buffers are sized generously (there are not that
many buffers that the amount of RAM used is a concern just yet, even
for small systems), so that no real flexibility is sacrificed.

None of this is extremely performance-critical (it is going to be quite
fast regardless, because very little is done compared to a even just
running a shell), so no algorithm is optimized for speed directly. For
example, the mount option parser table is somewhat compressed to reduce
the code size (negation and recursive variants of mount options are not
repeated), to the point where further reduction would likely sacrifice
the readability of the code. Execution speed is achieved by doing very
little, not by micro-optimizing algorithms.

Future features
---------------

There is no goal of adding too many additional features here, because
any additional feature is going to increase the binary size, and this
is supposed to be minimalistic and **not** a replacement for a full
initramfs. If you need advanced features, please use an already
existing solution. That said, there are two things that might be
interesting regardless:

 * Some minimalistic network file system support for very simple cases,
   if it is possible to let the kernel do all the network configuration
   even if an initramfs is used. For example, mounting an NFSv3 (or
   non-idmapped NFSv4 `sec=sys`) file system only consists of calling
   the `mount` syscall with a special data structure as the `data`
   parameter - which does not appear to be much more complex than what
   is currently implemented.
 * Support `UUID=` for the most common file systems: it shouldn't be
   too hard to go through all partitions and extract the UUIDs for at
   least the major file system types, basically just ext4, xfs and
   btrfs. (Open the block device, seek to position, verify that we know
   the file system type, seek to other position, read 16 bytes, close
   device.)

If any of these features should be implemented, depending on by how
much they increase the initramfs image size, they might be made
compile-time optional. The cutoff will be around 15 KiB on x86_64 (so
that it should be less than 16 KiB on all architectures), anything that
keeps the image size smaller than that will still be considered
acceptable.
