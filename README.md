tiny-initramfs - A minimalistic initramfs implementation
========================================================

This is a very minimalistic [initramfs](https://en.wikipedia.org/wiki/Initramfs)
implementation for booting Linux systems. It has nearly no features,
but is very small and very fast. It is written purely in C, but uses
only parts of the standard library.

There are three primary use cases:

 * It is designed for systems where an initramfs is typically not
   necessary (block device drivers + root file system compiled into the
   kernel, no  separate /usr file system), but where an initramfs is
   required for microcode upgrades. Instead of having to use a full
   initramfs, which is larger (more time spent in the boot loader
   loading it) and slower (because it does more), `tiny-initramfs` will
   add next to no overhead.
 * In cases where `UUID`-based boot is wanted not a full initramfs.
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
   implementations. The entire program is less about 2500 LoC, and that
   includes the License headers in the files.
 * Size: the implementation is really small (see below).
 * Speed: there is no noticeable performance penalty, because very
   little is done before execution is handed over to the operating
   system proper.
 * Supports kernel-named devices, for example `root=/dev/sda1`.
 * Supports `root=0xMAJMIN`.
 * Supports `root=UUID=...` for ext2, ext3, ext4, xfs and btrfs.
 * Supports parsing `/etc/fstab` to determine if a separate `/usr`
   partition exists and mounting that - as long as the entry there
   follows the same rule as the `root=` parameter (kernel device name,
   or `UUID=` entry for a select number of filesystems).
 * Supports the `root=`, `rootflags=`, `rootfstype=`, `rootdelay=`,
   `rootwait`, `ro`, `rw` and `init=` parameters.
 * Default timeout of 180 seconds to wait for the root device to appear
   (starts after the `rootdelay=` delay is over), after which a kernel
   panic is caused; if `rootwait` is specified it will wait
   indefinitely. (Recompilation is necessary for a larger timeout.)
 * Supports mounting NFSv4 file systems with `sec=sys` that do **not**
   use the idampper, i.e. use raw UIDs/GIDs. For the `/usr` file system
   the standard `/etc/fstab` entries are interpreted, for the root file
   system one should use `root=/dev/nfs` and the `nfsroot=` parameter
   (as documented in the kernel documentation). The network
   configuration needs to be specified via the `ip=` kernel command
   line parameter.
 * Very trivial module loading support (**no** automatic dependency
   resolution).

When compiled on an x86_64 system with the default `-Og` compiler flags,
statically linked against dietlibc 0.33~cvs20120325-6, the binary
stripped and the resulting initramfs (without any modules added)
compressed with `gzip -9`, the images produced are between 9 kiB and
14 kiB, depending on the feature set selected.

Using musl instead of dietlibc adds between 1.8 and 2.4 kiB to the
resulting `initrd.img` size (depending on the feature set).

Using glibc instead of dietlibc adds around 310 kiB to the resulting
initrd image and is not recommended (although it will work).

Adding modules to the initramfs will increase the size, and many block
device and file system drivers are 100s of kiB in size. On the other
hand, the kernel would be larger if they were compiled in, so the
actual amount of space lost due to using modules is quite a bit
smaller.

Requirements
------------

 * The kernel should have the necessary block device and file system
   drivers built-in that are required to access the root and `/usr`
   file systems. **Warning:** this is not true for most default kernels
   of mainstream  distributions, as they require a full initramfs to
   load the modules required to mount the root file system.
 * If the necessary drivers are not built into the kernel, there is
   limited support for loading modules from within the initramfs, see
   below for details.
 * The kernel must have `CONFIG_DEVTMPFS` built-in, because this
   implementation assumes the kernel will just create the devices by
   itself. (This is true for most distribution kernels.)
 * NFSv4 requires at least kernel 3.5 on both server and client (in
   order for raw UIDs/GIDs to work) and requires built-in kernel
   support for network autoconfiguration (`CONFIG_IP_PNP` and for DHCP
   support also `CONFIG_IP_PNP_DHCP`) as well as built-in kernel
   support for NFSv4 (`CONFIG_NFS_FS` as well as `CONFIG_NFS_V4`).

When not to use
---------------

 * `tiny-initramfs` does not support `PARTUUID=` for mounting the root
   or `/usr` file systems. It also doesn't support symlinks created by
   udev (such as `/dev/disk/by-label/...`). Only the kernel names
   themselves, such as `/dev/sda1`, as well as `UUID=` and hexadecimal
   device numbers (`0xMAJMIN`, e.g. `0x801`) are supported.
 * NFSv2/NFSv3 are currently not supported.
 * When booting from USB storage you should always use `UUID=`, because
   device names are not necessarily stable.
 * `/usr` on a FUSE file system, as they require user space helpers
   running to be able to mount. Generally speaking, any file system
   that can't be mounted with just a trivial `mount` syscall, but
   requires a userspace helper, will not work.
 * Any complex storage setup, such as LVM, encryption, iSCSI, etc.
   Basically, only things that the kernel provides devices for out of
   the box (potentially with additional kernel parameters) is
   supported.

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
 * You need to make sure that a split-`/usr` file system is remounted
   read-write if the `ro` option is passed on the kernel command line
   (because `tiny-initramfs` will also mount `/usr` read-only then);
   otherwise `/usr` will remain read-only after boot. If you use
   systemd as your init system, or e.g. the newest Debian initscripts
   (`2.88dsf-59.3` or higher) in conjunction with sysvinit, this should
   work. `tiny-initramfs` itself doesn't care about which init system
   is used, but the init system must be able to cope with the state
   that `tiny-initramfs` leaves the  `/usr` file system in. This may
   require changes to some scripts.
 * If `/usr` is a bind mount in `/etc/fstab`, this will currently fail,
   even though it should be supportable. (It's on the TODO list, as
   long as that doesn't require yet another file system.)
 * Overlay-type file systems for `/usr` are untested, but they should
   work if they are compiled into the kernel. What is *not* supported
   are overlay-type file systems for `/` and/or if something has to be
   done prior to mounting these file systems (such as creating a
   directory, or mounting an additional tmpfs or similar).
 * Booting from kernel-assembled RAID arrays (via `md=...`) should
   work, but is untested. Don't combine this with `UUID=`, though, as
   `tiny-initrd` currently does not check if a block device has array
   metadata, so it could falsely identify a member device (instead of
   the entire array) when using `UUID=` in some cases. But for arrays
   that are assembled by the kernel via `md=...` the device name is
   known anyway (typically `/dev/md0`), so this shouldn't be an issue.
 * NFS support is not thoroughly tested.
 * Host names are unsupported for NFS mounts, only IP addresses work.
 * While this is supposed to be portable, this has only been tested on
   x86_64 (amd64). Since low-level kernel syscalls are performed, there
   may be some issues on other architectures. Please report those if
   they are present.

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
example, with dietlibc it's `"diet gcc"`, with musl it's `musl-gcc`.

Use

    ./configure CC="diet gcc"
    make

to compile the `tiny_initramfs` binary and

    make initrd.img

to auto-create the initramfs image. Replace `"diet gcc"` with the
appropriate command for your libc implementation.

Note that if you specify `CFLAGS` (potentially via your build system)
you should take care to specify `-Os` and *not* to specify any debug
(`-g`) options, as those tend to increase the binary size quite a bit.
`./configure` will warn you about it, but it not abort in that case,
because the binary will work. Likewise, if you don't use an alternative
libc implementation but glibc, `./configure` will warn you about it,
because that will increase the binary size by a factor of 10 to 20.

You may specify multiple options to enable/disable certain features in
the initramfs. Specifically, you can disable UUID mounting support
(enabled by default), and you can enable NFSv4 support (disabled by
default). A list of possible options is displayed when using

    ./configure --help

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

Support for loading modules
---------------------------

There is limited support for loading modules if `--enable-modules` is
specified during the `configure` invocation. To use this feature, one
needs to create a file `/modules` in the initramfs image that is of the
following format:

    /file.ko options

The modules should not be in a sub-directory, because the directory
containing them will not be cleaned-up by tiny-initramfs after mounting
the root file system. (Loading the modules will work though.)

For example, the virtio block device driver `virtio_blk` requires some
additional modules to work. Using `modprobe` one may find out which:

    $ /sbin/modprobe --all --ignore-install --quiet --show-depends virtio_blk
    insmod /lib/modules/[...]/kernel/drivers/virtio/virtio.ko
    insmod /lib/modules/[...]/kernel/drivers/virtio/virtio_ring.ko
    insmod /lib/modules/[...]/kernel/drivers/block/virtio_blk.ko

It turns out that this is not quite sufficient, because the
`virtio_pci` driver is also required for `virtio_blk` to work (the
driver loads without `virtio_pci`, but doesn't work), so one may use:

    $ /sbin/modprobe --all --ignore-install --quiet --show-depends virtio_blk virtio_pci
    insmod /lib/modules/3.16.0-4-amd64/kernel/drivers/virtio/virtio.ko
    insmod /lib/modules/3.16.0-4-amd64/kernel/drivers/virtio/virtio_ring.ko
    insmod /lib/modules/3.16.0-4-amd64/kernel/drivers/block/virtio_blk.ko
    insmod /lib/modules/3.16.0-4-amd64/kernel/drivers/virtio/virtio.ko
    insmod /lib/modules/3.16.0-4-amd64/kernel/drivers/virtio/virtio_ring.ko
    insmod /lib/modules/3.16.0-4-amd64/kernel/drivers/virtio/virtio_pci.ko

(Note that in case soft dependencies are treated via `install` lines,
these have to be resolved manually. This is typically not the case for
drivers needed within initramfs, because other implementations also
suffer from the same issue. `install` is deprecated anyway according to
the manual page of `modprobe.d`.)

One may then copy these drivers to the initramfs image, and then add
a module file with the following contents:

    /virtio.ko
    /virtio_ring.ko
    /virtio_blk.ko
    /virtio.ko
    /virtio_ring.ko
    /virtio_pci.ko

The order is important, because dependency resolution is **not**
performed by tiny-initramfs, it has to be done while creating the
initramfs image. Duplicate entries are not a problem, because they will
silently be ignored (but you may remove duplicate entries if you don't
change the order otherwise).

Options may be specified when followed by a space (tab characters not
supported), for example:

    /libata.ko noacpi

Debugging
---------

If an error occurs, tiny-initramfs will print an error message
indicating the problem and then sleep for 10s before exiting. This is
because exiting will cause a kernel panic, but typical kernel traces
are so large that they replace the entire screen contents on a standard
terminal, so that the original message is not visible anymore. The 10s
delay allows the user to see what the problem is.

Additionally, one may use the `--enable-debug` flag of `./configure` to
make `initrd.img` verbose (while increasing the size a bit). This makes
debugging easier, especially if the system hangs at a certain point.
When compiled with that option, tiny-initramfs will print the contents
of `/proc/self/mountinfo` and sleep for 5s after mounting the root (and
potentially /usr) file systems before executing `init`.

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
fast regardless, because very little is done compared to even just
running a shell), so no algorithm is optimized for speed directly. For
example, the mount option parser table is somewhat compressed to reduce
the code size (negation and recursive variants of mount options are not
repeated), to the point where further reduction would likely sacrifice
the readability of the code. Execution speed is achieved by doing very
little, not by micro-optimizing algorithms.

Sometimes it is necessary to reimplement certain libc functions because
using the libc variants increase the image size too much. For example,
using `inet_ntoa` and `inet_aton` (to convert between ASCII to binary
representations of IP addresses) from the musl C library will cause
initramfs images (after compression) to be an additional 5 KiB larger
as compared to the own implementation.

Of course, changes that reduce the current code size even further (as
long as the code remains readable) are very welcome.

Future features
---------------

There is no goal of adding too many additional features here, because
any additional feature is going to increase the binary size, and this
is supposed to be minimalistic and **not** a replacement for a full
initramfs. If you need advanced features, please use an already
existing solution. That said, there are a couple of things that might
be interesting regardless:

 * Minimalistic NFSv2/3 mounting support (akin to the current NFSv4
   code).
 * Maybe support host name lookups for NFS mounts? (Probably not going
   to happen, as an own DNS resolver will likely increase the image
   size by too much - and is likely going to be rather complicated.)
 * Support `UUID=` for more filesystems, as long as they are really
   simple. Currently, the implementation checks the magic bytes of a
   given file system on the each device, and then compares the UUID at
   the right position in the file system metadata. (See `devices.c` for
   details on how this is implemented for the currently supported file
   systems.)
 * Support for excluding MD/RAID/... devices when probing for UUIDs of
   file systems.

Note that the goal is to keep the `initrd.img` size smaller than 16 KiB
on all platforms, so a cutoff of 15 KiB is used on x86_64, to leave
room for different assembly code sizes etc., at least when used in a
minimal configuration. Therefore, some features (such as `UUID=` and
NFSv4 support) are compile-time optional.

Note: any features missing from tiny-initramfs that would be required
in a space-constrained environment (i.e. mainly embedded), where it was
designed for, stand an excellent chance of being included later, at
least compile-time optional. Please make your case if you are missing
something.

TODO
----

 * bind mounts for /usr
 * clean up the code a bit.
 * go through all messages printed and make sure they are uniform in
   style
