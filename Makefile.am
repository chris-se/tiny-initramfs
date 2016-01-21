AM_CPPFLAGS = -Wall -Wextra

pkglibexec_PROGRAMS = tiny_initramfs

tiny_initramfs_SOURCES    = tiny_initramfs.c io.c fstab.c mount.c log.c devices.c util.c
if ENABLE_NFS4
  tiny_initramfs_SOURCES += nfs.c
endif
tiny_initramfs_CFLAGS     = -fno-inline-small-functions -fno-caller-saves
tiny_initramfs_LDFLAGS    = -static

EXTRA_DIST = README.md tiny_initramfs.h nfs4.h
