
CC=musl-gcc
CFLAGS=-Wall -Wextra -O2 -fstack-protector-strong
LDFLAGS=-static

# These are only needed for generating initrd.img
STRIP=strip
CPIO=cpio
CPIO_ARGS=--quiet -R 0:0 -H newc
FIND=find
MKDIR=mkdir
CP=cp
RM_R=rm -r
GZIP=gzip

.PHONY: clean all

all: tiny_initramfs

tiny_initramfs: tiny_initramfs.o io.o fstab.o mount.o log.o devices.o nfs.o util.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)

initrd.img: tiny_initramfs
	if [ -d initramfs ] ; then $(RM_R) initramfs ; fi
	$(MKDIR) initramfs initramfs/dev initramfs/proc initramfs/target
	$(CP) tiny_initramfs initramfs/init
	$(STRIP) initramfs/init
	cd initramfs ; $(FIND) . | $(CPIO) -o $(CPIO_ARGS) | $(GZIP) > ../initrd.img ; cd ..
	$(RM_R) initramfs

clean:
	rm -f *~ *.o tiny_initramfs initrd.img
