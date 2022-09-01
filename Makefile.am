AM_CPPFLAGS = -Wall -Wextra

noinst_PROGRAMS = tiny_initramfs

tiny_initramfs_SOURCES    = tiny_initramfs.c io.c fstab.c mount.c log.c devices.c util.c
if ENABLE_NFS4
  tiny_initramfs_SOURCES += nfs.c
endif
tiny_initramfs_CFLAGS     = -fno-inline-small-functions -fno-caller-saves
tiny_initramfs_LDFLAGS    = -static

EXTRA_DIST = README.md tiny_initramfs.h nfs4.h

installdirs-local:
	$(MKDIR_P) "$(DESTDIR)$(pkglibexecdir)"

if HAVE_VARIANT
install-exec-local:
	$(MKDIR_P) "$(DESTDIR)$(pkglibexecdir)"
	$(INSTALL_PROGRAM_ENV) $(INSTALL_PROGRAM) tiny_initramfs$(EXEEXT) "$(DESTDIR)$(pkglibexecdir)/init-@VARIANT@$(EXEEXT)"
uninstall-local:
	rm -f "$(DESTDIR)$(pkglibexecdir)/init-@VARIANT@$(EXEEXT)"
else
install-exec-local:
	$(MKDIR_P) "$(DESTDIR)$(pkglibexecdir)"
	$(INSTALL_PROGRAM_ENV) $(INSTALL_PROGRAM) tiny_initramfs$(EXEEXT) "$(DESTDIR)$(pkglibexecdir)/init$(EXEEXT)"
uninstall-local:
	rm -f "$(DESTDIR)$(pkglibexecdir)/init$(EXEEXT)"
endif
