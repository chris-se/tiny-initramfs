/*
 * tiny_initramfs - Minimalistic initramfs implementation
 * Copyright (C) 2016 Christian Seiler <christian@iwakd.de>
 *
 * mount.c: Helper functions for mounting filesystems
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <string.h>
#include <stdlib.h>
#include <sys/mount.h>
#include <errno.h>

#include "tiny_initramfs.h"

/* dietlibc doesn't define MS_DIRSYNC for some reason
 * (probably a bug)
 */
#ifndef MS_DIRSYNC
#define MS_DIRSYNC                   128
#endif

/* Newer mount flags (last update: 2016-01)
 * (the rest are supported by both musl and dietlibc, should there be
 * a C library that doesn't yet contain other flags used, feel free to
 * add conditional defines here)
 */
#ifndef MS_LAZYTIME
#define MS_LAZYTIME                  (1 << 25)
#endif

static char supported_filesystems[MAX_SUPPORTED_FILESYSTEMS][MAX_FILESYSTEM_TYPE_LEN];
static int supported_filesystems_count;
static void determine_supported_filesystems();
static int process_proc_filesystems(void *data, const char *line, int line_is_incomplete);

int mount_filesystem(const char *source, const char *target,
                     const char *type, const char *flags,
                     int override_flags_add, int override_flags_subtract)
{
  int options;
  char data[MAX_LINE_LEN];
  int nfsver = -1;
  int rc = -1;

#ifdef ENABLE_DEBUG
  warn("mount_filesystem(\"", source, "\", \"", target, "\", \"", type ? type : "(null)", "\", \"", flags, "\", ...): begin", NULL);
#endif

#ifdef ENABLE_NFS4
  if (type && (!strcmp(type, "nfs") || !strcmp(type, "nfs4")))
    nfsver = !strcmp(type, "nfs4") ? 4 : 0;
#endif
  options = parse_mount_options(data, MAX_LINE_LEN, flags, nfsver != -1 ? &nfsver : NULL);

#ifdef ENABLE_DEBUG
  warn("mount_filesystem: parsing mount options (done), unparsed options: ", data, NULL);
#endif

  options |= override_flags_add;
  options &= ~override_flags_subtract;

#ifdef ENABLE_NFS4
  if (type && !strcmp(type, "nfs4") && nfsver != 4)
    panic(0, "Cannot combine [nfs]vers=2/3 option with filesystem type nfs4.", NULL);
  if (type && (!strcmp(type, "nfs") || !strcmp(type, "nfs4"))) {
    if (nfsver != 4 && nfsver != 0)
      panic(0, "Sorry, only NFSv4 is currently supported.", NULL);
    /* Note that nfsver == 0 means we have type == nfs and no vers= parameter
     * at this point - which means that in principle we should try first NFSv4
     * and then NFSv3/2. But until we support NFSv3, we'll just do NFSv4. */
    return mount_nfs4(source, target, options, data);
  }
#endif

#ifdef ENABLE_DEBUG
  warn("mount_filesystem: not NFS", NULL);
#endif

  /* We need to loop through filesystem types as the kernel doesn't do
   * that for us if we call mount(). libmount does something similar,
   * but we don't want to link against it. */
  if ((!type || !strcmp(type, "auto") || !strcmp(type, "none")) && !(options & (MS_MOVE | MS_REMOUNT | MS_BIND))) {
    int i;

    determine_supported_filesystems();

    errno = EINVAL;
    rc = -1;
    for (i = 0; rc < 0 && i < supported_filesystems_count; i++) {
      rc = mount(source, target, supported_filesystems[i], options | MS_SILENT, data);
    }
    if (rc < 0)
      return -errno;
    return 0;
  }

  rc = mount(source, target, type, options, data);
  if (rc < 0)
    return -errno;
  return 0;
}

/* There are precisely 4 bits currently reserved for
 * kernel mount flags, so reuse them for parsing to
 * save code space. */
#define INVERTED         (1U << 28)
#define HAS_NO_VARIANT   (1U << 29)
#define HAS_R_VARIANT    (1U << 30)
#define IGNORE           (1U << 31)

#define FLAG_MASK        ~(INVERTED | HAS_NO_VARIANT | HAS_R_VARIANT | IGNORE)

int parse_mount_options(char *syscall_data, size_t syscall_data_len, const char *option_string, int *nfsver)
{
  /* This is not very readable, but it will save quite
   * bit of space in the resulting binary... */
  static const char *mount_option_names =
    /*  0 */ "ro\0"
             "rw\0"
             "exec\0"
             "suid\0"
             "dev\0"
             "sync\0"
             "dirsync\0"
             "remount\0"
             "bind\0"
             "silent\0"
    /* 10 */ "loud\0"
             "mand\0"
             "atime\0"
             "iversion\0"
             "diratime\0"
             "relatime\0"
             "strictatime\0"
             "unbindable\0"
             "private\0"
             "slave\0"
    /* 20 */ "shared\0"
             "defaults\0"
    /* NOTE: We ignore all of these for now, but if a filesystem we
     *       want to mount really has these options set in /etc/fstab,
     *       it's not clear that that is the right thing to do...
     *       (Most of them don't make sense for /usr anyway, and we
     *       don't support loop devices.)
     */
             "_netdev\0"
             "auto\0"
             "user=\0"
             "users\0"
             "owner\0"
             "group\0"
             "comment=\0"
             "loop=\0"
    /* 30 */ "offset=\0"
             "sizelimit=\0"
             "encryption=\0"
             "nofail\0"
             "uhelper=\0"
             "helper=\0"
  ;
  static const unsigned int mount_option_flags[] = {
    /*  0 */ 0                         | MS_RDONLY,
             INVERTED                  | MS_RDONLY,
             INVERTED | HAS_NO_VARIANT | MS_NOEXEC,
             INVERTED | HAS_NO_VARIANT | MS_NOSUID,
             INVERTED | HAS_NO_VARIANT | MS_NODEV,
             HAS_NO_VARIANT            | MS_SYNCHRONOUS,
             0                         | MS_DIRSYNC,
             0                         | MS_REMOUNT,
             HAS_R_VARIANT             | MS_BIND,
             0                         | MS_SILENT,
    /* 10 */ INVERTED                  | MS_SILENT,
             HAS_NO_VARIANT            | MS_MANDLOCK,
             INVERTED | HAS_NO_VARIANT | MS_NOATIME,
             HAS_NO_VARIANT            | MS_I_VERSION,
             INVERTED | HAS_NO_VARIANT | MS_NODIRATIME,
             HAS_NO_VARIANT            | MS_RELATIME,
             HAS_NO_VARIANT            | MS_STRICTATIME,
             HAS_R_VARIANT             | MS_UNBINDABLE,
             HAS_R_VARIANT             | MS_PRIVATE,
             HAS_R_VARIANT             | MS_SLAVE,
    /* 20 */ HAS_R_VARIANT             | MS_SHARED,
             0                         | 0,
             IGNORE                    | 0,
             HAS_NO_VARIANT | IGNORE   | 0,
             HAS_NO_VARIANT | IGNORE   | 0,
             HAS_NO_VARIANT | IGNORE   | 0,
             HAS_NO_VARIANT | IGNORE   | 0,
             HAS_NO_VARIANT | IGNORE   | 0,
             IGNORE                    | 0,
             IGNORE                    | 0,
   /* 30 */  IGNORE                    | 0,
             IGNORE                    | 0,
             IGNORE                    | 0,
             IGNORE                    | 0,
             IGNORE                    | 0,
             IGNORE                    | 0,
             0                         | 0
  };

  char opts[MAX_LINE_LEN] = { 0 };
  char *saveptr;
  char *token;
  char *check;
  int bits = 0;
  int had_variant;
  int applies;
  int bits_to_change;
  int invert;
  const char *opt_name;
  size_t opt_name_len;
  int opt_index, this_opt_index;
  int opt_flag = 0;

  set_buf(opts, MAX_LINE_LEN, option_string, NULL);
  memset(syscall_data, 0, syscall_data_len);

  for (token = strtok_r(opts, ",", &saveptr); token != NULL; token = strtok_r(NULL, ",", &saveptr)) {
    /* special case: ignore all that starts with x- */
    if (token[0] == 'x' && token[1] == '-')
      continue;

    this_opt_index = -1;
    had_variant = 0;
    for (opt_index = 0, opt_name = mount_option_names, opt_name_len = strlen(opt_name);
         *opt_name;
         ++opt_index, opt_name += opt_name_len + 1, opt_name_len = strlen(opt_name))
    {
      had_variant = 0;
      check = token;
      if (mount_option_flags[opt_index] & HAS_NO_VARIANT && strncmp(token, "no", 2) == 0) {
        had_variant = HAS_NO_VARIANT;
        check = token + 2;
      } else if (mount_option_flags[opt_index] & HAS_R_VARIANT && token[0] == 'r') {
        had_variant = HAS_R_VARIANT;
        check = token + 1;
      }
    recheck_full:
      if (opt_name[opt_name_len - 1] == '=') {
        applies = (strncmp(check, opt_name, opt_name_len) == 0)
               || (strlen(check) == opt_name_len - 1 &&
                   strncmp(check, opt_name, opt_name_len - 1) == 0);
      } else {
        applies = strcmp(check, opt_name) == 0;
      }
      if (!applies && had_variant) {
        /* just in case an option starts with 'no' or 'r' */
        had_variant = 0;
        check = token;
        goto recheck_full;
      }
      if (applies) {
        this_opt_index = opt_index;
        break;
      }
    }

    if (this_opt_index != -1) {
      opt_flag = mount_option_flags[this_opt_index];
      if (opt_flag & IGNORE)
        continue;
      bits_to_change = opt_flag & FLAG_MASK;
      if (opt_flag & HAS_R_VARIANT)
        bits_to_change |= MS_REC;
      /* logical XOR */
      invert = !(opt_flag & INVERTED) != !(had_variant & HAS_NO_VARIANT);
      if (invert)
        bits &= ~bits_to_change;
      else
        bits |= bits_to_change;
    } else {
      /* Hack to handle fstype = nfs with vers = number, so we can
       * determine the NFS version and dispatch accordingly. nfsver
       * should only be non-NULL if the fstype is "nfs". */
      if (nfsver && *nfsver > -1 && (strncmp(token, "vers=", 5) == 0 || strncmp(token, "nfsvers=", 8) == 0)) {
        char *endptr = NULL;
        char *eq = strchr(token, '=') + 1;
        long val;
        if (!*eq)
          panic(0, "Empty NFS version specified.", NULL);
        val = strtol(eq, &endptr, 10);
        if (!endptr || !*endptr)
          panic(0, "Invalid NFS version specified: ", eq, NULL);
        if (val != 2 && val != 3 && val != 4)
          panic(0, "Invalid NFS version specified: ", eq, NULL);
        *nfsver = (int)val;
        continue;
      }

      append_to_buf(syscall_data, syscall_data_len, *syscall_data ? "," : "", token, NULL);
    }
  }

  return bits;
}

void determine_supported_filesystems()
{
  int r;

  /* we already did this */
  if (supported_filesystems_count > 0)
    return;

  r = traverse_file_by_line(PROC_FILESYSTEMS_FILENAME, (traverse_line_t)process_proc_filesystems, NULL);
  if (r < 0)
    panic(-r, "could not determine list of kernel-supported filesystems", NULL);
}

int process_proc_filesystems(void *data, const char *line, int line_is_incomplete)
{
  (void) data;
  /* yikes, shouldn't happen */
  if (line_is_incomplete)
    return 0;
  if (!strncmp(line, "nodev ", 6) || !strncmp(line, "nodev\t", 6))
    return 0;
  while (line[0] == ' ' || line[0] == '\t')
    ++line;
  if (supported_filesystems_count == MAX_SUPPORTED_FILESYSTEMS) {
    warn("kernel supports too many filesystem types, ignoring some "
         "(please specify the rootfstype= kernel parameter if your system doesn't boot because of this)",
         NULL);
    return 0;
  }
  set_buf(supported_filesystems[supported_filesystems_count++], MAX_FILESYSTEM_TYPE_LEN, line, NULL);
  return 0;
}
