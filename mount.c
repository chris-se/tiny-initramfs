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

#ifdef DEBUG_INITRAMFS
  warn(LOG_PREFIX, "[----] mount_filesystem(\"", source, "\", \"", target, "\", \"", type ? type : "(null)", "\", \"", flags, "\", ...): start", NULL);
#endif

  if (type && (!strcmp(type, "nfs") || !strcmp(type, "nfs4")))
    nfsver = !strcmp(type, "nfs4") ? 4 : 0;
  options = parse_mount_options(data, MAX_LINE_LEN, flags, nfsver != -1 ? &nfsver : NULL);

#ifdef DEBUG_INITRAMFS
  warn(LOG_PREFIX, "[----] mount_filesystem: parsing mount options (done), unparsed options: ", data, NULL);
#endif

  options |= override_flags_add;
  options &= ~override_flags_subtract;

  if (type && !strcmp(type, "nfs4") && nfsver != 4)
    panic(0, LOG_PREFIX, "Cannot combine [nfs]vers=2/3 option with filesystem type nfs4.", NULL);
  if (type && (!strcmp(type, "nfs") || !strcmp(type, "nfs4"))) {
    if (nfsver != 4 && nfsver != 0)
      panic(0, LOG_PREFIX, "Sorry, only NFSv4 is currently supported.", NULL);
    /* Note that nfsver == 0 means we have type == nfs and no vers= parameter
     * at this point - which means that in principle we should try first NFSv4
     * and then NFSv3/2. But until we support NFSv3, we'll just do NFSv4. */
    return mount_nfs4(source, target, options, data);
  }

#ifdef DEBUG_INITRAMFS
  warn(LOG_PREFIX, "[----] mount_filesystem: not NFS", NULL);
#endif

  /* We need to loop through filesystem types as the kernel doesn't do
   * that for us if we call mount(). libmount does something similar,
   * but we don't want to link against it. */
  if ((!type || !strcmp(type, "auto") || !strcmp(type, "none")) && !(options & (MS_MOVE | MS_REMOUNT | MS_BIND))) {
    int i;

    determine_supported_filesystems();

    errno = EINVAL;
    for (i = 0; i < supported_filesystems_count; i++) {
      rc = mount(source, target, supported_filesystems[i], options | MS_SILENT, data);
      if (rc == 0)
        return 0;
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

#define INVERTED         0x01
#define HAS_NO_VARIANT   0x02
#define HAS_R_VARIANT    0x04
#define IGNORE           0x80

int parse_mount_options(char *syscall_data, size_t syscall_data_len, const char *option_string, int *nfsver)
{
  typedef struct {
    const char *name;
    int flags;
    int extra;
  } mount_option_t;
  static mount_option_t option_definitions[] = {
    { "ro",          MS_RDONLY,          0                         },
    { "rw",          MS_RDONLY,          INVERTED                  },
    { "exec",        MS_NOEXEC,          INVERTED | HAS_NO_VARIANT },
    { "suid",        MS_NOSUID,          INVERTED | HAS_NO_VARIANT },
    { "dev",         MS_NODEV,           INVERTED | HAS_NO_VARIANT },
    { "sync",        MS_SYNCHRONOUS,     HAS_NO_VARIANT            },
#ifdef MS_DIRSYNC
    { "dirsync",     MS_DIRSYNC,         0                         },
#endif
    { "remount",     MS_REMOUNT,         0                         },
    { "bind",        MS_BIND,            HAS_R_VARIANT             },
#ifdef MS_NOSUB
    { "sub",         MS_NOSUB,           INVERTED | HAS_NO_VARIANT },
#endif
#ifdef MS_SILENT
    { "silent",      MS_SILENT,          0                         },
    { "loud",        MS_SILENT,          INVERTED                  },
#endif
#ifdef MS_MANDLOCK
    { "mand",        MS_MANDLOCK,        HAS_NO_VARIANT            },
#endif
    { "atime",       MS_NOATIME,         INVERTED | HAS_NO_VARIANT },
#ifdef MS_I_VERSION
    { "iversion",    MS_I_VERSION,       HAS_NO_VARIANT            },
#endif
#ifdef MS_NODIRATIME
    { "diratime",    MS_NODIRATIME,      INVERTED | HAS_NO_VARIANT },
#endif
#ifdef MS_RELATIME
    { "relatime",    MS_RELATIME,        HAS_NO_VARIANT            },
#endif
#ifdef MS_STRICTATIME
    { "strictatime", MS_STRICTATIME,     HAS_NO_VARIANT            },
#endif
    { "unbindable",  MS_UNBINDABLE,      HAS_R_VARIANT             },
    { "private",     MS_PRIVATE,         HAS_R_VARIANT             },
    { "slave",       MS_SLAVE,           HAS_R_VARIANT             },
    { "shared",      MS_SHARED,          HAS_R_VARIANT             },
    { "defaults",    0,                  0                         },
    /* NOTE: We ignore all of these for now, but if a filesystem we
     *       want to mount really has these options set in /etc/fstab,
     *       it's not clear that that is the right thing to do...
     *       (Most of them don't make sense for /usr anyway, and we
     *       don't support loop devices.)
     */
    { "_netdev",     0,                  IGNORE                    },
    { "auto",        0,                  HAS_NO_VARIANT | IGNORE   },
    { "user=",       0,                  HAS_NO_VARIANT | IGNORE   },
    { "users",       0,                  HAS_NO_VARIANT | IGNORE   },
    { "owner",       0,                  HAS_NO_VARIANT | IGNORE   },
    { "group",       0,                  HAS_NO_VARIANT | IGNORE   },
    { "comment=",    0,                  IGNORE                    },
    { "loop=",       0,                  IGNORE                    },
    { "offset=",     0,                  IGNORE                    },
    { "sizelimit=",  0,                  IGNORE                    },
    { "encryption=", 0,                  IGNORE                    },
    { "nofail",      0,                  IGNORE                    },
    { "uhelper=",    0,                  IGNORE                    },
    { "helper=",     0,                  IGNORE                    },
    { NULL,          0,                  0                         }
  };
  mount_option_t *optdef, *this_optdef;
  char opts[MAX_LINE_LEN] = { 0 };
  char *saveptr;
  char *token;
  char *check;
  int bits = 0;
  size_t opt_name_len;
  int had_variant;
  int applies;
  int bits_to_change;
  int invert;

  set_buf(opts, MAX_LINE_LEN, option_string, NULL);
  memset(syscall_data, 0, syscall_data_len);

  for (token = strtok_r(opts, ",", &saveptr); token != NULL; token = strtok_r(NULL, ",", &saveptr)) {
    /* special case: ignore all that starts with x- */
    if (token[0] == 'x' && token[1] == '-')
      continue;

    this_optdef = NULL;
    had_variant = 0;
    for (optdef = option_definitions; optdef->name; optdef++) {
      opt_name_len = strlen(optdef->name);
      had_variant = 0;
      check = token;
      if (optdef->extra & HAS_NO_VARIANT && strncmp(token, "no", 2) == 0) {
        had_variant = HAS_NO_VARIANT;
        check = token + 2;
      } else if (optdef->extra & HAS_R_VARIANT && token[0] == 'r') {
        had_variant = HAS_R_VARIANT;
        check = token + 1;
      }
    recheck_full:
      if (optdef->name[opt_name_len - 1] == '=') {
        applies = (strncmp(check, optdef->name, opt_name_len) == 0)
               || (strlen(check) == opt_name_len - 1 &&
                   strncmp(check, optdef->name, opt_name_len - 1) == 0);
      } else {
        applies = strcmp(check, optdef->name) == 0;
      }
      if (!applies && had_variant) {
        /* just in case an option starts with 'no' or 'r' */
        had_variant = 0;
        check = token;
        goto recheck_full;
      }
      if (applies) {
        this_optdef = optdef;
        break;
      }
    }

    if (this_optdef) {
      if (this_optdef->extra & IGNORE)
        continue;
      bits_to_change = this_optdef->flags;
      if (had_variant & HAS_R_VARIANT)
        bits_to_change |= MS_REC;
      invert = (this_optdef->extra & INVERTED);
      if (had_variant & HAS_NO_VARIANT)
        invert = !invert;
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
          panic(0, LOG_PREFIX, "Empty NFS version specified.", NULL);
        val = strtol(eq, &endptr, 10);
        if (!endptr || !*endptr)
          panic(0, LOG_PREFIX, "Invalid NFS version specified: ", eq, NULL);
        if (val != 2 && val != 3 && val != 4)
          panic(0, LOG_PREFIX, "Invalid NFS version specified: ", eq, NULL);
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
    panic(-r, LOG_PREFIX, "could not determine list of kernel-supported filesystems", NULL);
}

int process_proc_filesystems(void *data, const char *line, int line_is_incomplete)
{
  (void) data;
  /* yikes, shouldn't happen */
  if (line_is_incomplete)
    return 0;
  if (!strncmp(line, "nodev", 5) && (line[5] == ' ' || line[5] == '\t'))
    return 0;
  while (line[0] == ' ' || line[0] == '\t')
    ++line;
  if (supported_filesystems_count == MAX_SUPPORTED_FILESYSTEMS) {
    warn(LOG_PREFIX, "kernel supports too many filesystem types, ignoring some "
                     "(please specify the rootfstype= kernel parameter if your system doesn't boot because of this)",
         NULL);
    return 0;
  }
  set_buf(supported_filesystems[supported_filesystems_count++], MAX_FILESYSTEM_TYPE_LEN, line, NULL);
  return 0;
}
