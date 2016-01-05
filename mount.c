/*
 * tiny_initrd - Minimalistic initrd implementation
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
#include <sys/mount.h>
#include <errno.h>

#include "tiny_initrd.h"

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
  options = parse_mount_options(data, MAX_LINE_LEN, flags);
  int rc = -1;

  options |= override_flags_add;
  options &= ~override_flags_subtract;

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

int parse_mount_options(char *syscall_data, size_t syscall_data_len, const char *option_string)
{
  static struct {
    const char *name;
    int flags;
    int extra;
  } option_definitions[] = {
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
  }, *optdef, *this_optdef;
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

  strncpy(opts, option_string, MAX_LINE_LEN - 1);
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
      if (*syscall_data) {
        strncat(syscall_data, ",", syscall_data_len - 1);
        strncat(syscall_data, token, syscall_data_len - 2);
        syscall_data_len -= strlen(token) + 1;
      } else {
        strncpy(syscall_data, token, syscall_data_len - 1);
        syscall_data_len -= strlen(token);
      }
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
  strncpy(supported_filesystems[supported_filesystems_count++], line, MAX_FILESYSTEM_TYPE_LEN - 1);
  return 0;
}
