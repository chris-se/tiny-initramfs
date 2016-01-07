/*
 * tiny_initramfs - Minimalistic initramfs implementation
 * Copyright (C) 2016 Christian Seiler <christian@iwakd.de>
 *
 * tiny_initramfs.c: main program
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

#include "tiny_initramfs.h"
#include <stdlib.h>
#include <unistd.h>
#include <sys/mount.h>
#include <errno.h>
#include <string.h>
#include <limits.h>

static void parse_cmdline();
static int parse_cmdline_helper(void *data, const char *line, int line_is_incomplete);
static void try_exec(int orig_argc, char *const orig_argv[], const char *binary);

static char root_device[MAX_PATH_LEN];
static char root_options[MAX_LINE_LEN];
static char root_fstype[MAX_FILESYSTEM_TYPE_LEN];
static int root_delay;
static int root_wait_indefinitely;
static char init_binary[MAX_PATH_LEN];
static int global_rw;

int main(int argc, char **argv)
{
  int r;
  int timeout_togo = DEVICE_TIMEOUT;
  fstab_info usrfs_info;
  char real_device_name[MAX_PATH_LEN];

  r = mount("proc", "/proc", "proc", MS_NODEV | MS_NOEXEC | MS_NOSUID, NULL);
  if (r < 0)
    panic(errno, LOG_PREFIX, "Could not mount /proc", NULL);

  r = mount("udev", "/dev", "devtmpfs", 0, DEVTMPFS_MOUNTOPTS);
  if (r < 0)
    panic(errno, LOG_PREFIX, "Could not mount /dev (as devtmpfs)", NULL);

  parse_cmdline();

  if (!strlen(root_device))
    panic(0, LOG_PREFIX, "No root filesystem (root=) specified", NULL);

  if (root_wait_indefinitely)
    timeout_togo = -1;
  wait_for_device(real_device_name, &timeout_togo, root_device, root_delay);

  r = mount_filesystem(real_device_name, TARGET_DIRECTORY, strlen(root_fstype) ? root_fstype : NULL, root_options, global_rw ? 0 : MS_RDONLY, global_rw ? MS_RDONLY : 0);
  if (r < 0)
    panic(-r, LOG_PREFIX, "Failed to mount root filesystem from ", root_device, NULL);

  /* We need these regardless of /usr handling */
  if (access(TARGET_DIRECTORY "/dev", F_OK) != 0)
    panic(errno, LOG_PREFIX, "/dev doesn't exist on root filesystem", NULL);
  if (access(TARGET_DIRECTORY "/proc", F_OK) != 0)
    panic(errno, LOG_PREFIX, "/proc doesn't exist on root filesystem", NULL);

  /* Make sure we mount /usr if present in /etc/fstab
   *  (no /etc/fstab is no error, we just assume that there'll
   *  be no entry then) */
  r = fstab_find_fs("/usr", &usrfs_info);
  if (r < 0 && r != -ENOENT && r != -ENODEV)
    panic(-r, LOG_PREFIX, "Failed to parse /etc/fstab in root device (non-existence would not be an error)", NULL);
  if (r == -ENODEV)
    panic(0, LOG_PREFIX, "Entry in /etc/fstab for /usr must be a (non-symlink) kernel device path, or of the form UUID=.", NULL);

  if (r == 0) {
    /* wait for /usr filesystem device */
    wait_for_device(real_device_name, &timeout_togo, usrfs_info.source, 0);

    /* mount it */
    r = mount_filesystem(real_device_name, TARGET_DIRECTORY "/usr", usrfs_info.type, usrfs_info.options, global_rw ? 0 : MS_RDONLY, global_rw ? MS_RDONLY : 0);
    if (r < 0)
      panic(-r, LOG_PREFIX, "Failed to mount /usr filesystem from ", usrfs_info.source, NULL);
  }

  /* move mounts */
  r = mount("/dev", TARGET_DIRECTORY "/dev", NULL, MS_MOVE, NULL);

  if (!r)
    r = mount("/proc", TARGET_DIRECTORY "/proc", NULL, MS_MOVE, NULL);

  if (r < 0)
    panic(errno, LOG_PREFIX, "Couldn't move /dev or /proc from initramfs to root filesystem", NULL);

  /* switch root */
  r = chdir(TARGET_DIRECTORY);
  if (!r)
    r = mount(TARGET_DIRECTORY, "/", NULL, MS_MOVE, NULL);
  if (!r)
    r = chroot(".");
  if (r < 0)
    panic(errno, LOG_PREFIX, "Couldn't switch root filesystem", NULL);

  if (strlen(init_binary)) {
    try_exec(argc, argv, init_binary);
  } else {
    try_exec(argc, argv, "/sbin/init");
    try_exec(argc, argv, "/etc/init");
    try_exec(argc, argv, "/bin/init");
    try_exec(argc, argv, "/bin/sh");
  }

  /* Message stolen from Linux's init/main.c */
  panic(0, "No working init found. Try passing init= option to kernel. "
           "See Linux Documentation/init.txt for guidance.", NULL);
  return 1;
}

void parse_cmdline()
{
  int r;
  r = traverse_file_by_line(PROC_CMDLINE_FILENAME, (traverse_line_t)parse_cmdline_helper, NULL);
  if (r < 0)
    panic(-r, LOG_PREFIX, "Could not parse ", PROC_CMDLINE_FILENAME, NULL);
}

int parse_cmdline_helper(void *data, const char *line, int line_is_incomplete)
{
  char *token;
  char *saveptr;
  char *endptr;
  unsigned long lval;

  (void)data;
  /* this really shouldn't happen, but don't try to interpret garbage */
  if (line_is_incomplete)
    return 0;

  for (token = strtok_r((char *)line, " \t", &saveptr); token != NULL; token = strtok_r(NULL, " \t", &saveptr)) {
    if (!strncmp(token, "root=", 5)) {
      token += 5;
      if (strlen(token) > MAX_PATH_LEN - 1)
        panic(0, LOG_PREFIX, "Parameter root=", token, " too long", NULL);
      if (!is_valid_device_name(token, NULL, NULL, NULL, NULL))
        panic(0, LOG_PREFIX, "Parameter root=", token, " unsupported (only /dev/, 0xMAJMIN and UUID= are supported)", NULL);
      strncpy(root_device, token, MAX_PATH_LEN);
    } else if (!strncmp(token, "rootflags=", 10)) {
      token += 10;
      /* this will automatically be at least 10 bytes shorter than
       * MAX_LINE_LEN */
      strncpy(root_options, token, MAX_LINE_LEN - 1);
    } else if (!strncmp(token, "rootfstype=", 11)) {
      token += 11;
      if (strlen(token) > MAX_FILESYSTEM_TYPE_LEN - 1)
        panic(0, LOG_PREFIX, "Parameter rootfstype=", token, " too long", NULL);
      strncpy(root_fstype, token, MAX_FILESYSTEM_TYPE_LEN - 1);
    } else if (!strncmp(token, "rootdelay=", 10)) {
      token += 10;
      lval = strtoul(token, &endptr, 10);
      if (!*token || !endptr || *endptr || lval > INT_MAX)
        panic(0, LOG_PREFIX, "Invalid rootdelay=", token," value, must be integer (and must fit into integer data type)", NULL);
      root_delay = (int) lval;
    } else if (!strcmp(token, "rootwait")) {
      root_wait_indefinitely = 1;
    } else if (!strcmp(token, "ro")) {
      global_rw = 0;
    } else if (!strcmp(token, "rw")) {
      global_rw = 1;
    } else if (!strncmp(token, "init=", 5)) {
      token += 5;
      if (strlen(token) > MAX_PATH_LEN - 1)
        panic(0, LOG_PREFIX, "Parameter init=", token, " too long", NULL);
      strncpy(init_binary, token, MAX_PATH_LEN - 1);
    }
  }
  return 0;
}

void try_exec(int orig_argc, char *const orig_argv[], const char *binary)
{
  char *argv[256];
  int i;

  if (orig_argc > 255)
    panic(0, "Too many arguments to init.", NULL);

  argv[0] = (char *)init_binary;
  for (i = 1; i < orig_argc; i++)
    argv[i] = orig_argv[i];
  argv[i] = NULL;

  execv(binary, argv);
}
