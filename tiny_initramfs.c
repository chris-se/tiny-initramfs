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
static int find_bootserver_from_pnp();
static int find_bootserver_helper(void *data, const char *line, int line_is_incomplete);

#ifdef DEBUG_INITRAMFS
static void debug_dump_file(const char *fn);
static int debug_dump_file_helper(void *data, const char *line, int line_is_incomplete);
#endif

static char root_device[MAX_PATH_LEN];
static char root_options[MAX_LINE_LEN];
static char root_nfshost[MAX_LINE_LEN];
static char root_nfsdir[MAX_LINE_LEN];
static char root_nfsoptions[MAX_LINE_LEN];
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
  char real_device_name[MAX_PATH_LEN] = { 0 };

#ifdef DEBUG_INITRAMFS
  warn(LOG_PREFIX, "[ 0  ] Startup", NULL);
#endif

  r = mount("proc", "/proc", "proc", MS_NODEV | MS_NOEXEC | MS_NOSUID, NULL);
  if (r < 0)
    panic(errno, LOG_PREFIX, "Could not mount /proc", NULL);

#ifdef DEBUG_INITRAMFS
  warn(LOG_PREFIX, "[ 1  ] /proc mounted", NULL);
#endif

  r = mount("udev", "/dev", "devtmpfs", 0, DEVTMPFS_MOUNTOPTS);
  if (r < 0)
    panic(errno, LOG_PREFIX, "Could not mount /dev (as devtmpfs)", NULL);

#ifdef DEBUG_INITRAMFS
  warn(LOG_PREFIX, "[ 2  ] /dev mounted", NULL);
#endif

  parse_cmdline();

#ifdef DEBUG_INITRAMFS
  warn(LOG_PREFIX, "[ 3  ] ", PROC_CMDLINE_FILENAME, " parsed", NULL);
#endif

  if (!strlen(root_device))
    panic(0, LOG_PREFIX, "No root filesystem (root=) specified", NULL);

  if (strcmp(root_device, "/dev/nfs") == 0) {
    /* We have nfsroot, so build together new device name */
    if (!strlen(root_nfshost)) {
      r = find_bootserver_from_pnp();
      if (r < 0 || !strlen(root_nfshost))
        panic(r ? -r : ENOENT, LOG_PREFIX, "Failed to determine boot server from kernel", NULL);
    }

    /* Make sure file system type is set properly */
    if (!strlen(root_fstype) || (strcmp(root_fstype, "nfs") != 0 && strcmp(root_fstype, "nfs4") != 0)) {
      if (strlen(root_fstype))
        warn(LOG_PREFIX, "rootfstype set to ", root_fstype, " but root=/dev/nfs specified. Assuming rootfstype=nfs.", NULL);
      set_buf(root_fstype, MAX_FILESYSTEM_TYPE_LEN, "nfs", NULL);
    }

    /* This will be special-cased when mounting the filesystem to
     * replace it with the IP. */
    if (!strlen(root_nfsdir))
      set_buf(root_nfsdir, MAX_LINE_LEN, DEFAULT_ROOTFS_NFS_DIR, NULL);

    if (strlen(root_nfshost) + 1 + strlen(root_nfsdir) + 1 > MAX_PATH_LEN)
      panic(0, LOG_PREFIX, "nfsroot=", root_nfshost, ":", root_nfsdir, " too long.", NULL);

    set_buf(real_device_name, MAX_PATH_LEN, root_nfshost, ":", root_nfsdir, NULL);

    if (strlen(root_nfsoptions)) {
      if (strlen(root_options) + strlen(root_nfsoptions) + 2 > MAX_LINE_LEN)
        panic(0, LOG_PREFIX, "nfsroot options (\"", root_nfsoptions, "\") too long.", NULL);
      append_to_buf(root_options, MAX_LINE_LEN, strlen(root_options) ? "," : "", root_nfsoptions, NULL);
    }
  } else {
    if (root_wait_indefinitely)
      timeout_togo = -1;
    wait_for_device(real_device_name, &timeout_togo, root_device, root_delay);
  }

#ifdef DEBUG_INITRAMFS
  warn(LOG_PREFIX, "[ 4  ] waited for root device", NULL);
#endif

  r = mount_filesystem(real_device_name, TARGET_DIRECTORY, strlen(root_fstype) ? root_fstype : NULL, root_options, global_rw ? 0 : MS_RDONLY, global_rw ? MS_RDONLY : 0);
  if (r < 0)
    panic(-r, LOG_PREFIX, "Failed to mount root filesystem from ", root_device, NULL);

#ifdef DEBUG_INITRAMFS
  warn(LOG_PREFIX, "[ 5  ] mounted root filesystem", NULL);
#endif

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
    panic(0, LOG_PREFIX, "Entry in /etc/fstab for /usr must be a (non-symlink) kernel device path, or of the form UUID=, or an NFS filesystem..", NULL);

#ifdef DEBUG_INITRAMFS
  warn(LOG_PREFIX, "[ 6  ] parsed /etc/fstab", NULL);
#endif

  if (r == 0) {
    int usr_rw_override = global_rw;

    if (strcmp(usrfs_info.type, "nfs") != 0 && strcmp(usrfs_info.type, "nfs4") != 0) {
      /* wait for /usr filesystem device */
      wait_for_device(real_device_name, &timeout_togo, usrfs_info.source, 0);

#ifdef DEBUG_INITRAMFS
      warn(LOG_PREFIX, "[ 6.1] waited for /usr device", NULL);
#endif
    } else {
      set_buf(real_device_name, MAX_PATH_LEN, usrfs_info.source, NULL);

      /* for network filesystems don't consider ro/rw on the 
       * kernel command line, but just keep the options set
       * in /etc/fstab */
      usr_rw_override = 0;

#ifdef DEBUG_INITRAMFS
      warn(LOG_PREFIX, "[ 6.1] no need to wait for /usr device (NFS)", NULL);
#endif
    }

    /* mount it */
    r = mount_filesystem(real_device_name, TARGET_DIRECTORY "/usr", usrfs_info.type, usrfs_info.options, usr_rw_override ? 0 : MS_RDONLY, usr_rw_override ? MS_RDONLY : 0);
    if (r < 0)
      panic(-r, LOG_PREFIX, "Failed to mount /usr filesystem from ", usrfs_info.source, NULL);

#ifdef DEBUG_INITRAMFS
    warn(LOG_PREFIX, "[ 6.2] mounted /usr filesystem", NULL);
#endif
  }

  /* move mounts */
  r = mount("/dev", TARGET_DIRECTORY "/dev", NULL, MS_MOVE, NULL);

#ifdef DEBUG_INITRAMFS
    warn(LOG_PREFIX, "[ 7  ] moved /dev", NULL);
#endif

  if (!r)
    r = mount("/proc", TARGET_DIRECTORY "/proc", NULL, MS_MOVE, NULL);

#ifdef DEBUG_INITRAMFS
    warn(LOG_PREFIX, "[ 8  ] moved /proc", NULL);
#endif

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

#ifdef DEBUG_INITRAMFS
    warn(LOG_PREFIX, "[ 9  ] switched root, output of /proc/self/mountinfo now is:", NULL);
    debug_dump_file("/proc/self/mountinfo");
    warn(LOG_PREFIX, "[10  ] sleeping for 5s", NULL);
    sleep(5);
    warn(LOG_PREFIX, "[11  ] booting the system", NULL);
#endif

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
      set_buf(root_device, MAX_PATH_LEN, token, NULL);
    } else if (!strncmp(token, "rootflags=", 10)) {
      token += 10;
      /* this will automatically be at least 10 bytes shorter than
       * MAX_LINE_LEN */
      set_buf(root_options, MAX_PATH_LEN, token, NULL);
    } else if (!strncmp(token, "rootfstype=", 11)) {
      token += 11;
      if (strlen(token) > MAX_FILESYSTEM_TYPE_LEN - 1)
        panic(0, LOG_PREFIX, "Parameter rootfstype=", token, " too long", NULL);
      set_buf(root_fstype, MAX_FILESYSTEM_TYPE_LEN, token, NULL);
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
      set_buf(init_binary, MAX_PATH_LEN, token, NULL);
    } else if (!strncmp(token, "nfsroot=", 8)) {
      char *ptr;

      root_nfsdir[0] = '\0';
      root_nfshost[0] = '\0';
      root_nfsoptions[0] = '\0';

      token += 8;
      ptr = strchr(token, ',');
      if (ptr) {
        *ptr++ = '\0';
        set_buf(root_nfsoptions, MAX_LINE_LEN, ptr, NULL);
      }

      ptr = strchr(token, ':');
      if (ptr) {
        *ptr = '\0';
        set_buf(root_nfshost, MAX_LINE_LEN, token, NULL);
        token = ptr + 1;
      }

      set_buf(root_nfsdir, MAX_LINE_LEN, token, NULL);
    }
  }
  return 0;
}

int find_bootserver_from_pnp()
{
  return traverse_file_by_line(PROC_NET_PNP_FILENAME, (traverse_line_t)find_bootserver_helper, NULL);
}

int find_bootserver_helper(void *data, const char *line, int line_is_incomplete)
{
  const char *value;

  (void)data;

  /* ignore lines we don't understand */
  if (line_is_incomplete)
    return 0;

  if (!strncmp(line, "bootserver", 10) && (line[10] == ' ' || line[10] == '\t')) {
    value = &line[11];
    while (*value == ' ' || *value == '\t')
      ++value;
    if (strlen(value) > 0)
      set_buf(root_nfshost, MAX_LINE_LEN, value, NULL);

    return 1;
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

#ifdef DEBUG_INITRAMFS
void debug_dump_file(const char *fn)
{
  (void)traverse_file_by_line(fn, (traverse_line_t)debug_dump_file_helper, NULL);
}

static int debug_dump_file_helper(void *data, const char *line, int line_is_incomplete)
{
  (void)data;
  (void)line_is_incomplete;
  warn(line, NULL);
  return 0;
}
#endif
