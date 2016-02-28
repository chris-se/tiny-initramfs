/*
 * tiny_initramfs - Minimalistic initramfs implementation
 * Copyright (C) 2016 Christian Seiler <christian@iwakd.de>
 *
 * devices.c: Device detection functions
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

#define _LARGEFILE_SOURCE

#include "tiny_initramfs.h"

#include <sys/time.h>
#include <time.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdint.h>

#ifdef ENABLE_UUID
#include <dirent.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>

/* Not all libcs define these things, unfortunately... */
#ifndef DT_UNKNOWN
#define DT_UNKNOWN 0
#define DT_FIFO 1
#define DT_CHR 2
#define DT_DIR 4
#define DT_BLK 6
#define DT_REG 8
#define DT_LNK 10
#define DT_SOCK 12
#define DT_WHT 14
#endif

/* We can't include linux/fs.h here. */
#define BLKGETSIZE64 _IOR(0x12,114,size_t)

static int hexbyte(char c);
static int is_blockdev_excluded(const char *device_name);
static int is_fs_with_uuid(const char *device_name, const char *uuid_buf);
static int is_ext234_with_uuid(const char *device_name, const char *uuid_buf);
static int is_xfs_with_uuid(const char *device_name, const char *uuid_buf);
static int is_btrfs_with_uuid(const char *device_name, const char *uuid_buf);
static int read_block(const char *device_name, off_t start, void *data_buffer, size_t len);

int parse_uuid(char *uuid_buf /* 16 bytes */, const char *string_representation)
{
  int n;
  int c1, c2;
  const char *ptr;
  if (strlen(string_representation) < 32)
    return -EINVAL;

  for (n = 0, ptr = string_representation; *ptr; ) {
    if (ptr != string_representation && ptr[0] == '-')
      ptr++;
    if (!ptr[0] || !ptr[1])
      return -EINVAL;
    c1 = hexbyte(ptr[0]);
    c2 = hexbyte(ptr[1]);
    if (c1 < 0 || c2 < 0)
      return -EINVAL;
    if (n >= 16)
      return -EINVAL;
    uuid_buf[n++] = (char)((c1 << 4) + c2);
    ptr += 2;
  }

  if (n != 16)
    return -EINVAL;

  return 0;
}
#endif /* defined(ENABLE_UUID) */

void wait_for_device(char *real_device_name, int *timeout, const char *device, int delay)
{
  /* We don't have udev running, but there is devtmpfs, so we just
   * do a very simple and stupid polling loop to wait until the
   * requested device is present. This could be improved a bit,
   * but for now it's good enough. */
  time_t start, current;
  int have_device;
  static int have_shown_message_timeout;
  int type;
  unsigned int major, minor;
  char uuid[16];

  /* Parse device information */
  if (!is_valid_device_name(device, &type, &major, &minor, uuid))
    panic(0, "Unsupported device specified: ", device, NULL);

  if (delay)
    (void)sleep(delay);

  /* Our timeout starts *after* the rootdelay. */
  start = time(NULL);

#ifdef ENABLE_UUID
  if (type != WANT_NAME) {
    have_device = scan_devices(real_device_name, type, major, minor, uuid);
  } else
#endif
  {
    set_buf(real_device_name, MAX_PATH_LEN, device, NULL);
    have_device = access(device, F_OK) != 0;
  }

  while (have_device) {
    current = time(NULL);
    if (*timeout > 0 && current - start > *timeout)
      panic(0, "Timeout while waiting for devices for / (and possibly /usr) filesystems to appear "
               "(did you specify the correct ones?)", NULL);
    /* In case this takes longer, show a nice message so the user has SOME
     * idea of what's going on here. */
    if (current - start > DEVICE_MESSAGE_TIMEOUT && !have_shown_message_timeout) {
      have_shown_message_timeout = 1;
      warn("Waiting for ", device, " to appear...", NULL);
    }
    /* Sleep for DEVICE_POLL_MSEC milliseconds, then poll again. */
    struct timespec req = { 0, DEVICE_POLL_MSEC * 1000 * 1000 };
    struct timespec rem;
    (void)nanosleep(&req, &rem);

#ifdef ENABLE_UUID
    if (type != WANT_NAME)
      have_device = scan_devices(real_device_name, type, major, minor, uuid);
    else
#endif
      have_device = access(device, F_OK) != 0;
  }

  /* Make sure we record how many seconds on the timeout are left,
   * because this function may be called again for the /usr filesystem. */
  if (*timeout > 0) {
    current = time(NULL);
    *timeout = current - start;
    if (*timeout <= 0)
      *timeout = 1;
  }
}

int is_valid_device_name(const char *device_name, int *type, unsigned int* major, unsigned int *minor, char *uuid)
{
#ifdef ENABLE_UUID
  int r;
  char *endptr;
  char uuid_buf[32 + 4 + 1] = { 0 };
  char uuid_temp[16];
  unsigned long x;
#else
  (void)major;
  (void)minor;
  (void)uuid;
#endif

  if (!device_name)
    return 0;

  if (!*device_name)
    return 0;

  if (strncmp(device_name, "/dev/", 5) == 0) {
    if (type)
      *type = WANT_NAME;
    return 1;
  }

#ifdef ENABLE_UUID
  /* 0x803 or so for 8:3 */
  if (device_name[0] == '0' && device_name[1] == 'x') {
    x = strtoul(device_name + 2, &endptr, 16);
    if (endptr && !*endptr) {
      if (type) {
        *type = WANT_MAJMIN;
        *major = (int)(x >> 8);
        *minor = (int)(x & 0xff);
      }
      return 1;
    }
    return 0;
  }

  if (strncmp(device_name, "UUID=", 5) == 0) {
    char c;

    device_name += 5;
    c = *device_name;
    if (c == '"' || c == '\'') {
      ++device_name;
      if (device_name[strlen(device_name)-1] != c)
        return 0;
      if (strlen(device_name) > 32 + 4 + 1)
        return 0;
      strncpy(uuid_buf, device_name, 32 + 4);
    } else {
      if (strlen(device_name) > 32 + 4)
        return 0;
      strncpy(uuid_buf, device_name, 32 + 4);
    }
    if (!uuid)
      uuid = uuid_temp;
    r = (parse_uuid(uuid, uuid_buf) == 0);
    if (r && type)
      *type = WANT_UUID;
    return r;
  }
#endif

  return 0;
}

#ifdef ENABLE_UUID
/* Which data types for this structure is available is wildly
 * incompatible between libc implementations, so we just use the
 * stdint.h types. */
struct linux_dirent {
    uint64_t         d_ino;
    int64_t          d_off;
    uint16_t         d_reclen;
    unsigned char    d_type;
    char             d_name[];
};

int scan_devices(char *device_name /* MAX_PATH_LEN bytes */, int type, unsigned int maj, unsigned int min, const char *uuid /* 16 bytes */)
{
  int dirfd;
  int nread, bpos;
  struct linux_dirent *d;
  char buf[1024];
  int r;
  struct stat st;
  char fn_buf[MAX_PATH_LEN];

  dirfd = open("/dev", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  if (dirfd < 0)
    return -errno;

  while (1) {
    /* We assume that either of these will be available from a libc
       implementation. */
#ifdef SYS_getdents64
    nread = syscall(SYS_getdents64, dirfd, (void *)buf, 1024);
#else
    nread = getdents64(dirfd, (void *)buf, 1024);
#endif
    if (nread < 0) {
      r = -errno;
      close(dirfd);
      return -r;
    }

    if (nread == 0)
      break;

    for (bpos = 0; bpos < nread; ) {
      d = (struct linux_dirent *)(buf + bpos);
      set_buf(fn_buf, MAX_PATH_LEN, "/dev/", d->d_name, NULL);
      if (strcmp(d->d_name, ".") != 0 &&
          strcmp(d->d_name, "..") != 0 &&
          (d->d_type == DT_UNKNOWN || type == WANT_MAJMIN)) {
        r = stat(fn_buf, &st);
        if (r == 0 && S_ISBLK(st.st_mode))
          d->d_type = DT_BLK;
        /* skip if stat fails */
        if (r < 0 && type == WANT_MAJMIN)
          d->d_type = DT_UNKNOWN;
      }
      if (d->d_type == DT_BLK && !is_blockdev_excluded(d->d_name)) {
        /* See if we found the device we want... */
        if (type == WANT_MAJMIN) {
          if (major(st.st_rdev) == maj && minor(st.st_rdev) == min) {
            set_buf(device_name, MAX_PATH_LEN, fn_buf, NULL);
            close(dirfd);
            return 0;
          }
        } else if (type == WANT_UUID) {
          if (is_fs_with_uuid(fn_buf, uuid)) {
            set_buf(device_name, MAX_PATH_LEN, fn_buf, NULL);
            close(dirfd);
            return 0;
          }
        }
      }
      bpos += d->d_reclen;
    }
  }

  close(dirfd);

  return -ENOENT;
}

int hexbyte(char c)
{
  if (c >= '0' && c <= '9')
    return c - '0';
  if (c >= 'A' && c <= 'F')
    return c - 'A' + 0xa;
  if (c >= 'a' && c <= 'f')
    return c - 'a' + 0xa;
  return -1;
}

int is_blockdev_excluded(const char *device_name)
{
  typedef struct {
    const char *prefix;
    const char *suffix;
  } dev_match_t;
  static dev_match_t exclude_devices[] = {
    { "fd",     NULL   },
    { "mtd",    NULL   },
    { "nbd",    NULL   },
    { "gnbd",   NULL   },
    { "btibm",  NULL   },
    { "dm-",    NULL   },
    { "zram",   NULL   },
    { "mmcblk", "rpmb" },
    { "sr",     NULL   },
  /* FIXME: We don't exclude md devices here, because we assume that
   *        they will only exist if the kernel has assembled them
   *        completely or not at all. (And the kernel only
   *        automatically assembles devices if they are specified on
   *        the kernel command line.) This isn't tested, however. */
  /*{ "md",     NULL   },*/
    { NULL, NULL }
  };
  dev_match_t *ptr;
  size_t l = strlen(device_name);
  size_t k;
  int matched;

  for (ptr = exclude_devices; ptr->prefix || ptr->suffix; ptr++) {
    matched = 1;
    if (ptr->prefix) {
      if (strncmp(device_name, ptr->prefix, strlen(ptr->prefix)) != 0)
        matched = 0;
    }
    if (ptr->suffix) {
      k = strlen(ptr->suffix);
      if (l < k || strncmp(&device_name[l - k], ptr->suffix, k) != 0)
        matched = 0;
    }
    if (matched)
      return 1;
  }
  return 0;
}

int read_block(const char *device_name, off_t start, void *data_buffer, size_t len)
{
  int fd, r;
  uint64_t blksize;
  off_t pos;
  ssize_t n;

  fd = open(device_name, O_RDONLY | O_CLOEXEC);
  if (fd < 0)
    return -errno;

  r = ioctl(fd, BLKGETSIZE64, &blksize);
  if (r < 0) {
    r = -errno;
    close(fd);
    return r;
  }

  if ((uint64_t)start + (uint64_t)len > blksize) {
    r = 1;
    close(fd);
    return r;
  }

  pos = lseek(fd, start, SEEK_SET);
  if (pos == (off_t)-1) {
    r = -errno;
    close(fd);
    return r;
  }

  n = read(fd, data_buffer, len);
  if (n < 0) {
    r = -errno;
    close(fd);
    return r;
  }

  close(fd);

  return 0;
}

int is_fs_with_uuid(const char *device_name, const char *uuid_buf)
{
  return is_btrfs_with_uuid(device_name, uuid_buf)
      || is_xfs_with_uuid(device_name, uuid_buf)
      || is_ext234_with_uuid(device_name, uuid_buf);
}

int is_ext234_with_uuid(const char *device_name, const char *uuid_buf)
{
  char buf[0x78];
  int r;

  r = read_block(device_name, 1024, buf, 0x78);
  if (r < 0 || r > 0)
    return 0;

  return memcmp(&buf[0x38], "\x53\xef", 2) == 0
      && memcmp(&buf[0x68], uuid_buf, 16) == 0;
}

int is_xfs_with_uuid(const char *device_name, const char *uuid_buf)
{
  char buf[0x30];
  int r;

  r = read_block(device_name, 0, buf, 0x30);
  if (r < 0 || r > 0)
    return 0;

  return memcmp(&buf[0x00], "XFSB", 4) == 0
      && memcmp(&buf[0x20], uuid_buf, 16) == 0;
}

int is_btrfs_with_uuid(const char *device_name, const char *uuid_buf)
{
  char buf[0x48];
  int r;

  r = read_block(device_name, 0x10000, buf, 0x48);
  if (r < 0 || r > 0)
    return 0;

  return memcmp(&buf[0x40], "_BHRfS_M", 8) == 0
      && memcmp(&buf[0x20], uuid_buf, 16) == 0;
}
#endif /* defined(ENABLE_UUID) */
