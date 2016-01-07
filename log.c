/*
 * tiny_initramfs - Minimalistic initramfs implementation
 * Copyright (C) 2016 Christian Seiler <christian@iwakd.de>
 *
 * log.c: Basic logging helpers
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

#include <sys/uio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>

static void showmsgv(va_list ap, const char *before1, const char *after1, const char *after2);

void panic(int err, ...)
{
  va_list ap;
  va_start(ap, err);
  if (err)
    showmsgv(ap, NULL, ": ", strerror(err));
  else
    showmsgv(ap, NULL, NULL, NULL);
  va_end(ap);

  /* We want the user to see the message before we cause a kernel panic,
   * because a kernel panic obscures the message. But we need to cause
   * a kernel panic (by PID 1 exiting), because if the user tells the
   * kernel to reboot on panic, we want to make sure this happens. */
  warn(LOG_PREFIX, "Will cause kernel panic in 10s...", NULL);
  sleep(10);
  _exit(1);
}

void warn(const char *str1, ...)
{
  va_list ap;
  va_start(ap, str1);
  showmsgv(ap, str1, NULL, NULL);
  va_end(ap);
}

void showmsgv(va_list ap, const char *before1, const char *after1, const char *after2)
{
  /* Don't use stdio functions, because we link statically
   * and they bloat the binary. */

  va_list ap_count;
  int argc = 0;
  int i;
  int fd;
  struct iovec iov[32];
  unsigned extra_arg_count = !!before1 + !!after1 + !!after2;
  unsigned first_arg = 0;

  va_copy(ap_count, ap);
  while (va_arg(ap_count, const char *)) {
    argc++;
  }
  va_end(ap_count);

  /* Try to open /dev/kmsg, log to stderr if not possible */
  fd = open(KMSG_FILENAME, O_WRONLY | O_NOCTTY | O_CLOEXEC);
  if (fd < 0)
    fd = 2;

  /* We only support a fixed number of arguments arguments. */
  if (argc + 1 + extra_arg_count > 32)
    argc = 31 - extra_arg_count;

  if (before1) {
    iov[0].iov_base = (char *)before1;
    iov[0].iov_len = strlen(before1);
    argc++;
    first_arg = 1;
  }

  for (i = first_arg; i < argc; i++) {
    const char *arg = va_arg(ap, const char *);
    iov[i].iov_base = (char *)arg;
    iov[i].iov_len = strlen(arg);
  }

  if (after1) {
    iov[argc].iov_base = (char *)after1;
    iov[argc].iov_len = strlen(after1);
    argc++;
  }

  if (after2) {
    iov[argc].iov_base = (char *)after2;
    iov[argc].iov_len = strlen(after2);
    argc++;
  }

  iov[argc].iov_base = (char *)"\n";
  iov[argc].iov_len = 1;

  writev(fd, iov, argc + 1);

  if (fd >= 3)
    close(fd);
}
