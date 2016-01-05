/*
 * tiny_initrd - Minimalistic initrd implementation
 * Copyright (C) 2016 Christian Seiler <christian@iwakd.de>
 *
 * io.c: I/O helper functions
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

#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

#include "tiny_initrd.h"

int traverse_file_by_line(const char *filename, traverse_line_t fn, void *data)
{
  int fd;
  ssize_t r;
  char buf[MAX_LINE_LEN] = { 0 };
  char *pos;
  char *oldpos;
  int more_data = 1, line_is_incomplete = 0;
  int e;

  fd = open(filename, O_RDONLY | O_CLOEXEC);
  if (fd < 0)
    return -errno;

  pos = buf;

  while (more_data) {
  read_more_data:
    memset(pos, 0, MAX_LINE_LEN - 1 - (pos - buf));
    r = read(fd, pos, MAX_LINE_LEN - 1 - (pos - buf));
    if (r < 0) {
      e = -errno;
      close(fd);
      return e;
    }

    more_data = (r == MAX_LINE_LEN - 1 - (pos - buf));

    oldpos = buf;
    do {
      pos = strchr(oldpos, '\n');
      if (!pos && more_data) {
        if (oldpos == buf) {
          line_is_incomplete = 1;
          pos = oldpos = buf;
        } else {
          memmove(buf, oldpos, MAX_LINE_LEN - (oldpos - buf));
          pos = buf + MAX_LINE_LEN - 1 - (oldpos - buf);
          oldpos = buf;
        }
        goto read_more_data;
      }
      if (pos) {
        *pos = '\0';
        pos++;
      }
      e = fn(data, oldpos, line_is_incomplete);
      if (e) {
        close(fd);
        return e < 0 ? e : 0;
      }
      line_is_incomplete = 0;
      oldpos = pos;
    } while (oldpos);
  }
  close(fd);
  return 0;
}
