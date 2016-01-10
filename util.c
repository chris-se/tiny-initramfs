/*
 * tiny_initramfs - Minimalistic initramfs implementation
 * Copyright (C) 2016 Christian Seiler <christian@iwakd.de>
 *
 * util.c: Misc helper functions
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

#include <stdarg.h>
#include <string.h>

static void append_to_buf_v(char *buf, size_t size, va_list ap)
{
  const char *ptr;
  size_t remaining_size;
  if (strlen(buf) > size)
    return;

  remaining_size = size - strlen(buf);

  for (ptr = va_arg(ap, const char *); ptr; ptr = va_arg(ap, const char *)) {
    strncat(buf, ptr, remaining_size - 1);

    /* Make sure it's NUL-terminated. */
    if (strlen(ptr) >= remaining_size - 1) {
      buf[size - 1] = '\0';
      break;
    }

    remaining_size -= strlen(ptr);
  }
}

void append_to_buf(char *buf, size_t size, ...)
{
  va_list ap;

  va_start(ap, size);
  append_to_buf_v(buf, size, ap);
  va_end(ap);
}

void set_buf(char *buf, size_t size, ...)
{
  va_list ap;

  va_start(ap, size);
  memset(buf, 0, size);
  append_to_buf_v(buf, size, ap);
  va_end(ap);
}
