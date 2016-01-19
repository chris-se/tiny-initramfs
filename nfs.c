/*
 * tiny_initramfs - Minimalistic initramfs implementation
 * Copyright (C) 2016 Christian Seiler <christian@iwakd.de>
 *
 * nfs.c: Helper functions for mounting NFSv4 filesystems
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
 *
 * Note:
 *
 * The mount_nfs4 function is based on the nfs4mount function in
 * util-linux, originally by Trond Myklebust <trond.myklebust@fys.uio.no>,
 * licensed under the GLPv2+.
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/mount.h>
#include <poll.h>
#include <time.h>

#include <netinet/in.h>
#include <netinet/ip.h>

#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>

#include "tiny_initramfs.h"
#include "nfs4.h"

#define AUTH_UNIX                    1
#define NFS_PORT                     2049
#define MOUNT_TIMEOUT                30

/* Not defined by all libc implementations. */
#ifndef SOCK_CLOEXEC
#define SOCK_CLOEXEC 02000000
#endif

#define MIN(a,b) \
   ({ __typeof__ (a) _a = (a); \
      __typeof__ (b) _b = (b); \
     _a < _b ? _a : _b; })

static int nfs4_ping(int domain, int type, struct sockaddr *dest, socklen_t dest_len, int timeout, char *ip_addr, size_t ip_addr_len);

/* See comment below why we reimplement this ourselves. */
static int small_inet_aton(const char *cp, struct in_addr *inp);
static char *small_inet_ntoa(struct in_addr in);

int mount_nfs4(const char *source, const char *target,
               int mount_flags, const char *nfs_options)
{
  typedef struct {
    const char *name;
    int *ptr;
  } num_opt_def_t;

  typedef struct {
    const char *name;
    int flag;
  } bool_opt_def_t;

  char p_options[MAX_LINE_LEN], *token, *saveptr, *opt_val, *endptr;
  long val;
  struct sockaddr_in server_addr = { 0 };
  char ip_addr[16] = "127.0.0.1";
  char hostname[MAX_LINE_LEN] = { 0 };
  char mnt_path[MAX_LINE_LEN] = { 0 };
  struct nfs4_mount_data data = { 0 };
  
  int bg = 0,
      retry = -1;

  int auth_pseudoflavor = AUTH_UNIX;
  time_t timeout;
  int r;
  int dummy;
  int had_warning;

  num_opt_def_t num_opt_defs[] = {
    { "rsize",    &data.rsize    },
    { "wsize",    &data.wsize    },
    { "timeo",    &data.timeo    },
    { "retrans",  &data.retrans  },
    { "acregmin", &data.acregmin },
    { "acregmax", &data.acregmax },
    { "acdirmin", &data.acdirmin },
    { "acdirmax", &data.acdirmax },
    { "retry",    &retry         },
    { "vers",     &dummy         },
    { NULL,       NULL           }
  };
#define INVERTED                0x10000
  bool_opt_def_t bool_opt_defs[] = {
    { "bg",          0                              },
    { "fg",                                INVERTED },
    { "soft",        NFS4_MOUNT_SOFT                },
    { "hard",        NFS4_MOUNT_SOFT     | INVERTED },
    { "intr",        NFS4_MOUNT_INTR                },
    { "cto",         NFS4_MOUNT_NOCTO    | INVERTED },
    { "ac",          NFS4_MOUNT_NOAC     | INVERTED },
    { "sharedcache", NFS4_MOUNT_UNSHARED | INVERTED },
    { NULL,          0                              }
  };
  num_opt_def_t *num_opt_def;
  bool_opt_def_t *bool_opt_def;

  set_buf(p_options, MAX_LINE_LEN, nfs_options, NULL);

  data.retrans = 3;
  data.acregmin = 3;
  data.acregmax = 60;
  data.acdirmin = 30;
  data.acdirmax = 60;
  data.proto = IPPROTO_TCP;

  opt_val = strchr((char *)source, ':');
  if (!opt_val)
    panic(0, "nfs mount: directory to mount not in host:dir format: ", source, NULL);
  strncpy(hostname, source, MIN(MAX_LINE_LEN - 1, opt_val - source));
  set_buf(mnt_path, MAX_LINE_LEN, opt_val + 1, NULL);

  server_addr.sin_family = AF_INET;
  server_addr.sin_port = htons(NFS_PORT);
  if (!small_inet_aton(hostname, &server_addr.sin_addr))
    panic(0, "nfs mount: only IP addresses supported for mounting NFS servers, got ", hostname, " instead.", NULL);

  for (token = strtok_r(p_options, ",", &saveptr); token != NULL; token = strtok_r(NULL, ",", &saveptr)) {
    opt_val = strchr(token, '=');
    if (opt_val) {
      *opt_val = '\0';
      opt_val++;
      if (strcmp(token, "proto") == 0) {
        if (strcmp(opt_val, "tcp") == 0)
          data.proto = IPPROTO_TCP;
        else if (strcmp(opt_val, "udp") == 0)
          data.proto = IPPROTO_UDP;
        else
          panic(0, "nfs mount: invalid proto option specified (valid values are: tcp, udp)", NULL);
        continue;
      } else if (strcmp(token, "clientaddr") == 0) {
        /* FIXME */
        panic(0, "nfs mount: clientaddr not supported yet", NULL);
      } else if (strcmp(token, "sec") == 0) {
        if (strcmp(opt_val + 1, "sys") != 0)
          panic(0, "nfs mount: only sec=sys is supported", NULL);
        continue;
      }

      if (!*opt_val)
        panic(0, "nfs mount: invalid empty option ", token, " specified", NULL);

      endptr = NULL;
      val = strtol(opt_val, &endptr, 10);
      if (!endptr || !*endptr)
        panic(0, "nfs mount: option ", token, " requires a number, got ", opt_val, " instead.", NULL);

      if (strcmp(token, "port") == 0) {
        server_addr.sin_port = htons((int)val);
        continue;
      }

      if (strcmp(token, "actimeo") == 0) {
        data.acregmin = data.acregmax = data.acdirmin = data.acdirmax = (int)val;
        continue;
      }

      for (num_opt_def = num_opt_defs; num_opt_def->name; num_opt_def++) {
        if (strcmp(token, num_opt_def->name) == 0) {
          *num_opt_def->ptr = (int)val;
          break;
        }
      }
      if (!num_opt_def->name)
        panic(0, "nfs mount: invalid option ", token, "=", opt_val, NULL);
    } else {
      val = 1;
      if (strncmp(token, "no", 2) == 0) {
        opt_val = token + 2;
        val = 0;
      } else {
        opt_val = token;
      }
      if (strcmp(opt_val, "bg") == 0) {
        bg = 1;
      } else if (strcmp(opt_val, "fg") == 0) {
        bg = 0;
      } else {
        for (bool_opt_def = bool_opt_defs; bool_opt_def->name; bool_opt_def++) {
          if (strcmp(opt_val, bool_opt_def->name) == 0) {
            /* != is logical XOR in C */
            val = val != !!(bool_opt_def->flag & INVERTED);
            if (val)
              data.flags |= (bool_opt_def->flag & NFS4_MOUNT_FLAGMASK);
            else
              data.flags &= ~(bool_opt_def->flag & NFS4_MOUNT_FLAGMASK);
            break;
          }
        }
        if (!bool_opt_def->name)
          panic(0, "nfs mount: invalid option ", token, NULL);
      }
    }
  }

  if (bg) {
    warn("nfs mount: background mounts unsupported for / and /usr, defaulting to foreground", NULL);
    bg = 0;
  }

  if (retry == -1)
    retry = 2;

  data.auth_flavourlen = 1;
  data.auth_flavours = &auth_pseudoflavor;

  data.mnt_path.data = mnt_path;
  data.mnt_path.len = strlen(mnt_path);

  data.hostname.data = hostname;
  data.hostname.len = strlen(hostname);

  data.host_addr = (struct sockaddr *)&server_addr;
  data.host_addrlen = sizeof(server_addr);

  timeout = time(NULL) + 60 * retry;
  data.version = NFS4_MOUNT_VERSION;

  had_warning = 0;

  for (;;) {
    r = nfs4_ping(AF_INET, data.proto == IPPROTO_UDP ? SOCK_DGRAM : SOCK_STREAM, (struct sockaddr *)&server_addr, sizeof(server_addr), MOUNT_TIMEOUT, ip_addr, sizeof(ip_addr));
    if (r == 0)
      break;

    if (time(NULL) >= timeout) {
      if (r < 0 && r != -ETIMEDOUT)
        panic(r, "nfs mount: failed to mount ", source, NULL);
      else
        panic(0, "nfs mount: timeout while trying to mount ", source, NULL);
    }

    if (!had_warning) {
      had_warning = 1;
      if (r >= 0)
        r = -ETIMEDOUT;
      warn("nfs mount: waiting for response from NFS server ", hostname, ": ", strerror(-r), NULL);
    }

    /* Wait a bit before retrying, otherwise we will flood the network... */
    if (r < 0 && r != -ETIMEDOUT)
      sleep(1);
  }

  data.client_addr.data = ip_addr;
  data.client_addr.len = strlen(ip_addr);

  r = mount(source, target, "nfs4", mount_flags, &data);
  if (r < 0)
    return -errno;
  return r;
}

int nfs4_ping(int domain, int type, struct sockaddr *dest, socklen_t dest_len, int timeout, char *ip_addr, size_t ip_addr_len)
{
  /* So we don't really want to implement the whole RPC protocol
   * for NFSv4 (would be too much code), and since we need to do
   * a NULLPROC only anyway, where we know how the request and
   * response have to look like on a byte level, we just store
   * the packets here. If the response match, everything
   * succeeded.
   *
   * Also, we are going to blatantly assume that the NULLPROC
   * requests/responses are always going to fit into a single
   * RPC fragment. Otherwise, our code would get quite a bit
   * more complicated. */
  char nullproc_request[] = {
    0x80, 0x00, 0x00, 0x28, /* last fragment, fragment length: 40 */
    0x00, 0x00, 0x00, 0x00, /* xid, will be overwritten */
    0x00, 0x00, 0x00, 0x00, /* message type: call */
    0x00, 0x00, 0x00, 0x02, /* RPC Version: 2 */
    0x00, 0x01, 0x86, 0xa3, /* NFS */
    0x00, 0x00, 0x00, 0x04, /* Version 4 */
    0x00, 0x00, 0x00, 0x00, /* NULLPROC */
    0x00, 0x00, 0x00, 0x00, /* NULL credentials */
    0x00, 0x00, 0x00, 0x00, /* (length 0) */
    0x00, 0x00, 0x00, 0x00, /* NULL verifier */
    0x00, 0x00, 0x00, 0x00  /* (length 0) */
  };
  char nullproc_expected_response[] = {
    0x80, 0x00, 0x00, 0x18, /* last fragment, fragment length: 24 */
    0x00, 0x00, 0x00, 0x00, /* xid, will be overwritten */
    0x00, 0x00, 0x00, 0x01, /* message type: reply */
    0x00, 0x00, 0x00, 0x00, /* reply state: accepted */
    0x00, 0x00, 0x00, 0x00, /* NULL verifier */
    0x00, 0x00, 0x00, 0x00, /* (length 0) */
    0x00, 0x00, 0x00, 0x00  /* accept state: RPC executed successfully */
  };
  char nullproc_response[sizeof(nullproc_expected_response)];

  int sock_fd, r;
  ssize_t bytes;
  enum {
    WAIT_FOR_CONNECT,
    WAIT_FOR_SEND,
    WAIT_FOR_RECEIVE,
    DONE
  } state = WAIT_FOR_CONNECT;
  struct pollfd poll_fd;
  int timeout_msec = timeout * 1000;
  int pos = 0;
  size_t msg_start;
  socklen_t len;

  union {
    char buf[256];
    struct sockaddr_in in;
  } client_addr;
  socklen_t client_addr_len = sizeof(client_addr);

  /* get some random data for xid
   * (we don't care about the entropy pool state,
   * as we don't pretend that sec=sys NFSv4 is at
   * all cryptographically safe) */
  {
    int urandom_fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (urandom_fd < 0)
      return -errno;
    r = read(urandom_fd, nullproc_request + 4, 4);
    if (r != 4) {
      r = -errno;
      close(urandom_fd);
      return r;
    }
    close(urandom_fd);
    /* copy xid so we are sure that we get something matching
     * back */
    memcpy(nullproc_expected_response + 4, nullproc_request + 4, 4);
  }

  sock_fd = socket(domain, type | SOCK_CLOEXEC, 0);
  if (sock_fd < 0)
    return -errno;

  r = fcntl(sock_fd, F_GETFL);
  if (r < 0)
    goto error_out;

  r = fcntl(sock_fd, F_SETFL, r | O_NONBLOCK);
  if (r < 0)
    goto error_out;

  if (type == SOCK_DGRAM) {
    state = WAIT_FOR_SEND;
    msg_start = 4;
  } else {
    msg_start = 0;
    r = connect(sock_fd, dest, dest_len);
    if (r < 0 && errno != EINPROGRESS && errno != EWOULDBLOCK)
      goto error_out;
  }

  while (state != DONE) {
    poll_fd.fd = sock_fd;
    poll_fd.events = (state == WAIT_FOR_RECEIVE ? POLLIN : POLLOUT);
    poll_fd.revents = 0;
    r = poll(&poll_fd, 1, timeout_msec);
    if (r == 0) {
      errno = ETIMEDOUT;
      goto error_out;
    }

    switch (state) {
      case WAIT_FOR_CONNECT:
        len = sizeof(errno);
        r = getsockopt(sock_fd, SOL_SOCKET, SO_ERROR, &errno, &len);
        if (r < 0 || errno != 0)
          goto error_out;
        state = WAIT_FOR_SEND;
        break;
      case WAIT_FOR_SEND:
          /* UDP doesn't have fragment length */
        if (type == SOCK_DGRAM)
          bytes = sendto(sock_fd, nullproc_request + 4, sizeof(nullproc_request) - 4, 0, dest, dest_len);
        else
          bytes = send(sock_fd, nullproc_request, sizeof(nullproc_request), 0);
        if (bytes != (int)sizeof(nullproc_request) - (type == SOCK_DGRAM) * 4) {
          if (bytes >= 0)
            errno = EMSGSIZE;
          goto error_out;
        }
        state = WAIT_FOR_RECEIVE;
        pos = 0;
        break;
      case WAIT_FOR_RECEIVE:
        if (type == SOCK_DGRAM) {
          /* UDP doesn't have fragment length */
          bytes = recvfrom(sock_fd, nullproc_response + 4, sizeof(nullproc_response) - 4, 0, dest, &dest_len);
          if (bytes != (int)sizeof(nullproc_response) - 4) {
            if (bytes >= 0)
              errno = -1; /* unexpected response */
            goto error_out;
          }
          state = DONE;
        } else {
          bytes = recv(sock_fd, &nullproc_response[pos], sizeof(nullproc_response) - pos, 0);
          if (bytes <= 0) {
            if (bytes == 0)
              errno = -1; /* unexpected response */
            goto error_out;
          }
          if (bytes < (int)sizeof(nullproc_response) - pos) {
            pos += bytes;
            continue;
          }
          state = DONE;
        }
      case DONE:
        break;
    }
  }

  /* We had a successful response from the server
   * at this point */

  r = getsockname(sock_fd, (struct sockaddr *)&client_addr, &client_addr_len);
  if (r < 0)
    r = -errno;

  close(sock_fd);

  if (r < 0)
    return r;

  /* Compare the response to the expected response */
  r = memcmp(&nullproc_expected_response[msg_start], &nullproc_response[msg_start], sizeof(nullproc_response) - msg_start);
  if (r == 0 && ip_addr) {
    /* Write string representation of client address to ip_addr */
    *ip_addr = '\0';
    if (domain == AF_INET)
      set_buf(ip_addr, ip_addr_len, small_inet_ntoa(client_addr.in.sin_addr), NULL);
  }
  return r;

error_out:
  r = -errno;
  close(sock_fd);
  return r;
}

/* We reimplement these functions ourselves, because including
 * arpa/inet.h + using the functions in the C library can increase the
 * size of the (compressed) initrd.img quite a bit with certain C
 * libraries. For example. when compiled against musl this adds around
 * 5 kiB to the code - just for converting IP addresses to their string
 * representation and back... :-( Doing this ourselves reduces the size
 * by quite a bit. (Note that we don't need this function often, so
 * efficiency is not a concern for the implementation.
 */

static const char ip_part_terminator_chars[4] = { '.', '.', '.', '\0' };

int small_inet_aton(const char *cp, struct in_addr *inp)
{
  char *ptr, *endptr;
  int i;
  unsigned long value;
  union {
    char bytes[4];
    struct in_addr addr;
  } result;

  for (i = 0, ptr = (char *)cp; i < 4; i++, ptr = endptr + 1) {
    endptr = NULL;
    value = strtoul(ptr, &endptr, 10);
    if (value >= 256 || !endptr || endptr == ptr || *endptr != ip_part_terminator_chars[i])
      return 0;
    result.bytes[i] = (char)value;
  }

  *inp = result.addr;
  return 1;
}

char *small_inet_ntoa(struct in_addr in)
{
  static char buf[16];
  int i;
  char *ptr;
  union {
    char bytes[4];
    struct in_addr addr;
  } input;

  input.addr = in;

  ptr = buf;
  for (i = 0; i < 4; i++) {
    unsigned int v = (unsigned char)input.bytes[i];
    *ptr = v / 100 + '0';
    v %= 100;
    ptr += (*ptr != '0');
    *ptr = v / 10 + '0';
    v %= 10;
    ptr += (*ptr != '0');
    *ptr = v + '0';
    ptr++;
    *ptr = ip_part_terminator_chars[i];
    ptr++;
  }

  return buf;
}
