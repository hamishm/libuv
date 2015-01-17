/* Copyright Joyent, Inc. and other Node contributors. All rights reserved.
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#include "uv.h"
#include "internal.h"

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>

#include <net/if.h>
#include <net/if_dl.h>

#include <dlfcn.h>
#include <fcntl.h>
#include <sys/poll.h>
#include <sys/time.h>
#include <unistd.h>

#include <kernel/OS.h>



int uv__platform_loop_init(uv_loop_t* loop, int default_loop) {
  loop->backend_fd = -1;
  return 0;
}


void uv__platform_loop_delete(uv_loop_t* loop) {
}


void uv__platform_invalidate_fd(uv_loop_t* loop, int fd) {
  struct pollfd* fds;
  uintptr_t i;
  uintptr_t nfds;

  assert(loop->watchers != NULL);

  fds = (struct pollfd*) loop->watchers[loop->nwatchers];
  nfds = (uintptr_t) loop->watchers[loop->nwatchers + 1];
  if (fds == NULL)
    return;

  /* Invalidate events with same file descriptor */
  for (i = 0; i < nfds; i++)
    if (fds[i].fd == fd)
      fds[i].fd = -1;
}


void uv__io_poll(uv_loop_t* loop, int timeout) {
  struct pollfd* fds;
  struct pollfd* pollfd;
  QUEUE* q;
  uv__io_t* w;
  uint64_t base;
  uint64_t diff;
  int nfds;
  unsigned int i;
  unsigned int curfd;
  unsigned int numfds;
  int nevents;
  int fd;

  if (loop->nfds == 0) {
    assert(QUEUE_EMPTY(&loop->watcher_queue));
    return;
  }

  while (!QUEUE_EMPTY(&loop->watcher_queue)) {
    q = QUEUE_HEAD(&loop->watcher_queue);
    QUEUE_REMOVE(q);
    QUEUE_INIT(q);

    w = QUEUE_DATA(q, uv__io_t, watcher_queue);
    assert(w->pevents != 0);
    assert(w->fd >= 0);
    assert(w->fd < (int) loop->nwatchers);
    w->events = w->pevents;
  }

  assert(timeout >= -1);
  base = loop->time;

  numfds = loop->nfds;
  fds = (struct pollfd*)malloc(numfds * sizeof(struct pollfd));

  for (i = 0, curfd = 0; i < loop->nwatchers; i++) {
    w = loop->watchers[i];

    if (w != NULL) {
      assert(curfd < numfds);
      fds[curfd].fd = w->fd;
      fds[curfd].events = w->pevents;
      fds[curfd].revents = 0;
      curfd++;
  	}
  }

  for (;;) {
    nfds = poll(fds, numfds, timeout);
    /* Update loop->time unconditionally. It's tempting to skip the update when
     * timeout == 0 (i.e. non-blocking poll) but there is no guarantee that the
     * operating system didn't reschedule our process while in the syscall.
     */
    SAVE_ERRNO(uv__update_time(loop));

    if (nfds == 0) {
      assert(timeout != -1);
      return;
    }

    if (nfds == -1) {
      if (errno != EINTR)
        abort();

      if (timeout == 0)
        return;

      if (timeout == -1)
        continue;

      goto update_timeout;
    }

    nevents = 0;

    assert(loop->watchers != NULL);
    loop->watchers[loop->nwatchers] = (void*) fds;
    loop->watchers[loop->nwatchers + 1] = (void*) (uintptr_t) numfds;

    for (i = 0; i < (unsigned) numfds; i++) {
      pollfd = fds + i;
      fd = pollfd->fd;

      /* Skip invalidated events, see uv__platform_invalidate_fd */
      if (fd == -1)
        continue;

      if (pollfd->revents == 0)
        continue;

      if (pollfd->revents == UV__POLLERR || pollfd->revents == UV__POLLHUP)
        pollfd->revents |= w->pevents & (UV__POLLIN | UV__POLLOUT);

      assert(fd >= 0);
      assert((unsigned) fd < loop->nwatchers);

      w = loop->watchers[fd];

      /* File descriptor that we've stopped watching, ignore. */
      if (w == NULL)
        continue;

      w->cb(loop, w, pollfd->revents);
      nevents++;
    }

    loop->watchers[loop->nwatchers] = NULL;
    loop->watchers[loop->nwatchers + 1] = NULL;

    if (nevents != 0)
      return;

    if (timeout == 0)
      return;

    if (timeout == -1)
      continue;

update_timeout:
    assert(timeout > 0);

    diff = loop->time - base;
    if (diff >= (uint64_t) timeout)
      return;

    timeout -= diff;
  }
}


uint64_t uv__hrtime(uv_clocktype_t type) {
  struct timespec t;
  clock_t clock_id;

  clock_id = CLOCK_MONOTONIC;
  if (clock_gettime(clock_id, &t))
    abort();

  return t.tv_sec * (uint64_t) 1e9 + t.tv_nsec;
}


/*
 * We could use a static buffer for the path manipulations that we need outside
 * of the function, but this function could be called by multiple consumers and
 * we don't want to potentially create a race condition in the use of snprintf.
 */
int uv_exepath(char* buffer, size_t* size) {
  Dl_info info;
  int res;

  if (buffer == NULL || size == NULL)
    return -EINVAL;

  res = dladdr((void*)uv_exepath, &info);
  if (res == 0)
    return -errno;

  assert(info.dli_fname != NULL);

  strncpy(buffer, info.dli_fname, *size - 1);
  buffer[*size - 1] = '\0';
  *size = strlen(buffer);

  return 0;
}


uint64_t uv_get_free_memory(void) {
  return (uint64_t) sysconf(_SC_PAGESIZE) * sysconf(_SC_AVPHYS_PAGES);
}


uint64_t uv_get_total_memory(void) {
  return (uint64_t) sysconf(_SC_PAGESIZE) * sysconf(_SC_PHYS_PAGES);
}


void uv_loadavg(double avg[3]) {
  avg[0] = 0.0;
  avg[1] = 0.0;
  avg[2] = 0.0;
}


int uv_fs_event_init(uv_loop_t* loop, uv_fs_event_t* handle) {
  return -ENOSYS;
}


int uv_fs_event_start(uv_fs_event_t* handle,
                      uv_fs_event_cb cb,
                      const char* filename,
                      unsigned int flags) {
  return -ENOSYS;
}


int uv_fs_event_stop(uv_fs_event_t* handle) {
  return -ENOSYS;
}


void uv__fs_event_close(uv_fs_event_t* handle) {
  UNREACHABLE();
}


char** uv_setup_args(int argc, char** argv) {
  return argv;
}


int uv_set_process_title(const char* title) {
  return 0;
}


int uv_get_process_title(char* buffer, size_t size) {
  if (size > 0) {
    buffer[0] = '\0';
  }
  return 0;
}


int uv_resident_set_memory(size_t* rss) {
  return -ENOSYS;
}


int uv_uptime(double* uptime) {
  system_info info;
  bigtime_t now;
  status_t res;

  res = get_system_info(&info);
  if (res != B_OK)
    return res;

  now = real_time_clock_usecs();
  *uptime = now - info.boot_time;
  return 0;
}


int uv_cpu_info(uv_cpu_info_t** cpu_infos, int* count) {
  return -ENOSYS;
/*
  system_info sys_info;
  status_t res;
  cpu_info* cpu_info;

  res = get_system_info(&sys_info);
  if (res != B_OK)
    return res;

  cpu_info = (cpu_info*) malloc(sizeof(cpu_info) * sys_info.cpu_count);
  if (!cpu_info)
    return -errno;

  res = get_cpu_info(0, sys_info.cpu_count, &cpu_info);
  if (res != B_OK) {
    free(cpu_info);
    return res;
  }

  *cpu_infos = malloc(sys_info.cpu_count * sizeof(uv_cpu_info_t));
  if (!(*cpu_infos)) {
  	free(cpu_info);
    return -errno;
  }

  // You get the idea.
*/
}


void uv_free_cpu_info(uv_cpu_info_t* cpu_infos, int count) {
  int i;

  for (i = 0; i < count; i++) {
    free(cpu_infos[i].model);
  }

  free(cpu_infos);
}


int uv_interface_addresses(uv_interface_address_t** addresses, int* count) {
  return -ENOSYS;
}


void uv_free_interface_addresses(uv_interface_address_t* addresses,
  int count) {
  int i;

  for (i = 0; i < count; i++) {
    free(addresses[i].name);
  }

  free(addresses);
}
