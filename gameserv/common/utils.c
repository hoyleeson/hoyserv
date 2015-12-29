#include <stdarg.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <common/log.h>

/** UTILITIES
 **/

void* xalloc(size_t sz)
{
    void*  p;

    if (sz == 0)
        return NULL;

    p = malloc(sz);
    if (p == NULL)
        fatal("not enough memory");

    return p;
}

void* xzalloc(size_t  sz)
{
    void*  p = xalloc(sz);
    memset(p, 0, sz);
    return p;
}

void* xrealloc(void*  block, size_t  size)
{
    void*  p = realloc(block, size);

    if (p == NULL && size > 0)
        fatal("not enough memory");

    return p;
}


int fd_read(int  fd, void*  to, int  len)
{
    int  ret;

    do {
        ret = read(fd, to, len);
    } while (ret < 0 && errno == EINTR);

    return ret;
}

int fd_write(int  fd, const void*  from, int  len)
{
    int  ret;

    do {
        ret = write(fd, from, len);
    } while (ret < 0 && errno == EINTR);

    return ret;
}

void fd_setnonblock(int  fd)
{
    int  ret, flags;

    do {
        flags = fcntl(fd, F_GETFD);
    } while (flags < 0 && errno == EINTR);

    if (flags < 0) {
        fatal("%s: could not get flags for fd %d: %s",
               __FUNCTION__, fd, strerror(errno));
    }

    do {
        ret = fcntl(fd, F_SETFD, flags | O_NONBLOCK);
    } while (ret < 0 && errno == EINTR);

    if (ret < 0) {
        fatal("%s: could not set fd %d to non-blocking: %s",
               __FUNCTION__, fd, strerror(errno));
    }
}


int fd_accept(int  fd)
{
    struct sockaddr  from;
    socklen_t        fromlen = sizeof(from);
    int              ret;

    do {
        ret = accept(fd, &from, &fromlen);
    } while (ret < 0 && errno == EINTR);

    return ret;
}


