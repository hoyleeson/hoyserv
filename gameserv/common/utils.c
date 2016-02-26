#include <stdarg.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>

#include <sys/stat.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <common/log.h>
#include <net/if.h>
#include <sys/ioctl.h>

#define DEFAULT_NET_DEV     "eth0"

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

int get_ipaddr(const char* eth, char* ipaddr)
{
    int i = 0;
    int sockfd;
    struct ifconf ifconf;
    char buf[512];
    struct ifreq *ifreq;
    char *dev = (char *)eth;

    if(!dev) {
        dev = DEFAULT_NET_DEV;
    }

    ifconf.ifc_len = 512;
    ifconf.ifc_buf = buf;

    if((sockfd = socket(AF_INET, SOCK_DGRAM, 0))<0) {
        perror("socket");
        exit(1);
    }

    ioctl(sockfd, SIOCGIFCONF, &ifconf);
    ifreq = (struct ifreq*)buf;

    for(i=(ifconf.ifc_len/sizeof(struct ifreq)); i>0; i--) {
        if(strcmp(ifreq->ifr_name, dev)==0) {
            strcpy(ipaddr, inet_ntoa(((struct sockaddr_in*)&(ifreq->ifr_addr))->sin_addr));
            return 0;
        }

        ifreq++;
    }
    return -EINVAL;
}

