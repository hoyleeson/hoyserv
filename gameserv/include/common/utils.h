#ifndef _COMMON_UTILS_H_
#define _COMMON_UTILS_H_

#include <stdint.h>

void* xalloc(size_t   sz);
void* xzalloc(size_t  sz);
void* xrealloc(void*  block, size_t  size);

int fd_read(int  fd, void*  to, int  len);
int fd_write(int  fd, const void*  from, int  len);
void fd_setnonblock(int  fd);
int fd_accept(int  fd);


#define  xnew(p)   do { (p) = xalloc(sizeof(*(p))); } while(0)
#define  xznew(p)   do { (p) = xzalloc(sizeof(*(p))); } while(0)
#define  xfree(p)    do { (free((p)), (p) = NULL); } while(0)
#define  xrenew(p,count)  do { (p) = xrealloc((p),sizeof(*(p))*(count)); } while(0)

#endif

