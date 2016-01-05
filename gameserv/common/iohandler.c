#include <stdint.h>
#include <stdarg.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>

#include <common/iohandler.h>
#include <common/log.h>
#include <common/utils.h>


struct iohandler {
	looper_t         looper;
    fdhandler_list_t  fdhandlers;
};

static struct iohandler _iohandler; 


/* initialize a looper object */
void looper_init(looper_t*  l)
{
    l->epoll_fd = epoll_create(1);
    l->num_fds  = 0;
    l->max_fds  = 0;
    l->events   = NULL;
    l->hooks    = NULL;
}

/* finalize a looper object */
void looper_done(looper_t*  l)
{
    xfree(l->events);
    xfree(l->hooks);
    l->max_fds = 0;
    l->num_fds = 0;

    close(l->epoll_fd);
    l->epoll_fd  = -1;
}

/* return the loop_hook_t corresponding to a given
 * monitored file descriptor, or NULL if not found
 */
loop_hook_t* looper_find(looper_t*  l, int  fd)
{
    loop_hook_t*  hook = l->hooks;
    loop_hook_t*  end  = hook + l->num_fds;

    for (; hook < end; hook++) {
        if (hook->fd == fd)
            return hook;
    }
    return NULL;
}

/* grow the arrays in the looper object */
void looper_grow(looper_t*  l)
{
    int  old_max = l->max_fds;
    int  new_max = old_max + (old_max >> 1) + 4;
    int  n;

    xrenew(l->events, new_max);
    xrenew(l->hooks,  new_max);
    l->max_fds = new_max;

    /* now change the handles to all events */
    for (n = 0; n < l->num_fds; n++) {
        struct epoll_event ev;
        loop_hook_t*          hook = l->hooks + n;

        ev.events   = hook->wanted;
        ev.data.ptr = hook;
        epoll_ctl(l->epoll_fd, EPOLL_CTL_MOD, hook->fd, &ev);
    }
}

/* register a file descriptor and its event handler.
 * no event mask will be enabled
 */
void looper_add(looper_t*  l, int  fd, event_fn  func, void*  user)
{
    struct epoll_event  ev;
    loop_hook_t*           hook;

    if (l->num_fds >= l->max_fds)
        looper_grow(l);

    hook = l->hooks + l->num_fds;

    hook->fd      = fd;
    hook->ev_user = user;
    hook->ev_func = func;
    hook->state   = 0;
    hook->wanted  = 0;
    hook->events  = 0;

    fd_setnonblock(fd);

    ev.events   = 0;
    ev.data.ptr = hook;
    epoll_ctl(l->epoll_fd, EPOLL_CTL_ADD, fd, &ev);

    l->num_fds += 1;
}

/* unregister a file descriptor and its event handler
 */
void looper_del(looper_t*  l, int  fd)
{
    loop_hook_t*  hook = looper_find(l, fd);

    if (!hook) {
        loge("%s: invalid fd: %d", __func__, fd);
        return;
    }
    /* don't remove the hook yet */
    hook->state |= HOOK_CLOSING;

    epoll_ctl(l->epoll_fd, EPOLL_CTL_DEL, fd, NULL);
}

/* enable monitoring of certain events for a file
 * descriptor. This adds 'events' to the current
 * event mask
 */
void looper_enable(looper_t*  l, int  fd, int  events)
{
    loop_hook_t*  hook = looper_find(l, fd);

    if (!hook) {
        loge("%s: invalid fd: %d", __func__, fd);
        return;
    }

    if (events & ~hook->wanted) {
        struct epoll_event  ev;

        hook->wanted |= events;
        ev.events   = hook->wanted;
        ev.data.ptr = hook;

		printf("----%s:%d---\n", __func__, __LINE__);
        epoll_ctl(l->epoll_fd, EPOLL_CTL_MOD, fd, &ev);
    }
}

/* disable monitoring of certain events for a file
 * descriptor. This ignores events that are not
 * currently enabled.
 */
void looper_disable(looper_t*  l, int  fd, int  events)
{
    loop_hook_t*  hook = looper_find(l, fd);

    if (!hook) {
        loge("%s: invalid fd: %d", __func__, fd);
        return;
    }

    if (events & hook->wanted) {
        struct epoll_event  ev;

        hook->wanted &= ~events;
        ev.events   = hook->wanted;
        ev.data.ptr = hook;

        epoll_ctl(l->epoll_fd, EPOLL_CTL_MOD, fd, &ev);
    }
}

/* wait until an event occurs on one of the registered file
 * descriptors. Only returns in case of error !!
 */
void looper_loop(looper_t*  l)
{
	int ret;
    for (;;) {
		ret = looper_exec(l);
		if(ret)
			break;
    }
}


int looper_exec(looper_t* l) {
	int  n, count;

	do {
		count = epoll_wait(l->epoll_fd, l->events, l->num_fds, -1);
		printf("----%s:%d-%d:%d--\n", __func__, __LINE__, count, errno );
	} while (count < 0 && errno == EINTR);

	if (count < 0) {
		loge("%s: error: %s\n", __func__, strerror(errno));
		return -EINVAL;
	}

	if (count == 0) {
		loge("%s: huh ? epoll returned count=0\n", __func__);
		return 0;
	}

		printf("----%s:%d---\n", __func__, __LINE__);
	/* mark all pending hooks */
	for (n = 0; n < count; n++) {
		loop_hook_t*  hook = l->events[n].data.ptr;
		hook->state  = HOOK_PENDING;
		hook->events = l->events[n].events;
	}

	/* execute hook callbacks. this may change the 'hooks'
	 * and 'events' array, as well as l->num_fds, so be careful */
	for (n = 0; n < l->num_fds; n++) {
		loop_hook_t*  hook = l->hooks + n;
		if (hook->state & HOOK_PENDING) {
			hook->state &= ~HOOK_PENDING;
			hook->ev_func(hook->ev_user, hook->events);
		}
	}

	/* now remove all the hooks that were closed by
	 * the callbacks */
	for (n = 0; n < l->num_fds;) {
		struct epoll_event ev;
		loop_hook_t*  hook = l->hooks + n;

		if (!(hook->state & HOOK_CLOSING)) {
			n++;
			continue;
		}

		hook[0]     = l->hooks[l->num_fds-1];
		l->num_fds -= 1;
		ev.events   = hook->wanted;
		ev.data.ptr = hook;
		epoll_ctl(l->epoll_fd, EPOLL_CTL_MOD, hook->fd, &ev);
	}
	return 0;
}

/* we expect to alloc/free a lot of packets during
 * operations so use a single linked list of free packets
 * to keep things speedy and simple.
 */
static packet_t*   _free_packets;

/* Allocate a packet */
static packet_t* packet_alloc(void)
{
    packet_t*  p = _free_packets;
    if (p != NULL) {
        _free_packets = p->next;
    } else {
        xnew(p);
    }
    p->next    = NULL;
    p->len     = 0;
    p->channel = 0;
	p->refcount = 1;
    return p;
}

static packet_t* packet_get(packet_t* p)
{
	p->refcount++;
	return p;
}

/* Release a packet. This takes the address of a packet
 * pointer that will be set to NULL on exit (avoids
 * referencing dangling pointers in case of bugs)
 */
static void packet_free(packet_t*  *ppacket)
{
    packet_t*  p = *ppacket;
    if (p) {
        p->next       = _free_packets;
        _free_packets = p;
        *ppacket = NULL;
    }
}


/* handle a packet to a receiver. Note that this transfers
 * ownership of the packet to the receiver.
 */
static __inline__ void receiver_post(receiver_t*  r, packet_t*  p)
{
    if (r->post)
        r->post(r, p);
	else
		packet_free(&p);
}

/* tell a receiver the packet source was closed.
 * this will also prevent further handleing to the
 * receiver.
 */
static __inline__ void receiver_close(receiver_t*  r)
{
    if (r->close) {
        r->close(r->user);
        r->close = NULL;
    }
    r->post = NULL;
    r->handle = NULL;
}

/* remove a fdhandler_t from its current list */
void fdhandler_remove(fdhandler_t*  f)
{
    f->pref[0] = f->next;
    if (f->next)
        f->next->pref = f->pref;
}

/* add a fdhandler_t to a given list */
void fdhandler_prepend(fdhandler_t*  f, fdhandler_t**  list)
{
    f->next = list[0];
    f->pref = list;
    list[0] = f;
    if (f->next)
        f->next->pref = &f->next;
}

/* initialize a fdhandler_t list */
void fdhandler_list_init(fdhandler_list_t*  list, looper_t*  looper)
{
    list->looper  = looper;
    list->active  = NULL;
    list->closing = NULL;
}


/* close a fdhandler_t (and free it). Note that this will not
 * perform a graceful shutdown, i.e. all packets in the
 * outgoing queue will be immediately free.
 *
 * this *will* notify the receiver that the file descriptor
 * was closed.
 *
 * you should call fdhandler_shutdown() if you want to
 * notify the fdhandler_t that its packet source is closed.
 */
void fdhandler_close(fdhandler_t*  f)
{
	logd("%s: closing fd %d", __func__, f->fd);

    /* notify receiver */
    receiver_close(f->receiver);

    /* remove the handler from its list */
    fdhandler_remove(f);

    /* get rid of outgoing packet queue */
    if (f->out_first != NULL) {
        packet_t*  p;
        while ((p = f->out_first) != NULL) {
            f->out_first = p->next;
            packet_free(&p);
        }
    }

    /* get rid of file descriptor */
    if (f->fd >= 0) {
        looper_del(f->list->looper, f->fd);
        close(f->fd);
        f->fd = -1;
    }

    f->list = NULL;
    xfree(f);
}

/* Ask the fdhandler_t to cleanly shutdown the connection,
 * i.e. send any pending outgoing packets then auto-free
 * itself.
 */
void fdhandler_shutdown(fdhandler_t*  f)
{
	logd("%s: shoutdown", __func__);
    /* prevent later fdhandler_close() to
     * call the receiver's close.
     */
    f->receiver->close = NULL;

    if (f->out_first != NULL && !f->closing)
    {
        /* move the handler to the 'closing' list */
        f->closing = 1;
        fdhandler_remove(f);
        fdhandler_prepend(f, &f->list->closing);
        return;
    }

    fdhandler_close(f);
}

/* Enqueue a new packet that the fdhandler_t will
 * send through its file descriptor.
 */
static void fdhandler_enqueue(fdhandler_t*  f, packet_t*  p)
{
    packet_t*  first = f->out_first;

    p->next         = NULL;
    f->out_ptail[0] = p;
    f->out_ptail    = &p->next;

    if (first == NULL) {
        f->out_pos = 0;
        looper_enable(f->list->looper, f->fd, EPOLLOUT);
		printf("----%s:%d---\n", __func__, __LINE__);
    }
}

void fdhandler_send(fdhandler_t *f, const uint8_t *data, int len) 
{
    packet_t*   p;
   
	p = packet_alloc();
	memcpy(p->data, data, len);
	p->len = len;
    
    fdhandler_enqueue(f, p);
}

void fdhandler_sendto(fdhandler_t *f, const uint8_t *data, int len, void *to) 
{
    packet_t*   p;
	struct sockaddr *addr = (struct sockaddr *)to;
   
	p = packet_alloc();
	memcpy(p->data, data, len);
	p->len = len;
	p->addr = *addr;
    
    fdhandler_enqueue(f, p);
}

packet_t *fdhandler_pkt_alloc(fdhandler_t *f)
{
	return packet_alloc();
}

packet_t *fdhandler_pkt_get(fdhandler_t *f, packet_t *p)
{
	return packet_get(p);
}

void fdhandler_pkt_free(fdhandler_t *f, packet_t *p)
{
	packet_free(&p);
}

void fdhandler_pkt_submit(fdhandler_t *f, packet_t *p)
{
    fdhandler_enqueue(f, p);
}

static int fdhandler_read(fdhandler_t*  f)
{
	packet_t*  p = packet_alloc();

	switch(f->type) {
		case HANDLER_TYPE_UDP:
		{
			struct sockaddr src_addr;
		   	socklen_t addrlen = sizeof(struct sockaddr_in);
			bzero(&src_addr, sizeof(src_addr));
			p->len = recvfrom(f->fd, p->data, MAX_PAYLOAD, 0, &src_addr, &addrlen);
			p->addr = src_addr;
			break;
		}
		case HANDLER_TYPE_TCP_ACCEPT:
			p->len = 1;
			p->channel = fd_accept(f->fd);
			break;
		case HANDLER_TYPE_NORMAL:
			p->len = fd_read(f->fd, p->data, MAX_PAYLOAD);
			break;
		default:
			p->len = -1;
			break;
	}

	if(p->len < 0)
		goto fail;
	
	receiver_post(f->receiver, p);
	return 0;
fail:
	packet_free(&p);
	return -EINVAL;
}


static int fdhandler_write(fdhandler_t*  f) 
{
	int      avail, len;
	packet_t*  p = f->out_first;
	avail = p->len - f->out_pos;

		printf("----%s:%d---\n", __func__, __LINE__);
	switch(f->type) {
		case HANDLER_TYPE_UDP:
			len = sendto(f->fd, p->data + f->out_pos, avail, 0, 
					&p->addr, sizeof(struct sockaddr));
			break;
		case HANDLER_TYPE_TCP_ACCEPT:
			goto out;
		case HANDLER_TYPE_NORMAL:
			len = fd_write(f->fd, p->data + f->out_pos, avail);
			break;

	}
	if(len < 0) {
		f->out_pos   = 0;
		f->out_first = p->next;
		packet_free(&p);
		if (f->out_first == NULL) {
			f->out_ptail = &f->out_first;
			looper_disable(f->list->looper, f->fd, EPOLLOUT);
		}
		loge("send data fail, ret=%d, droped.\n", len);
		return -EINVAL;
	}

	f->out_pos += len;
	if (f->out_pos >= p->len) {
		f->out_pos   = 0;
		f->out_first = p->next;
		packet_free(&p);
		if (f->out_first == NULL) {
			f->out_ptail = &f->out_first;
			looper_disable(f->list->looper, f->fd, EPOLLOUT);
		}
	}

out:
	return 0;
}

/* fdhandler_t file descriptor event callback for read/write ops */
static void fdhandler_event(fdhandler_t*  f, int  events)
{
		printf("----%s:%d---\n", __func__, __LINE__);
    /* in certain cases, it's possible to have both EPOLLIN and
     * EPOLLHUP at the same time. This indicates that there is incoming
     * data to read, but that the connection was nonetheless closed
     * by the sender. Be sure to read the data before closing
     * the receiver to avoid packet loss.
     */
    if (events & EPOLLIN) {
		fdhandler_read(f);
    }

    if (events & (EPOLLHUP|EPOLLERR)) {
        /* disconnection */
        loge("%s: disconnect on fd %d", __func__, f->fd);
        fdhandler_close(f);
        return;
    }

    if (events & EPOLLOUT && f->out_first) {
		fdhandler_write(f);
    }
}

/* Create a new fdhandler_t that monitors read/writes */
static fdhandler_t* fdhandler_new(int fd, fdhandler_list_t* list, 
		int type, receiver_t* receiver)
{
    fdhandler_t*  f = xzalloc(sizeof(*f));

    f->fd          = fd;
    f->list        = list;
    f->receiver[0] = receiver[0];
    f->out_first   = NULL;
    f->out_ptail   = &f->out_first;
    f->out_pos     = 0;
	f->type = type;

    fdhandler_prepend(f, &list->active);

    looper_add(list->looper, fd, (event_fn) fdhandler_event, f);
    looper_enable(list->looper, fd, EPOLLIN);
    return f;
}


static void normal_post_func(receiver_t *r, packet_t *p)
{
	if(r->handle)
		r->handle(r->user, p->data, p->len);

	packet_free(&p);
}

fdhandler_t* fdhandler_create(int fd, handle_func hand_fn, close_func close_fn, void *data)
{
	struct iohandler *ioh = &_iohandler;
    receiver_t  recv;

    recv.user  = data;
    recv.handle = hand_fn;
	recv.post = (post_func)normal_post_func;
    recv.close = close_fn;

	return fdhandler_new(fd, &ioh->fdhandlers, HANDLER_TYPE_NORMAL, &recv);
}

static void udp_post_func(receiver_t *r, packet_t *p)
{
	if(r->handlefrom)
		r->handlefrom(r->user, p->data, p->len, &p->addr);

	packet_free(&p);
}


fdhandler_t* fdhandler_udp_create(int fd, handlefrom_func handfrom_fn, 
		close_func close_fn, void *data)
{
	struct iohandler *ioh = &_iohandler;
    receiver_t  recv;

    recv.user  = data;
    recv.handlefrom = handfrom_fn;
	recv.post = (post_func)udp_post_func;
    recv.close = close_fn;

	return fdhandler_new(fd, &ioh->fdhandlers, HANDLER_TYPE_UDP, &recv);
}


static void accept_post_func(receiver_t *r, packet_t *p)
{
	if(r->accept)
		r->accept(r->user, (int)p->channel);

	packet_free(&p);
}

fdhandler_t* fdhandler_accept_create(int fd, 
		accept_func accept_fn, close_func close_fn, void *data) 
{
	fdhandler_t *f;
	struct iohandler *ioh = &_iohandler;
    receiver_t  recv;

    recv.user  = data;
	recv.post = (post_func)accept_post_func;
    recv.accept = accept_fn;
    recv.close = close_fn;

    f = fdhandler_new(fd, &ioh->fdhandlers, HANDLER_TYPE_TCP_ACCEPT, &recv);
    listen(fd, 5);
	return f;
}


unsigned long iohandler_init(void) 
{
	struct iohandler *ioh = &_iohandler;

    looper_init(&ioh->looper);

    fdhandler_list_init(&ioh->fdhandlers, &ioh->looper);
	
	return (unsigned long)ioh;
}

void iohandler_once() 
{
	struct iohandler *ioh = &_iohandler;

    looper_exec(&ioh->looper);
}

void iohandler_loop() 
{
	struct iohandler *ioh = &_iohandler;

    looper_loop(&ioh->looper);
}

