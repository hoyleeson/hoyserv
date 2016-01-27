#include <stdint.h>
#include <stdarg.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <pthread.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>

#include <common/iohandler.h>
#include <common/log.h>
#include <common/utils.h>
#include <common/thr_pool.h>
#include <common/fake_atomic.h>

#define USE_THREAD_POOLS 	(1)


/* A looper_t object is used to monitor activity on one or more
 * file descriptors (e.g sockets).
 *
 * - call looper_add() to register a function that will be
 *   called when events happen on the file descriptor.
 *
 * - call looper_enable() or looper_disable() to enable/disable
 *   the set of monitored events for a given file descriptor.
 *
 * - call looper_del() to unregister a file descriptor.
 *   this does *not* close the file descriptor.
 *
 * Note that you can only provide a single function to handle
 * all events related to a given file descriptor.

 * You can call looper_enable/_disable/_del within a function
 * callback.
 */

/* the current implementation uses Linux's epoll facility
 * the event mask we use are simply combinations of EPOLLIN
 * EPOLLOUT, EPOLLHUP and EPOLLERR
 */

#define  MAX_CHANNELS  16
#define  MAX_EVENTS    (MAX_CHANNELS+1)  /* each channel + the serial fd */

/* the event handler function type, 'user' is a user-specific
 * opaque pointer passed to looper_add().
 */
typedef void (*event_fn)(void*  user, int  events);

/* bit flags for the loop_hook_t structure.
 *
 * HOOK_PENDING means that an event happened on the
 * corresponding file descriptor.
 *
 * HOOK_CLOSING is used to delay-close monitored
 * file descriptors.
 */
enum {
    HOOK_PENDING = (1 << 0),
    HOOK_CLOSING = (1 << 1),
};

/* A loop_hook_t structure is used to monitor a given
 * file descriptor and record its event handler.
 */
typedef struct {
    int        fd;
    int        wanted;  /* events we are monitoring */
    int        events;  /* events that occured */
    int        state;   /* see HOOK_XXX constants */
    void*      ev_user; /* user-provided handler parameter */
    event_fn  ev_func; /* event handler callback */
} loop_hook_t;

/* looper_t is the main object modeling a looper object
*/
typedef struct {
    int epoll_fd;
    int num_fds;
    int max_fds;

    loop_hook_t*       	hooks;
    struct epoll_event* events;
    int ctl_socks[2];
    int running;

    pthread_mutex_t 	lock;
} looper_t;


typedef struct {
    void*      user;
    post_func   post;
    close_func  close;
    union {
        handle_func handle; /* used for ioasync_create() */
        handlefrom_func handlefrom; /* used for ioasync_create() */
        accept_func accept; /* used for ioasync_create() */
    };
} receiver_t;


enum ioasync_type {
    HANDLER_TYPE_NORMAL,
    HANDLER_TYPE_TCP_ACCEPT,
    HANDLER_TYPE_UDP,
};

#define IOASYNC_EXCLUSIVE       (1 << 0)

struct ioasync {
    ioasync_list_t*  list;
    int    	fd;
    int 	type;
    int     flags;
    char    closing;
    receiver_t receiver[1];

    /* queue of outgoing packets */
    packet_t*     out_first;
    packet_t**    out_ptail;

    ioasync_t*    next;
    ioasync_t**   pref;
    pthread_mutex_t lock;
};

struct ioasync_list {
    /* the looper that manages the fds */
    looper_t*      looper;

    /* list of active ioasync_t objects */
    ioasync_t*   active;

    /* list of closing ioasync_t objects.
     * these are waiting to push their
     * queued packets to the fd before
     * freeing themselves.
     */
    ioasync_t*   closing;

    pthread_mutex_t lock;
};



struct iohandler {
    looper_t looper;
    ioasync_list_t ioasyncs;
};

static struct iohandler _iohandler; 

enum loop_ev_opt {
    EV_LOOPER_ADD,
    EV_LOOPER_DEL,
    EV_LOOPER_ENABLE,
    EV_LOOPER_DISABLE,
    EV_LOOPER_SIGNAL,
};

typedef struct {
    int opt;
    int fd;

    union {
        struct {
            void* ev_user;
            event_fn ev_func;
        } ev; /* used for looper add */
        int events; 		/* used for looper enable / disable */
    };
} loop_ctl_t;


static inline void looper_ctl_submit(looper_t* l, void *data, int len)
{
    int ret;

    pthread_mutex_lock(&l->lock);
    ret = fd_write(l->ctl_socks[0], data, len);
    if(ret < 0)
        loge("looper ctl command submit failed(%d).\n", ret);
    pthread_mutex_unlock(&l->lock);
}

/* register a file descriptor and its event handler.
 * no event mask will be enabled
 */
static void looper_add(looper_t*  l, int  fd, event_fn  func, void*  user)
{
    loop_ctl_t ctl;

    ctl.opt = EV_LOOPER_ADD;
    ctl.fd = fd;

    ctl.ev.ev_user = user;
    ctl.ev.ev_func = func;

    looper_ctl_submit(l, &ctl, sizeof(ctl));
}

/*
 * unregister a file descriptor and its event handler
 */
static void looper_del(looper_t*  l, int  fd)
{
    loop_ctl_t ctl;

    ctl.opt = EV_LOOPER_DEL;
    ctl.fd = fd;

    looper_ctl_submit(l, &ctl, sizeof(ctl));
}

/* enable monitoring of certain events for a file
 * descriptor. This adds 'events' to the current
 * event mask
 */
static void looper_enable(looper_t*  l, int  fd, int  events)
{
    loop_ctl_t ctl;

    ctl.opt = EV_LOOPER_ENABLE;
    ctl.fd = fd;
    ctl.events = events;

    looper_ctl_submit(l, &ctl, sizeof(ctl));
}

/* disable monitoring of certain events for a file
 * descriptor. This ignores events that are not
 * currently enabled.
 */
static void looper_disable(looper_t*  l, int  fd, int  events)
{
    loop_ctl_t ctl;

    ctl.opt = EV_LOOPER_DISABLE;
    ctl.fd = fd;
    ctl.events = events;

    looper_ctl_submit(l, &ctl, sizeof(ctl));
}

/* 
 * 
 */
static void looper_signal(looper_t*  l)
{
    loop_ctl_t ctl;

    ctl.opt = EV_LOOPER_SIGNAL;
    looper_ctl_submit(l, &ctl, sizeof(ctl));
}


/* return the loop_hook_t corresponding to a given
 * monitored file descriptor, or NULL if not found
 */
static loop_hook_t* looper_find(looper_t*  l, int  fd)
{
    loop_hook_t*  hook;
    loop_hook_t*  end;

    hook = l->hooks;
    end = hook + l->num_fds;

    for (; hook < end; hook++) {
        if (hook->fd == fd)
            return hook;
    }

    return NULL;
}

/* grow the arrays in the looper object */
static void looper_grow(looper_t*  l)
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
static void looper_ctl_add(looper_t*  l, int  fd, event_fn  func, void*  user)
{
    struct epoll_event  ev;
    loop_hook_t*           hook;

    if (l->num_fds >= l->max_fds)
        looper_grow(l);

    hook = l->hooks + l->num_fds;
    l->num_fds += 1;

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
}

/* unregister a file descriptor and its event handler
*/
static void looper_ctl_del(looper_t*  l, int  fd)
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
static void looper_ctl_enable(looper_t*  l, int  fd, int  events)
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

        epoll_ctl(l->epoll_fd, EPOLL_CTL_MOD, fd, &ev);
    }
}

/* disable monitoring of certain events for a file
 * descriptor. This ignores events that are not
 * currently enabled.
 */
static void looper_ctl_disable(looper_t*  l, int  fd, int  events)
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


static void looper_ctl_handle(looper_t *l, void *data, int len)
{
    loop_ctl_t *ctl;

    ctl = (loop_ctl_t *)data;

    switch(ctl->opt) {
        case EV_LOOPER_ADD:
            looper_ctl_add(l, ctl->fd, ctl->ev.ev_func, ctl->ev.ev_user);
            break;
        case EV_LOOPER_DEL:
            looper_ctl_del(l, ctl->fd);
            break;
        case EV_LOOPER_ENABLE:
            looper_ctl_enable(l, ctl->fd, ctl->events);
            break;
        case EV_LOOPER_DISABLE:
            looper_ctl_disable(l, ctl->fd, ctl->events);
            break;
        default:
            break;
    }
}

static void looper_ctl_event(looper_t *l, int events)
{
    char data[MAX_PAYLOAD] = {0};
    int len;

    if(!(events & EPOLLIN)) {
        return;
    }

    len = fd_read(l->ctl_socks[1], data, MAX_PAYLOAD);
    if(len < 0)
        return;

    looper_ctl_handle(l, data, len);
}

static int looper_exec(looper_t* l) {
    int n, count;
    loop_hook_t* hook;

    do {
        count = epoll_wait(l->epoll_fd, l->events, l->num_fds, -1);
    } while (count < 0 && errno == EINTR);

    if (count < 0) {
        loge("%s: error: %s\n", __func__, strerror(errno));
        return -EINVAL;
    }

    if (count == 0) {
        loge("%s: huh ? epoll returned count=0\n", __func__);
        return 0;
    }

    /* mark all pending hooks */
    for (n = 0; n < count; n++) {
        hook = l->events[n].data.ptr;
        hook->state  = HOOK_PENDING;
        hook->events = l->events[n].events;
    }

    /* execute hook callbacks. this may change the 'hooks'
     * and 'events' array, as well as l->num_fds, so be careful */
    for (n = 1; n < l->num_fds; n++) {
        hook = l->hooks + n;
        if (hook->state & HOOK_PENDING) {
            hook->state &= ~HOOK_PENDING;
            hook->ev_func(hook->ev_user, hook->events);
        }
    }

    /* now remove all the hooks that were closed by
     * the callbacks */
    for (n = 1; n < l->num_fds;) {
        struct epoll_event ev;
        hook = l->hooks + n;

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

    /* manage hook. */
    hook = l->hooks;
    if (hook->state & HOOK_PENDING) {
        hook->state &= ~HOOK_PENDING;
        hook->ev_func(hook->ev_user, hook->events);
    }

    return 0;
}


/* initialize a looper object */
static void looper_init(looper_t*  l)
{
    int ret; 
    int size = MAX_PAYLOAD * 4;
    l->epoll_fd = epoll_create(1);
    l->num_fds  = 0;
    l->max_fds  = 0;
    l->events   = NULL;
    l->hooks    = NULL;

    pthread_mutex_init(&l->lock, NULL);

    ret = socketpair(AF_UNIX, SOCK_DGRAM, 0, l->ctl_socks);
    if (ret < 0) {
        loge("Error in pipe() errno:%d", errno);
        return;
    }

    loge("Create pipe() :%d:%d", l->ctl_socks[0], l->ctl_socks[1]);
    setsockopt(l->ctl_socks[0], SOL_SOCKET, SO_RCVBUF, &size, sizeof(size));
    setsockopt(l->ctl_socks[0], SOL_SOCKET, SO_SNDBUF, &size, sizeof(size));
    setsockopt(l->ctl_socks[1], SOL_SOCKET, SO_RCVBUF, &size, sizeof(size));
    setsockopt(l->ctl_socks[1], SOL_SOCKET, SO_SNDBUF, &size, sizeof(size));
    fcntl(l->ctl_socks[0], F_SETFL, O_NONBLOCK);
    fcntl(l->ctl_socks[1], F_SETFL, O_NONBLOCK);

    looper_ctl_add(l, l->ctl_socks[1], (event_fn)looper_ctl_event, l);
    looper_ctl_enable(l, l->ctl_socks[1], EPOLLIN);
    l->running = 1;
}

/* finalize a looper object */
static void looper_release(looper_t*  l)
{
    if(l->running) {
        l->running = 0;
        logw("warning:looper release enter. but looper is running.\n");
    }

    xfree(l->events);
    xfree(l->hooks);
    l->max_fds = 0;
    l->num_fds = 0;

    close(l->epoll_fd);
    l->epoll_fd  = -1;
}

static void looper_done(looper_t*  l)
{
    l->running = 0;
    looper_signal(l);
}


/* wait until an event occurs on one of the registered file
 * descriptors. Only returns in case of error !!
 */
static void looper_loop(looper_t*  l)
{
    int ret;
    for (;;) {
        if(!l->running)
            break;

        ret = looper_exec(l);
        if(ret)
            break;
    }

    looper_release(l);
}


/**********************************************************************/


/* we expect to alloc/free a lot of packets during
 * operations so use a single linked list of free packets
 * to keep things speedy and simple.
 */
static packet_t*   _free_packets;
static pthread_mutex_t packets_lock = PTHREAD_MUTEX_INITIALIZER;

/* Allocate a packet */
static packet_t* packet_alloc(void)
{
    packet_t*  p;

    pthread_mutex_lock(&packets_lock);
    p = _free_packets;
    if (p != NULL) {
        _free_packets = p->next;
    } else {
        xnew(p);
    }
    pthread_mutex_unlock(&packets_lock);

    p->next    = NULL;
    p->len     = 0;
    p->type    = TYPE_NORMAL;
    fake_atomic_init(&p->refcount, 1);

    return p;
}

static packet_t* packet_get(packet_t* p)
{
    fake_atomic_inc(&p->refcount);
    return p;
}

/* Release a packet. This takes the address of a packet
 * pointer that will be set to NULL on exit (avoids
 * referencing dangling pointers in case of bugs)
 */
static void packet_free(packet_t*  *ppacket)
{
    pthread_mutex_lock(&packets_lock);

    packet_t* p = *ppacket;
    if (p) {
        if(!fake_atomic_dec_and_test(&p->refcount))
            goto out;

        p->next       = _free_packets;
        _free_packets = p;
        *ppacket = NULL;
    }

out:
    pthread_mutex_unlock(&packets_lock);
}


/**********************************************************************/


static inline void __receiver_post(receiver_t*  r, packet_t* p)
{
    if (r->post)
        r->post(r, p);
    else
        packet_free(&p);
}


struct handler_job_arg {
    receiver_t *recv;
    packet_t *pkt;
};


static void *receiver_handle(void *arg)
{
    struct handler_job_arg *job = (struct handler_job_arg *)arg;

    __receiver_post(job->recv, job->pkt);

    free(job);
    return 0;
}


/* handle a packet to a receiver. Note that this transfers
 * ownership of the packet to the receiver.
 */
static void receiver_post(receiver_t*  r, packet_t*  p)
{
    struct handler_job_arg *arg;
    thr_pool_t * thpool;

    if(!USE_THREAD_POOLS)
        return __receiver_post(r, p);

    arg = malloc(sizeof(struct handler_job_arg));
    arg->recv = r;
    arg->pkt = p;

    thpool = get_global_thpool();
    thr_pool_queue(thpool, receiver_handle, arg);
}


/* tell a receiver the packet source was closed.
 * this will also prevent further handleing to the
 * receiver.
 */
static inline void receiver_close(receiver_t*  r)
{
    if (r->close) {
        r->close(r->user);
        r->close = NULL;
    }
    r->post = NULL;
    r->handle = NULL;
}

/* remove a ioasync_t from its current list */
static void ioasync_remove(ioasync_t*  f)
{
    ioasync_list_t*  list = f->list;

    pthread_mutex_lock(&list->lock);
    f->pref[0] = f->next;
    if (f->next)
        f->next->pref = f->pref;
    pthread_mutex_unlock(&list->lock);
}

/* add a ioasync_t to a given list */
static void ioasync_prepend(ioasync_t*  f, ioasync_t**  l)
{
    ioasync_list_t*  list = f->list;

    pthread_mutex_lock(&list->lock);

    f->next = l[0];
    f->pref = l;
    l[0] = f;
    if (f->next)
        f->next->pref = &f->next;

    pthread_mutex_unlock(&list->lock);
}

/* initialize a ioasync_t list */
static void ioasync_list_init(ioasync_list_t*  list, looper_t*  looper)
{
    list->looper  = looper;
    list->active  = NULL;
    list->closing = NULL;
    pthread_mutex_init(&list->lock, NULL);
}


/* close a ioasync_t (and free it). Note that this will not
 * perform a graceful shutdown, i.e. all packets in the
 * outgoing queue will be immediately free.
 *
 * this *will* notify the receiver that the file descriptor
 * was closed.
 *
 * you should call ioasync_shutdown() if you want to
 * notify the ioasync_t that its packet source is closed.
 */
void ioasync_close(ioasync_t*  f)
{
    logd("%s: closing fd %d", __func__, f->fd);

    /* notify receiver */
    receiver_close(f->receiver);

    /* remove the handler from its list */
    ioasync_remove(f);

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

    if(f->flags & IOASYNC_EXCLUSIVE)
        looper_done(f->list->looper);

    f->list = NULL;
    xfree(f);
}

/* Ask the ioasync_t to cleanly shutdown the connection,
 * i.e. send any pending outgoing packets then auto-free
 * itself.
 */
void ioasync_shutdown(ioasync_t*  f)
{
    logd("%s: shoutdown", __func__);
    /* prevent later ioasync_close() to
     * call the receiver's close.
     */
    f->receiver->close = NULL;

    if (f->out_first != NULL && !f->closing)
    {
        /* move the handler to the 'closing' list */
        f->closing = 1;
        ioasync_remove(f);
        ioasync_prepend(f, &f->list->closing);
        return;
    }

    ioasync_close(f);
}

/* Enqueue a new packet that the ioasync_t will
 * send through its file descriptor.
 */
static void ioasync_enqueue(ioasync_t*  f, packet_t*  p)
{
    packet_t*  first;

    pthread_mutex_lock(&f->lock);

    first = f->out_first;

    p->next         = NULL;
    f->out_ptail[0] = p;
    f->out_ptail    = &p->next;

    if (first == NULL) {
        looper_enable(f->list->looper, f->fd, EPOLLOUT);
    }

    pthread_mutex_unlock(&f->lock);
}

void ioasync_send(ioasync_t *f, const uint8_t *data, int len) 
{
    packet_t*   p;

    p = packet_alloc();
    memcpy(p->data, data, len);
    p->len = len;

    p->type = TYPE_NORMAL;
    ioasync_enqueue(f, p);
}

void ioasync_sendto(ioasync_t *f, const uint8_t *data, int len, void *to) 
{
    packet_t*   p;
    struct sockaddr *addr = (struct sockaddr *)to;

    p = packet_alloc();
    memcpy(p->ucast.data, data, len);
    p->len = len;
    p->ucast.addr = *addr;

    p->type = TYPE_UCAST;
    ioasync_enqueue(f, p);
}

packet_t *ioasync_pkt_alloc(ioasync_t *f)
{
    return packet_alloc();
}

packet_t *ioasync_pkt_get(packet_t *p)
{
    return packet_get(p);
}

void ioasync_pkt_free(packet_t *p)
{
    packet_free(&p);
}

void ioasync_pkt_send(ioasync_t *f, packet_t *p)
{
    p->type = TYPE_NORMAL;
    ioasync_enqueue(f, p);
}

void ioasync_pkt_sendto(ioasync_t *f, packet_t *p, struct sockaddr *to)
{
    p->ucast.addr = *to;
    p->type = TYPE_UCAST;
    ioasync_enqueue(f, p);
}

void ioasync_pkt_multicast(ioasync_t *f, packet_t *p,
        struct sockaddr *to, int count)
{
    p->mcast.count = count;
    memcpy(&p->mcast.addr, to, count * sizeof(struct sockaddr));
    p->type = TYPE_MCAST;
    ioasync_enqueue(f, p);
}

static int ioasync_read(ioasync_t*  f)
{
    packet_t*  p = packet_alloc();

    switch(f->type) {
        case HANDLER_TYPE_NORMAL:
            p->len = fd_read(f->fd, p->data, MAX_PAYLOAD);
            break;
        case HANDLER_TYPE_UDP:
        {
            socklen_t addrlen = sizeof(struct sockaddr_in);
            bzero(&p->ucast.addr, sizeof(p->ucast.addr));
            p->len = recvfrom(f->fd, p->ucast.data, MAX_PAYLOAD, 0, &p->ucast.addr, &addrlen);
            break;
        }
        case HANDLER_TYPE_TCP_ACCEPT:
        {
            int channel = fd_accept(f->fd);
            memcpy(p->data, &channel, sizeof(int));
            p->len = sizeof(int);
            break;
        }
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

static int ioasync_write_packet(ioasync_t* f, packet_t *p)
{
    int len;

    switch(f->type) {
        case HANDLER_TYPE_NORMAL:
            {
                int out_pos = 0;
                int avail = 0;

                while(out_pos < p->len) {
                    avail = p->len - out_pos;

                    len = fd_write(f->fd, p->data + out_pos, avail);
                    if(len < 0) 
                        goto fail;
                    out_pos += len;
                }
                break;
            }
        case HANDLER_TYPE_UDP:
            if(p->type == TYPE_MCAST) {
                int i = 0;
                for(i=0; i<p->mcast.count; i++) {
                    len = sendto(f->fd, p->mcast.data, p->len, 0, 
                            &p->mcast.addr[i], sizeof(struct sockaddr));
                    if(len < 0)
                        goto fail;               
                }
            } else {
                len = sendto(f->fd, p->ucast.data, p->len, 0, 
                        &p->ucast.addr, sizeof(struct sockaddr));
                if(len < 0)
                    goto fail;
            }
            break;
        case HANDLER_TYPE_TCP_ACCEPT:
        default:
            goto fail;
    }

    return 0;

fail:
    packet_free(&p);
    loge("send data fail, ret=%d, droped.\n", len);
    return -EINVAL;
}

static int ioasync_write(ioasync_t*  f) 
{
    packet_t* p;
    int ret;

    pthread_mutex_lock(&f->lock);
    if(!f->out_first) {
        pthread_mutex_unlock(&f->lock);
        return 0;
    }

    p = f->out_first;

    f->out_first = p->next;
    if (f->out_first == NULL) {
        f->out_ptail = &f->out_first;
        looper_disable(f->list->looper, f->fd, EPOLLOUT);
    }

    pthread_mutex_unlock(&f->lock);

    ret = ioasync_write_packet(f, p);
    ioasync_pkt_free(p);

    return ret;
}

/* ioasync_t file descriptor event callback for read/write ops */
static void ioasync_event(ioasync_t*  f, int  events)
{
    /* in certain cases, it's possible to have both EPOLLIN and
     * EPOLLHUP at the same time. This indicates that there is incoming
     * data to read, but that the connection was nonetheless closed
     * by the sender. Be sure to read the data before closing
     * the receiver to avoid packet loss.
     */
    if(events & EPOLLIN) {
        ioasync_read(f);
    }

    if(events & EPOLLOUT) {
        ioasync_write(f);
    }

    if(events & (EPOLLHUP|EPOLLERR)) {
        /* disconnection */
        loge("%s: disconnect on fd %d", __func__, f->fd);
        ioasync_close(f);
        return;
    }
}

/* Create a new ioasync_t that monitors read/writes */
static ioasync_t* ioasync_new(int fd, ioasync_list_t* list, 
        int type, receiver_t* receiver)
{
    ioasync_t*  f = xzalloc(sizeof(*f));

    f->fd = fd;
    f->type = type;
    f->list = list;
    f->receiver[0] = receiver[0];
    f->flags = 0;

    f->out_first   = NULL;
    f->out_ptail   = &f->out_first;
    pthread_mutex_init(&f->lock, NULL);

    ioasync_prepend(f, &list->active);

    looper_add(list->looper, fd, (event_fn)ioasync_event, f);
    looper_enable(list->looper, fd, EPOLLIN);
    return f;
}


static void normal_post_func(receiver_t *r, packet_t *p)
{
    if(r->handle)
        r->handle(r->user, p->data, p->len);

    packet_free(&p);
}

ioasync_t* ioasync_create(int fd, handle_func hand_fn, close_func close_fn, void *data)
{
    struct iohandler *ioh = &_iohandler;
    receiver_t  recv;

    recv.user  = data;
    recv.handle = hand_fn;
    recv.post = (post_func)normal_post_func;
    recv.close = close_fn;

    return ioasync_new(fd, &ioh->ioasyncs, HANDLER_TYPE_NORMAL, &recv);
}


static void accept_post_func(receiver_t *r, packet_t *p)
{
    int channel = ((int *)p->data)[0];
    if(r->accept)
        r->accept(r->user, channel);

    packet_free(&p);
}

ioasync_t* ioasync_accept_create(int fd, 
        accept_func accept_fn, close_func close_fn, void *data) 
{
    ioasync_t *f;
    struct iohandler *ioh = &_iohandler;
    receiver_t  recv;

    recv.user  = data;
    recv.post = (post_func)accept_post_func;
    recv.accept = accept_fn;
    recv.close = close_fn;

    f = ioasync_new(fd, &ioh->ioasyncs, HANDLER_TYPE_TCP_ACCEPT, &recv);
    listen(fd, 5);
    return f;
}


static void udp_post_func(receiver_t *r, packet_t *p)
{
    if(r->handlefrom)
        r->handlefrom(r->user, p->ucast.data, p->len, &p->ucast.addr);

    packet_free(&p);
}


ioasync_t* ioasync_udp_create(int fd, handlefrom_func handfrom_fn, 
        close_func close_fn, void *data)
{
    struct iohandler *ioh = &_iohandler;
    receiver_t  recv;

    recv.user  = data;
    recv.handlefrom = handfrom_fn;
    recv.post = (post_func)udp_post_func;
    recv.close = close_fn;

    return ioasync_new(fd, &ioh->ioasyncs, HANDLER_TYPE_UDP, &recv);
}

static void *iohandler_loop_exclusive(void *arg)
{
    struct iohandler *ioh = (struct iohandler *)arg;

    looper_loop(&ioh->looper);

    /* exit!! */
    free(ioh);
    return 0;
}

static int iohandler_run_exclusive(struct iohandler *ioh)
{
    int ret;
    pthread_t th;

    ret = pthread_create(&th, NULL, iohandler_loop_exclusive, ioh);
    if(ret)
        return ret;

    return 0;
}

ioasync_t* ioasync_udp_create_exclusive(int fd, handlefrom_func handfrom_fn, 
        close_func close_fn, void *data)
{
    struct iohandler *ioh;
    ioasync_t *f;
    receiver_t  recv;

    recv.user  = data;
    recv.handlefrom = handfrom_fn;
    recv.post = (post_func)udp_post_func;
    recv.close = close_fn;

    /* create a unique iohandler */
    ioh = (struct iohandler *)malloc(sizeof(*ioh));

    looper_init(&ioh->looper);
    ioasync_list_init(&ioh->ioasyncs, &ioh->looper);

    f = ioasync_new(fd, &ioh->ioasyncs, HANDLER_TYPE_UDP, &recv);
    f->flags |= IOASYNC_EXCLUSIVE;

    iohandler_run_exclusive(ioh);
    return f;
}

unsigned long iohandler_init(void) 
{
    struct iohandler *ioh = &_iohandler;

    looper_init(&ioh->looper);

    ioasync_list_init(&ioh->ioasyncs, &ioh->looper);

    return (unsigned long)ioh;
}


void iohandler_loop(void) 
{
    struct iohandler *ioh = &_iohandler;

    looper_loop(&ioh->looper);
}

void iohandler_done(void) 
{
    struct iohandler *ioh = &_iohandler;

    looper_done(&ioh->looper);
}


