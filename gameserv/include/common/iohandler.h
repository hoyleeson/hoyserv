#ifndef _EMUSERVD_IOHANDLER_H_
#define _EMUSERVD_IOHANDLER_H_

#include <pthread.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/types.h>



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

    pthread_mutex_t 	lock;
} looper_t;


void looper_init(looper_t*  l);
void looper_done(looper_t*  l);
loop_hook_t* looper_find(looper_t*  l, int  fd);
void looper_grow(looper_t*  l);
void looper_add(looper_t*  l, int  fd, event_fn  func, void*  user);
void looper_del(looper_t*  l, int  fd);
void looper_enable(looper_t*  l, int  fd, int  events);
void looper_disable(looper_t*  l, int  fd, int  events);
void looper_loop(looper_t*  l);
int looper_exec(looper_t* l);


/** PACKETS
 **
 ** We need a way to buffer data before it can be sent to the
 ** corresponding file descriptor. We use linked list of packet_t
 ** objects to do this.
 **/

typedef struct _packet   packet_t;
#define  MAX_PAYLOAD 		(4000) 

struct _packet {
    packet_t* next;
    int refcount;
    union {
        uint32_t channel; 	/*used tcp accept only*/
        struct sockaddr addr; 	/*used udp only*/
    };

    int len;
    uint8_t data[MAX_PAYLOAD];
};

#define data_to_packet(ptr)  \
    node_to_item(ptr, packet_t, data)


/** PACKET RECEIVER
 **
 ** Simple abstraction for something that can receive a packet
 ** from a fdhandler_t (see below) or something else.
 **
 ** Send a packet to it with 'receiver_post'
 **
 ** Call 'receiver_close' to indicate that the corresponding
 ** packet source was closed.
 **/

typedef void (*post_func) (void* user, packet_t *p);
typedef void (*handle_func) (void* user, uint8_t *data, int len);
typedef void (*handlefrom_func) (void* user, uint8_t *data, int len, void *from);
typedef void (*accept_func) (void* user, int acceptfd);
typedef void (*close_func)(void*  user);

typedef struct {
    void*      user;
    post_func   post;
    close_func  close;
    union {
        handle_func handle; /* used for fdhandler_create() */
        handlefrom_func handlefrom; /* used for fdhandler_create() */
        accept_func accept; /* used for fdhandler_create() */
    };
} receiver_t;



/** FD HANDLERS
 **
 ** these are smart listeners that send incoming packets to a receiver
 ** and can queue one or more outgoing packets and send them when
 ** possible to the FD.
 **
 ** note that we support clean shutdown of file descriptors,
 ** i.e. we try to send all outgoing packets before destroying
 ** the fdhandler_t.
 **/

typedef struct fdhandler      fdhandler_t;
typedef struct fdhandler_list  fdhandler_list_t;
typedef struct fdhandler_ops fdhandler_ops_t;


enum fdhandler_type {
    HANDLER_TYPE_NORMAL,
    HANDLER_TYPE_TCP_ACCEPT,
    HANDLER_TYPE_UDP,
};

struct fdhandler {
    fdhandler_list_t*  list;
    int    	fd;
    int 	type;
    char    closing;
    receiver_t receiver[1];

    /* queue of outgoing packets */
    packet_t*     out_first;
    packet_t**    out_ptail;

    fdhandler_t*    next;
    fdhandler_t**   pref;
    pthread_mutex_t lock;
};

struct fdhandler_list {
    /* the looper that manages the fds */
    looper_t*      looper;

    /* list of active fdhandler_t objects */
    fdhandler_t*   active;

    /* list of closing fdhandler_t objects.
     * these are waiting to push their
     * queued packets to the fd before
     * freeing themselves.
     */
    fdhandler_t*   closing;

    pthread_mutex_t lock;
};


packet_t *fdhandler_pkt_alloc(fdhandler_t *f);
packet_t *fdhandler_pkt_get(fdhandler_t *f, packet_t *buf);
void fdhandler_pkt_free(fdhandler_t *f, packet_t *buf);
void fdhandler_pkt_submit(fdhandler_t *f, packet_t *buf);

void fdhandler_remove(fdhandler_t*  f);
void fdhandler_prepend(fdhandler_t*  f, fdhandler_t**  list);
void fdhandler_list_init(fdhandler_list_t* list, looper_t* looper);
void fdhandler_close(fdhandler_t*  f);
void fdhandler_shutdown(fdhandler_t*  f);
void fdhandler_send(fdhandler_t *f, const uint8_t *data, int len);
void fdhandler_sendto(fdhandler_t *f, const uint8_t *data, int len, void *to);

fdhandler_t* fdhandler_create(int fd, handle_func hand_fn, close_func close_fn, void *data);
fdhandler_t* fdhandler_udp_create(int fd, handlefrom_func hand_fn, close_func close_fn, void *data);
fdhandler_t* fdhandler_accept_create(int fd, accept_func accept_fn, close_func close_fn, void *data);

unsigned long iohandler_init(void);
void iohandler_once(void);
void iohandler_loop(void);

#endif

