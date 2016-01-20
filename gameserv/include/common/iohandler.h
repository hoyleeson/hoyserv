#ifndef _EMUSERVD_IOHANDLER_H_
#define _EMUSERVD_IOHANDLER_H_

#include <pthread.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <common/fake_atomic.h>


/** PACKETS
 **
 ** We need a way to buffer data before it can be sent to the
 ** corresponding file descriptor. We use linked list of packet_t
 ** objects to do this.
 **/
typedef struct _packet   packet_t;


#define MAX_PAYLOAD 		(2000) 
#define SOCKADDR_LEN        (16)    /* equals of sizeof(struct sockaddr_in) */
#define MCASTS_COUNT        (8)
#define MCASTS_PAYLOAD      (MAX_PAYLOAD - MCASTS_COUNT * SOCKADDR_LEN - 4)
#define UCASTS_PAYLOAD      (MAX_PAYLOAD - SOCKADDR_LEN)

enum _packet_type {
    TYPE_NORMAL,
    TYPE_UCAST,
    TYPE_MCAST,
};

struct _packet {
    packet_t* next;
    fake_atomic_t refcount;
    int type;

    int len;
    union {
        struct {
            uint8_t data[MCASTS_PAYLOAD];   /* It must be placed in first */
            int count;
            struct sockaddr addr[MCASTS_COUNT]; 
        } mcast;     /*used for Multicast */
        struct {
            uint8_t data[UCASTS_PAYLOAD];  /* It must be placed in first */
            struct sockaddr addr; 	/*used udp only*/
        } ucast;  /*used for Unicast*/

        uint8_t data[MAX_PAYLOAD];
    };
};

#define data_to_packet(ptr)  \
    node_to_item(ptr, packet_t, data)


/** PACKET RECEIVER
 **
 ** Simple abstraction for something that can receive a packet
 ** from a ioasync_t (see below) or something else.
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


/** FD HANDLERS
 **
 ** these are smart listeners that send incoming packets to a receiver
 ** and can queue one or more outgoing packets and send them when
 ** possible to the FD.
 **
 ** note that we support clean shutdown of file descriptors,
 ** i.e. we try to send all outgoing packets before destroying
 ** the ioasync_t.
 **/

typedef struct ioasync      ioasync_t;
typedef struct ioasync_list  ioasync_list_t;
typedef struct ioasync_ops ioasync_ops_t;


packet_t *ioasync_pkt_alloc(ioasync_t *f);
packet_t *ioasync_pkt_get(packet_t *buf);
void ioasync_pkt_free(packet_t *buf);

void ioasync_pkt_send(ioasync_t *f, packet_t *p);
void ioasync_pkt_sendto(ioasync_t *f, packet_t *p, struct sockaddr *to);
void ioasync_pkt_multicast(ioasync_t *f, packet_t *p, struct sockaddr *dstptr, int count);

void ioasync_send(ioasync_t *f, const uint8_t *data, int len);
void ioasync_sendto(ioasync_t *f, const uint8_t *data, int len, void *to);

ioasync_t *ioasync_create(int fd, handle_func hand_fn, close_func close_fn, void *data);
ioasync_t *ioasync_udp_create(int fd, handlefrom_func hand_fn, close_func close_fn, void *data);
ioasync_t *ioasync_accept_create(int fd, accept_func accept_fn, close_func close_fn, void *data);
ioasync_t* ioasync_udp_create_exclusive(int fd, handlefrom_func handfrom_fn, 
        close_func close_fn, void *data);

void ioasync_close(ioasync_t*  f);
void ioasync_shutdown(ioasync_t*  f);

unsigned long iohandler_init(void);
void iohandler_loop(void);
void iohandler_done(void);

#endif

