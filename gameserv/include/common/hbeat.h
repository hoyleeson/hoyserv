#ifndef _COMMON_HBEAT_H_
#define _COMMON_HBEAT_H_

#include <common/list.h>
#include <common/timer.h>

#define HBEAT_INIT 		    (3)
#define HBEAD_DEAD_TIME     (10 * NSEC2SEC)


typedef struct hbeat_node {
    int count;
    int online;
    struct listnode node;
} hbeat_node_t;

typedef struct hbeat_god {
    struct listnode list;
    struct timer_item *timer;
    void (*dead)(hbeat_node_t *hbeat);
    pthread_mutex_t lock;
} hbeat_god_t;


void user_heartbeat(hbeat_node_t *hbeat);

void hbeat_add_to_god(hbeat_god_t *god, hbeat_node_t *hbeat);
void hbeat_rm_from_god(hbeat_god_t *god, hbeat_node_t *hbeat);

void hbeat_god_init(hbeat_god_t *god, void (*dead)(hbeat_node_t *));

#endif
