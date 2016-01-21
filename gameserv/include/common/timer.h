#ifndef _EMUSERVD_TIMER_H_
#define _EMUSERVD_TIMER_H_

#include <pthread.h>
#include <stdint.h>
#include "iohandler.h"

#define NSEC2SEC 	(1000000000LL)

struct timer_item;

enum clock_mode {
    CLOCK_MODE_LOOP,
    CLOCK_MODE_EVENT,
}; 

//#define EMU_CLOCK_MODE_EVENT

typedef struct timer_base {
    int clkid;
    int enable;
    int64_t next_expires;
    ioasync_t* ioasync;
    struct timer_item *timers;

#ifdef EMU_CLOCK_MODE_EVENT
    int mode;
    pthread_cond_t cond;
    pthread_mutex_t mutex;
#endif
} timer_base_t;

struct timer_item {
    struct timer_item *next;

    struct timer_base *clock;

    int64_t expires;
    void (*func)(unsigned long);
    unsigned long data;
};

typedef void (*timer_func)(unsigned long);

void add_timer(struct timer_item *timer, int64_t expires);
void mod_timer(struct timer_item *timer, int64_t expires);
void del_timer(struct timer_item *timer);
void free_timer(struct timer_item *timer);
struct timer_item *new_timer(void (*fn)(unsigned long), unsigned long data);
int64_t get_clock_ns(void);
void timer_init(void);
void run_timers();


#endif

