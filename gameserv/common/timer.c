#include <time.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/timerfd.h>
#include <errno.h>

#include <common/timer.h>
#include <common/log.h>
#include <common/utils.h>
#include <common/iohandler.h>


static timer_base_t _clock;


static void timer_set_interval(struct timer_item *timer, int64_t interval)
{
    timer_base_t *clock = timer->clock;
    struct itimerspec itval;
    int i_sec = interval / NSEC2SEC;
    int i_nsec = interval % NSEC2SEC;;

    itval.it_interval.tv_sec = 0;
    itval.it_interval.tv_nsec = 0;

    itval.it_value.tv_sec = i_sec;
    itval.it_value.tv_nsec = i_nsec;

    logd("timer set interval:sec:%d, nsec:%d\n", i_sec, i_nsec);
    if (timerfd_settime(clock->clkid, 0, &itval, NULL) == -1)
        loge("timer_set_interval: timerfd_settime failed, %d.%d\n", i_sec, i_nsec);
}

static void timer_set_expires(struct timer_item *timer, int64_t expires) {
    int64_t now = get_clock_ns();
    timer_base_t *clock = timer->clock;

    clock->next_expires = expires;
    timer_set_interval(timer, expires - now);
}

static int timer_expired(struct timer_item *timer, int64_t expires) {
    return timer && (timer->expires <= expires);
}

void add_timer(struct timer_item *timer, int64_t expires) {
    struct timer_item **pt, *t;
    timer_base_t *clock = timer->clock;
    int64_t now = get_clock_ns();

    if(expires < now) {
        loge("warning: expires invaild:%lld\n", expires);
        return;
    }

    logd("%s: expires:%lld\n", __func__, expires);
    /* add the timer in the sorted list */
    /* NOTE: this code must be signal safe because
       qtimer_expired() can be called from a signal. */

    pt = &clock->timers;
    for(;;) {
        t = *pt;
        if (!timer_expired(t, expires)) {
            break;
        }
        pt = &t->next;
    }
    timer->expires = expires;
    timer->next = *pt;
    *pt = timer;

    if(clock->next_expires > expires || clock->next_expires <= now) {
        timer_set_expires(timer, expires);
    }
}

void del_timer(struct timer_item *timer) {
    timer_base_t *clock = timer->clock;
    struct timer_item **pt, *t;

    logd("del timer\n");
    pt = &clock->timers;

    for(;;) {
        t = *pt;
        if(!t)
            break;
        if(t == timer) {
            *pt = t->next;
            break;
        }
        pt = &t->next;	
    }

    if(t && (t->expires == clock->next_expires) && (*pt != NULL))
        timer_set_expires(timer, (*pt)->expires);
}

void mod_timer(struct timer_item *timer, int64_t expires) {
    del_timer(timer);
    add_timer(timer, expires);
}

void free_timer(struct timer_item *timer) {
    free(timer);
}

struct timer_item *new_timer(void (*fn)(unsigned long), unsigned long data) 
{
    struct timer_item *timer;

    timer = (struct timer_item *)malloc(sizeof(*timer));
    if(!timer)
        return NULL;

    timer->clock = &_clock;
    timer->expires = 0;
    timer->func = fn;
    timer->data = data;
    timer->next = NULL;

    return timer;
}

int64_t get_clock_ns(void) {
    //struct timeval tv;
    //gettimeofday(&tv, NULL);
    //return tv.tv_sec * 1000000000LL + (tv.tv_usec * 1000);
    struct timespec curr;

    if (clock_gettime(CLOCK_MONOTONIC, &curr) == -1)
        return -EINVAL;

    return curr.tv_sec * NSEC2SEC + curr.tv_nsec;
}

void run_timers() {
    timer_base_t *clock = &_clock;
    struct timer_item **pt, *t;
    int64_t curr_time;

    if(!clock->enable)
        return;

    logd("timer running, fd:%d\n", clock->clkid);
    curr_time = get_clock_ns();
    pt = &clock->timers;
    for(;;) {
        t = *pt;
        if(!t)
            break;

        if(!timer_expired(t, curr_time)) {
            timer_set_expires(t, t->expires);
            break;
        }

        *pt = t->next;
        t->next = NULL;
        t->func(t->data);
    }
}

static void timerfd_receive(timer_base_t* c, uint8_t *data, int len)
{
    logd("%s: %p (%d)\n", __FUNCTION__, c, len);
    run_timers();
}

static void timerfd_close(timer_base_t* c)
{
    logd("%s: client %p.\n", __FUNCTION__, c);

    /* no need to shutdown the FDHandler */
    c->ioasync = NULL;
}


void timer_init(void) {
    timer_base_t *clock = &_clock;

    clock->timers = NULL;
    clock->enable = 1;
    clock->next_expires = 0;

    clock->clkid = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
    clock->ioasync = ioasync_create(clock->clkid, (handle_func)timerfd_receive, 
            (close_func)timerfd_close, clock);

    logi("timer init, fd:%d, %p\n", clock->clkid, clock->ioasync);
}

