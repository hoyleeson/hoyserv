#include <time.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/timerfd.h>

#include "timer.h"
#include "utils.h"


static struct emu_clock _clock;

#define NSEC2SEC 	(1000000000LL)

static void timer_set_interval(struct emu_timer *timer, int64_t interval)
{
	struct emu_clock *clock = timer->clock;
    struct itimerspec itval;
	int i_sec = interval / NSEC2SEC;
	int i_nsec = interval % NSEC2SEC;;

	itval.it_interval.tv_sec = 0;
	itval.it_interval.tv_nsec = 0;

    itval.it_value.tv_sec = i_sec;
    itval.it_value.tv_nsec = i_nsec;

	D("timer set interval:sec:%d, nsec:%d", i_sec, i_nsec);
    if (timerfd_settime(clock->clkid, 0, &itval, NULL) == -1)
		LOG("timer_set_interval: timerfd_settime failed, %d.%d\n", i_sec, i_nsec);
}

static void timer_set_expires(struct emu_timer *timer, int64_t expires) {
	int64_t now = emu_get_clock_ns();
	struct emu_clock *clock = timer->clock;

	clock->next_expires = expires;
	timer_set_interval(timer, expires - now);
}

static int emu_timer_expired(struct emu_timer *timer, int64_t expires) {
    return timer && (timer->expires <= expires);
}

void emu_add_timer(struct emu_timer *timer, int64_t expires) {
	struct emu_timer **pt, *t;
	struct emu_clock *clock = timer->clock;
	int64_t now = emu_get_clock_ns();

	if(expires < now) {
		D("warning: expires invaild:%lld", expires);
		return;
	}

	D("%s: expires:%lld", __func__, expires);
    /* add the timer in the sorted list */
    /* NOTE: this code must be signal safe because
       qemu_timer_expired() can be called from a signal. */

    pt = &clock->timers;
    for(;;) {
        t = *pt;
        if (!emu_timer_expired(t, expires)) {
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

void emu_del_timer(struct emu_timer *timer) {
	struct emu_clock *clock = timer->clock;
	struct emu_timer **pt, *t;

	D("del timer");
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

void emu_mod_timer(struct emu_timer *timer, int64_t expires) {
	emu_del_timer(timer);
	emu_add_timer(timer, expires);
}

void emu_free_timer(struct emu_timer *timer) {
	free(timer);
}

struct emu_timer *emu_new_timer(void (*fn)(unsigned long), unsigned long data) 
{
	struct emu_timer *timer;

	timer = (struct emu_timer *)malloc(sizeof(*timer));
	if(!timer)
		return NULL;

	timer->clock = &_clock;
	timer->expires = 0;
	timer->func = fn;
	timer->data = data;
	timer->next = NULL;

	return timer;
}

int64_t emu_get_clock_ns(void) {
	//struct timeval tv;
	//gettimeofday(&tv, NULL);
	//return tv.tv_sec * 1000000000LL + (tv.tv_usec * 1000);
	struct timespec curr;

	if (clock_gettime(CLOCK_MONOTONIC, &curr) == -1)
		return -EINVAL;

	return curr.tv_sec * NSEC2SEC + curr.tv_nsec;
}

void emu_run_timers() {
	struct emu_clock *clock = &_clock;
	struct emu_timer **pt, *t;
    int64_t curr_time;

	if(!clock->enable)
		return;

	D("timer running, fd:%d", clock->clkid);
    curr_time = emu_get_clock_ns();
	pt = &clock->timers;
	for(;;) {
		t = *pt;
		if(!emu_timer_expired(t, curr_time)) {
			timer_set_expires(t, t->expires);
			break;
		}

		*pt = t->next;
		t->next = NULL;
		t->func(t->data);
	}
}

static void timerfd_receive(struct emu_clock* c, uint8_t *data, int len)
{
    T("%s: %p (%d)", __FUNCTION__, c, len);
	emu_run_timers();
}

static void timerfd_close(struct emu_clock* c)
{
    T("%s: client %p (%d)", __FUNCTION__, c, c->fdhandler->fd);

    /* no need to shutdown the FDHandler */
    c->fdhandler = NULL;
}



void emu_timer_init(void) {
	struct emu_clock *clock = &_clock;

	clock->timers = NULL;
	clock->enable = 1;
	clock->next_expires = 0;

	clock->clkid = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
	clock->fdhandler = fdhandler_create(clock->clkid, (handle_func)timerfd_receive, 
			(close_func)timerfd_close, clock);

	D("timer init, fd:%d, %p", clock->clkid, clock->fdhandler);
}

