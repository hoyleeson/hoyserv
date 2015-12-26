#ifndef _EMUSERVD_TIMER_H_
#define _EMUSERVD_TIMER_H_

#include <pthread.h>
#include <stdint.h>
#include "iohandler.h"

struct emu_timer;

enum clock_mode {
	CLOCK_MODE_LOOP,
	CLOCK_MODE_EVENT,
}; 

//#define EMU_CLOCK_MODE_EVENT

struct emu_clock {
	int clkid;
	int enable;
	int64_t next_expires;
	FDHandler* fdhandler;
	struct emu_timer *timers;

#ifdef EMU_CLOCK_MODE_EVENT
	int mode;
	pthread_cond_t cond;
    pthread_mutex_t mutex;
#endif
};

struct emu_timer {
	struct emu_timer *next;

	struct emu_clock *clock;

	int64_t expires;
	void (*func)(unsigned long);
	unsigned long data;
};

typedef void (*timer_func)(unsigned long);

void emu_mod_timer(struct emu_timer *timer, int64_t expires);
void emu_del_timer(struct emu_timer *timer);
void emu_free_timer(struct emu_timer *timer);
struct emu_timer *emu_new_timer(void (*fn)(unsigned long), unsigned long data);
int64_t emu_get_clock_ns(void);
void emu_timer_init(void);
void emu_run_timers();


#endif

