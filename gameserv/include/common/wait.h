#ifndef _COMMON_WAIT_H_
#define _COMMON_WAIT_H_

typedef struct _wait_obj {
	int done;
	sem_t sem;
} wait_obj_t;

void wait_obj_init(wait_obj_t *wait);
int wait_obj_destory(wait_obj_t *wait);

int wait_for_obj_timeout(wait_obj_t *wait, int ms);
int wait_for_obj(wait_obj_t *wait);

int post_obj(wait_obj_t *wait);

#define WAIT_TIMEOUT 	ETIMEDOUT

#endif

