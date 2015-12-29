#include <stdlib.h>
#include <semaphore.h>

#define ms2ns(ms) ((ms)*1000*1000)


int wait_obj_init(wait_obj_t *wait) 
{
	return sem_init(&wait->sem, 0, 0);
}

int wait_for_obj_timeout(wait_obj_t *wait, int ms)
{
    struct timespec timeout;

	gettimeofday(&now, NULL);
	timeout.tv_sec = now.tv_sec + ms / 1000;
	timeout.tv_nsec = now.tv_usec * 1000 + ms2ns(ms % 1000);

	return sem_timedwait(&wait->sem, &timeout);
}

int wait_for_obj(wait_obj_t *wait)
{
	return sem_wait(&wait->sem);
}

int post_obj(wait_obj_t *wait)
{
	return sem_post(&wait->sem);
}

int wait_obj_destory(wait_obj_t *wait)
{
	return sem_destroy(&wait->sem);
}
