#include <stdlib.h>
#include <semaphore.h>
#include <string.h>
#include <sys/time.h>

#include <common/wait.h>

#define ms2ns(ms) ((ms)*1000*1000)

//#define WAIT_PACKET_TIMEOUT_MS 		(10 * 1000)
#define WAIT_PACKET_TIMEOUT_MS 		(1000 * 1000) 	//debug

int wait_obj_init(wait_obj_t *wait) 
{
	return sem_init(&wait->sem, 0, 0);
}

int wait_for_obj_timeout(wait_obj_t *wait, int ms)
{
    struct timespec timeout;
	struct timeval now;

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

static int int64_hash(void *key)
{
	return hashmapHash(key, sizeof(uint64_t));
}

static bool int64_equals(void* keyA, void* keyB) 
{
	uint64_t a = *(uint64_t *)keyA;
	uint64_t b = *(uint64_t *)keyB;
	  
	return (a == b);
}

int response_wait_init(response_wait_t *wait, int capacity)
{
	wait->hash = hashmapCreate(capacity, int64_hash, int64_equals);
	return 0;
}


int wait_for_response_data(response_wait_t *wait, int type, int seq,
	   	void *response, int *count)
{
	int ret;
	struct response_node expect;

	expect.type = type;
	expect.key = (uint64_t)type << 32 | seq;
	expect.response = response;
	expect.count = (count) ? *count : 0;

	wait_obj_init(&expect.wait);

	hashmapPut(wait->hash, &expect.key, &expect);
	ret = wait_for_obj_timeout(&expect.wait, WAIT_PACKET_TIMEOUT_MS);
	
	if(count != NULL)
		*count = expect.count;

	hashmapRemove(wait->hash, &expect.key);
	return ret;
}


void post_response_data(response_wait_t *wait, int type, int seq, 
		void *response, int count)
{
	uint64_t key;
	struct response_node *expect;

	key = (uint64_t)type << 32 | seq;
	expect = hashmapGet(wait->hash, &key);
	if(!expect)
		return;

	if((expect->count == 0) || 
			(expect->count != 0 && expect->count > count))
		expect->count = count;

	memcpy(expect->response, response, expect->count);

	post_obj(&expect->wait);
}


int wait_for_response(response_wait_t *wait, int type, int seq, void *response)
{
	return wait_for_response_data(wait, type, seq, response, NULL);
}


void post_response(response_wait_t *wait, int type, int seq, void *response,
	   	void (*fn)(void *dst, void *src))
{
	uint64_t key;
	struct response_node *expect;

	key = (uint64_t)type << 32 | seq;
	expect = hashmapGet(wait->hash, &key);
	if(!expect)
		return;

	fn(expect->response, response);

	post_obj(&expect->wait);
}


