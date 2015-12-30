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

struct response_node {
	int type;
	uint64_t key;
	void *response;
	wait_obj_t wait;
};

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
	wait->waits_map = hashmapCreate(capacity, int64_hash, int64_equals);
	return 0;
}

int wait_for_response(response_wait_t *wait, int type, int seq, void *response)
{
	int ret;
	struct response_node expect;

	expect.type = type;
	expect.key = (uint64_t)type << 32 | seq;
	expect.response = response;
	wait_obj_init(&expect.wait);

	hashmapPut(cli->waits_map, type, &expect);
	ret = wait_for_obj_timeout(&expect.wait, WAIT_PACKET_TIMEOUT_MS);
	
	hashmapRemove(cli->waits_map, type);
	return ret;
}


void post_response(response_wait_t *wait, int type, int seq, void *response,
	   	void (*fn)(void *dst, void *src))
{
	uint64_t key;
	struct response_node *expect;

	key = (uint64_t)type << 32 | seq;
	expect = hashmapGet(cli->waits_map, key);
	if(!expect)
		return;

	fn(expect->response, response);

	post_obj(&expect->wait);
}


