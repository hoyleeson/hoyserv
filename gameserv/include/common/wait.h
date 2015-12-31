#ifndef _COMMON_WAIT_H_
#define _COMMON_WAIT_H_

#include <stdint.h>
#include <semaphore.h>
#include <common/hashmap.h>

typedef struct _wait_obj {
	int done;
	sem_t sem;
} wait_obj_t;

int wait_obj_init(wait_obj_t *wait);
int wait_obj_destory(wait_obj_t *wait);

int wait_for_obj_timeout(wait_obj_t *wait, int ms);
int wait_for_obj(wait_obj_t *wait);

int post_obj(wait_obj_t *wait);


struct response_node {
	int type;
	uint64_t key;
	void *response;
	wait_obj_t wait;
};

typedef struct response_wait {
	Hashmap *hash;
} response_wait_t;


int response_wait_init(response_wait_t *wait, int capacity);
int wait_for_response(response_wait_t *wait, int type, int seq, void *response);
void post_response(response_wait_t *wait, int type, int seq, void *response,
		void (*fn)(void *, void *));

#define response_post(_wait, _type, _seq, _resp) ({  \
	int ret = 0; 		\
	do  { 				\
		uint64_t key; 	\
		struct response_node *expect; \
		typeof(*(_resp)) *dst = expect->response; \
						\
		key = (uint64_t)(_type)<< 32 | (_seq); 	\
		expect = hashmapGet((_wait)->hash, &key); \
		if(!expect) {	\
			ret = -EINVAL; 	\
			break; 		\
		} 				\
		*dst =  *(_resp); \
						\
		post_obj(&expect->wait); \
	} while(0); 		\
	ret; 				\
})


static inline void default_assign(void * a, void *b)
{
	a = b;
}


#define WAIT_TIMEOUT 	ETIMEDOUT

#endif

