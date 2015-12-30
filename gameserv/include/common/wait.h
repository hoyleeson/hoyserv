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


typedef struct response_wait {
	Hashmap *hash;
} response_wait_t;


int response_wait_init(response_wait_t *wait, int capacity);
int wait_for_response(response_wait_t *wait, int type, int seq, void *response);
void post_response(response_wait_t *wait, int type, int seq, void *response,
		void (*fn)(void *, void *));

#define response_post(wait, type, seq, resp) ({  \
	int ret = 0; 		\
	do  { 				\
		uint64_t key; 	\
		struct response_node *expect; \
		typeof(*resp) *dst = expect->response; \
						\
		key = (uint64_t)type << 32 | seq; 	\
		expect = hashmapGet(cli->waits_map, key); \
		if(!expect) {	\
			ret = -EINVAL; 	\
			break; 		\
		} 				\
		*dst =  *response; 		\
						\
		post_obj(&expect->wait); \
	} while(0) 			\
	ret; 				\
})


static inline void default_assign(void * a, void *b)
{
	a = b;
}


#define WAIT_TIMEOUT 	ETIMEDOUT

#endif

