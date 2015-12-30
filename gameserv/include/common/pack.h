#ifndef _COMMON_PACK_H_
#define _COMMON_PACK_H_

#include <stdint.h>

typedef struct _pack_header {
	uint16_t magic;
	uint8_t version;
	uint8_t type;
	uint16_t seqnum;
	uint8_t _reserved1;
	uint8_t _reserved2;
	uint32_t datalen;
	uint8_t data[0];
}__attribute__((packed)) pack_head_t;


pack_head_t *create_pack(uint8_t type, uint32_t len);
void init_pack(pack_head_t *pack, uint8_t type, uint32_t len);
void free_pack(pack_head_t *pack);


typedef struct _pack_buf {
	void *data;
	int len;

	struct listnode list;

	void  (*destructor)(pack_buf_t *pkb);
	uint8_t refcount;
	pthread_mutex_t lock;
} pack_buf_t;


pack_buf_t *alloc_pack_buf(void);

pack_buf_t *pack_buf_get(pack_buf_t *pkb);

void free_pack_buf(pack_buf_t *pkb);

#endif

