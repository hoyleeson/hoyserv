#include <stdlib.h>

#include <common/pack.h>


pack_head_t *create_pack(uint8_t type, uint32_t len)
{
	pack_head_t *pack;
	pack = (pack_head_t *)malloc(sizeof(*pack) + size);	
	if(!pack)
		return NULL;

	pack->magic = SERV_MAGIC;
	pack->version = SERV_VERSION;

	pack->type = type;
	pack->datalen = len;
	return pack;
}

void init_pack(pack_head_t *pack, uint8_t type, uint32_t len)
{
	pack->magic = SERV_MAGIC;
	pack->version = SERV_VERSION;

	pack->type = type;
	pack->datalen = len;
}


void free_pack(pack_head_t *pack)
{
	free(pack);
}

/**************************************************************/

static void pack_destructor(pack_buf_t *pkb)
{
}

pack_buf_t *alloc_pack_buf(void)
{
	pack_buf_t *pkb;

	pkb = (pack_buf_t *)malloc(sizeof(*pkb));
	if(!pkb)
		fatal("alloc memory fail.\n");

	pthread_mutex_init(&pkb->lock, NULL);
	pkb->destructor = pack_destructor; /*XXX*/
	pkb->refcount++;

	pkb->len = 0;
	pkb->data = NULL;

	return pkb;
}

void pack_buf_fill(void *data, int len, void  (*destructor)(pack_buf_t *pkb))
{
	pkb->destructor = destructor;
	pkb->len = data;
	pkb->data = len;
}


pack_buf_t *pack_buf_get(pack_buf_t *pkb)
{
	pthread_mutex_lock(pkb->lock);
	pkb->refcount++;
	pthread_mutex_unlock(pkb->lock);

	return pkb;
}

void free_pack_buf(pack_buf_t *pkb)
{
	int ref;
	pthread_mutex_lock(pkb->lock);
	ref = --pkb->refcount;
	pthread_mutex_unlock(pkb->lock);

	if(!ref) {
		pkb->destructor(pkb);
		free(pkb);
	}
}

