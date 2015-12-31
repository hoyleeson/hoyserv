#ifndef _SERV_TASK_H_
#define _SERV_TASK_H_

#include <stdint.h>

#include <protos.h>

typedef struct _task_baseinfo {
	uint8_t data[0];
} task_baseinfo_t;

struct task;
typedef struct task task_t;

static inline void init_taskbase_info(task_baseinfo_t *info)
{
	return;
}

struct task_operations {
	int type;
	struct listnode node;

	/* used by node manager only */
	int (*init_assign_pkt)(task_baseinfo_t *base, struct pack_task_assign *pkt);
	int (*init_reclaim_pkt)(task_baseinfo_t *base, struct pack_task_reclaim *pkt);
	int (*init_control_pkt)(task_baseinfo_t *base, struct pack_task_control *pkt);

	/* used by node server only */
	task_t* (*assign_handle)(struct pack_task_assign *pkt);
	int (*reclaim_handle)(task_t *task, struct pack_task_reclaim *pkt);
	int (*control_handle)(task_t *task, struct pack_task_control *pkt);

	int (*init_assign_response_pkt)(task_t *task, struct pack_task_base *pkt);

	int (*task_handle)(task_t *task, struct pack_task_req *pack);
};

static inline int default_init_assign_pkt(task_baseinfo_t *base, struct pack_task_assign *pkt)
{
	int len = sizeof(struct pack_task_assign);

	*pkt = (struct pack_task_assign *)malloc(len);
	return len;
}

static inline int default_init_reclaim_pkt(task_baseinfo_t *base, struct pack_task_reclaim *pkt)
{
	int len = sizeof(struct pack_task_reclaim);

	*pkt = (struct pack_task_reclaim *)malloc(len);
	return len;
}

static inline int default_init_control_pkt(task_baseinfo_t *base, struct pack_task_control *pkt)
{
	int len = sizeof(struct pack_task_control);

	*pkt = (struct pack_task_control *)malloc(len);
	return len;
}

static inline int default_init_assign_response_pkt(struct pack_task_assign_response *pkt)
{
	int len = sizeof(struct pack_task_assign_response);

	*pkt = (struct pack_task_assign_response *)malloc(len);
	return len;
}

#endif

