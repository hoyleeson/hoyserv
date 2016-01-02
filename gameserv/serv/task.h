#ifndef _SERV_TASK_H_
#define _SERV_TASK_H_

#include <stdint.h>

#include <protos.h>
#include "protos_internal.h"

typedef struct _task_baseinfo {
	uint8_t data[0];
} task_baseinfo_t;

typedef struct _task_worker task_worker_t;

typedef struct task {
	int taskid;
	int type;
	int priority;
	task_worker_t *worker;
	struct task_operations *ops;
	uint8_t priv_data[0];
} task_t;



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
	int (*control_handle)(task_t *task, int opt, struct pack_task_control *pkt);

	int (*init_assign_response_pkt)(task_t *task, struct pack_task_assign_response *pkt);

	int (*task_handle)(task_t *task, struct pack_task_req *pack);
};

static inline int default_init_assign_pkt(task_baseinfo_t *base, struct pack_task_assign *pkt)
{
	return sizeof(struct pack_task_assign);
}

static inline int default_init_reclaim_pkt(task_baseinfo_t *base, struct pack_task_reclaim *pkt)
{
	return sizeof(struct pack_task_reclaim);
}

static inline int default_init_control_pkt(task_baseinfo_t *base, struct pack_task_control *pkt)
{
	return sizeof(struct pack_task_control);
}

static inline int default_init_assign_response_pkt(task_t *task,
	   	struct pack_task_assign_response *pkt)
{
	return sizeof(struct pack_task_assign_response);
}

#endif

