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
	int (*create_assign_pkt)(task_baseinfo_t *base, struct pack_task_assign **pkt);
	int (*create_reclaim_pkt)(task_baseinfo_t *base, struct pack_task_reclaim **pkt);
	int (*create_control_pkt)(task_baseinfo_t *base, struct pack_task_control **pkt);

	/* used by node server only */
	task_t* (*assign_handle)(struct pack_task_assign *pkt);
	int (*reclaim_handle)(task_t *task, struct pack_task_reclaim *pkt);
	int (*control_handle)(task_t *task, struct pack_task_control *pkt);

	int (*task_handle)(task_t *task, struct pack_task_req *pack);
};


#endif

