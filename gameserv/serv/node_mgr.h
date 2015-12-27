#ifndef _TURN_NODE_MGR_H_
#define _TURN_NODE_MGR_H_

typedef struct _node_mgr node_mgr_t;
typedef struct _node_info node_info_t;

typedef struct _task_baseinfo {
	uint8_t data[0];
} task_baseinfo_t;


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
	int (*assign_handle)(task_baseinfo_t *base, struct pack_task_assign *pkt);
	int (*reclaim_handle)(task_baseinfo_t *base, struct pack_task_reclaim *pkt);
	int (*control_handle)(task_baseinfo_t *base, struct pack_task_control *pkt);
};


struct _node_info {
	int fd;
	fdhandler_t *hand;
	struct listnode node;
	node_mgr_t *mgr;
};

struct _node_mgr {
	int node_count;
	fdhandler_t *hand;
	struct listnode nodelist;
};


#endif

