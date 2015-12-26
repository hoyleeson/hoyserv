#ifndef _TURN_NODE_MGR_H_
#define _TURN_NODE_MGR_H_

typedef struct _node_mgr node_mgr_t;
typedef struct _node_info node_info_t;

typedef struct _task_info {
	int type;
	int priority;
} task_info_t;


struct task_operations {
	int type;
	struct listnode node;

	/* used by node manager only */
	int (*create_assign_pkt)(void *data, struct pack_task_assign **pkt);
	int (*create_reclaim_pkt)(void *data, struct pack_task_reclaim **pkt);
	int (*create_control_pkt)(void *data, struct pack_task_control **pkt);

	/* used by node server only */
	int (*assign_handle)(void *data, struct pack_task_assign *pkt);
	int (*reclaim_handle)(void *data, struct pack_task_reclaim *pkt);
	int (*control_handle)(void *data, struct pack_task_control *pkt);
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

