#ifndef _SERV_NODE_MGR_H_
#define _SERV_NODE_MGR_H_

typedef struct _node_mgr node_mgr_t;
typedef struct _node_info node_info_t;

struct _node_info {
	int fd;
	fdhandler_t *hand;
	response_wait waits;

	struct listnode node;
	node_mgr_t *mgr;
};

struct _node_mgr {
	int node_count;
	fdhandler_t *hand;
	struct listnode nodelist;
};

typedef struct _task_handle {
	int taskid;
	int type;
	int priority;
	
	struct sockaddr addr; 	/* assign response */
	struct task_operations *ops;

	node_info_t *node;
} task_handle_t;


#endif

