#ifndef _SERV_NODE_MGR_H_
#define _SERV_NODE_MGR_H_

#include <stdint.h>
#include <common/list.h>
#include <common/wait.h>
#include <common/iohandler.h>

#include "task.h"

typedef struct _node_mgr node_mgr_t;
typedef struct _node_info node_info_t;

struct _node_info {
	int fd;
	fdhandler_t *hand;
	int nextseq;
	response_wait_t waits;

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


node_mgr_t *node_mgr_init(void);

#endif

