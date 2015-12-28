#ifndef _SERV_NODE_MGR_H_
#define _SERV_NODE_MGR_H_

typedef struct _node_mgr node_mgr_t;
typedef struct _node_info node_info_t;

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

