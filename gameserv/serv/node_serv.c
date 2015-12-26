#include <stdio.h>



typedef struct _task_handle {
	fdhandler_t *hand;
	int port;
	void *priv_data;
} task_handle_t;

/* ns: node server */

typedef struct _node_serv {
	int task_count;

	fdhandler_t *mgr_hand;
} node_serv_t;

static node_serv_t node_serv;

static int ns_task_assign_handle(struct pack_task_assign *pa)
{
	struct task_operations *ops;

	ops = find_task_protos_by_type(task->type);
	if(!ops)
		return -EINVAL;

	return ops->assign_handle(pkt);
}

static int ns_task_reclaim_handle(struct pack_task_reclaim *pr)
{
	struct task_operations *ops;

	ops = find_task_protos_by_type(task->type);
	if(!ops)
		return -EINVAL;

	return ops->reclaim_handle(pkt);
}

static int ns_task_control_handle(struct pack_task_control *pc)
{
	struct task_operations *ops;

	ops = find_task_protos_by_type(task->type);
	if(!ops)
		return -EINVAL;

	return ops->control_handle(pkt);
}

int ns_task_register()
{

}

static void create_task_handle()
{

}

static void ns_hand_func(void *opaque, uint8_t *data, int len)
{
	int ret;
	node_serv_t *ns = (node_serv_t *)opaque;
	pack_head_t *head;
	void *payload;

	if(data == NULL || len < sizeof(*head))
		return;

	head = (pack_head_t *)data;
	payload = head + 1; 

	if(head->magic != TURN_SERV_MAGIC ||
		   	head->version != TURN_VERSION)
		return;

	switch(head->type) {
		case MSG_TASK_ASSIGN:
			struct pack_task_assign *ta = (struct pack_task_assign *)payload;
			break;
		case MSG_TASK_RECLAIM:
			struct pack_task_reclaim *ta = (struct pack_task_reclaim *)payload;
			break;
		case MSG_TASK_CONTROL:
			struct pack_task_control *ta = (struct pack_task_control *)payload;
			break;
	}


}

static void ns_close_fn(node_serv_t *ns)
{

}


int node_serv_init(const char *host)
{
	int socket;
	node_serv_t *ns = &node_serv;

	socket = socket_network_client(host, CENTER_SERV_NODE_PORT, SOCK_STREAM);

	ns->mgr_hand = fdhandler_create(socket, ns_handle_fn, ns_close_fn, ns);

	ns->task_hand = fdhandler_create();

	return 0;
}

