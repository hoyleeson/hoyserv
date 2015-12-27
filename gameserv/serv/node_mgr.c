#include <stdio.h>

typedef struct _task_handle {
	int taskid;
	int type;
	int priority;

	node_info_t *node;
} task_handle_t;

static struct listnode task_protos_list;
static pthread_mutex_t task_protos_lock;

void task_protos_register(struct task_operations *ops) 
{
	list_add_tail(&task_protos_list, &ops->node);
}

void task_protos_unregister(struct task_operations *ops)
{
	list_remove(&ops->node);
}

struct task_operations *find_task_protos_by_type(int type) 
{
	struct task_operations *ops;
	list_for_each_entry(ops, &task_protos_list, node) {
		if(ops->type == type)
			return ops;
	}

	return NULL;
}

static int node_register(node_mgr_t *mgr, node_info_t *node)
{
	list_add_tail(&mgr->nodelist, &node->node);
	mgr->node_count++;
}

static void node_unregister(node_mgr_t *mgr, node_info_t *node)
{
	list_remove(&node->node);
	mgr->node_count--;
}


static nodemgr_task_send(node_info_t *node, const uint8_t data, int len)
{
	fdhandler_send(node->hand, data, len);
}


static void node_hand_func(void* user, uint8_t *data, int len)
{
	
}

static void node_close_fn(void *user)
{
	node_info_t *node = (node_info_t *)user;
	node_unregister(node);
}


static void nodemgr_accept_func(void* user, int acceptfd)
{
	node_info_t *node;
	node_mgr_t *mgr = (node_mgr_t *)user;

	node = malloc(sizeof(*node));
	if(!node)
		return;

	node->fd = acceptfd;
	node->mgr = mgr;
	node->hand = fdhandler_create(acceptfd, nodemgr_hand_fn, nodemgr_close_fn, node);
	
	node_register(mgr, node);
}

static void nodemgr_close_fn(void *user)
{
}

static node_info_t *nodemgr_choice_node(node_mgr_t *mgr, int priority)
{

}


static int create_task_assign_pkt(int type, task_baseinfo_t *base,
	   	struct pack_task_assign **pkt)
{
	struct task_operations *ops;

	ops = find_task_protos_by_type(type);
	if(!ops)
		return -EINVAL;

	return ops->create_assign_pkt(base, pkt);
}


unsigned int nodemgr_task_assign(node_mgr_t *mgr, int type, int priority,
		task_baseinfo_t *base)
{
	int len;
	node_info_t *node;
	struct pack_task_assign *pkt;
	task_handle_t *handle;

	if(!mgr)
		return -EINVAL;

	handle = malloc(sizeof(*handle));
	if(!handle)
		return -EINVAL;

	node = nodemgr_choice_node(mgr, priority);
	handle->node = node;
	handle->taskid = alloc_taskid(mgr);
	handle->type = type;
	handle->priority = priority;

	len = create_task_assign_pkt(type, base, &pkt);

	pkt->type = MSG_TASK_ASSIGN;
	pkt->taskid = handle->taskid;
	pkt->priority = handle->priority;
	nodemgr_task_send(node, (const uint8_t)pkt, len);

	return (unsigned int)handle;
}


static int create_task_reclaim_pkt(int type, task_baseinfo_t *base,
	   	struct pack_task_reclaim **pkt)
{
	struct task_operations *ops;

	ops = find_task_protos_by_type(type);
	if(!ops)
		return -EINVAL;

	return ops->create_reclaim_pkt(base, pkt);
}


int nodemgr_task_reclaim(node_mgr_t *mgr, unsigned int handle,
		task_baseinfo_t *base)
{
	int len;
	node_info_t *node;
	struct pack_task_reclaim *pkt;
	task_handle_t *task = (task_handle_t *)handle;

	if(!mgr)
		return -EINVAL;

	node = task->node;

	len = create_task_reclaim_pkt(base, &pkt);

	pkt->type = MSG_TASK_RECLAIM;
	nodemgr_task_send(node, (const uint8_t)pkt, len);
	return 0;
}


static int create_task_control_pkt(int type, task_baseinfo_t *base,
	   	struct pack_task_control **pkt)
{
	struct task_operations *ops;

	ops = find_task_protos_by_type(type);
	if(!ops)
		return -EINVAL;

	return ops->create_control_pkt(base, pkt);
}


int nodemgr_task_control(node_mgr_t *mgr, unsigned int handle,
	   	task_baseinfo_t *base)
{
	int len;
	node_info_t *node;
	struct pack_task_control *pkt;

	if(!task || !mgr)
		return -EINVAL;

	node = (node_info_t *)handle;

	len = create_task_control_pkt(task, &pkt);

	pkt->type = MSG_TASK_CONTROL;
	nodemgr_task_send(node, (const uint8_t)pkt, len);
	return 0;
}


node_mgr_t *node_mgr_init(void)
{
	nodeserv_mgr_t *nsm;

	cm = malloc(sizeof(*nsm));
	if(!tsm)
		return NULL;

	nsm->hand = fdhandler_accept_create(clifd, nodemgr_accept_fn, nodemgr_close_fn, nsm);

	list_init(&task_protos_list);

	return nsm;
}

