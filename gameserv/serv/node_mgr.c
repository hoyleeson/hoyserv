#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>

#include <common/log.h>
#include <common/pack.h>
#include <common/wait.h>
#include <arpa/inet.h>

#include "node_mgr.h"

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

static void *nodemgr_task_pkt_alloc(node_info_t *node)
{
	packet_t *packet;
	packet = fdhandler_pkt_alloc(node->hand);

	return packet->data + pack_head_len();

}

static void nodemgr_task_pkt_send(node_info_t *node, int type, void *data, int len)
{
	pack_head_t *head;
	packet_t *packet = (packet_t *)((uint8_t *)data - pack_head_len());

	head = (pack_head_t *)packet->data;
	init_pack(head, type, len);
	head->seqnum = node->nextseq++;

	packet->len = len + pack_head_len();
	fdhandler_pkt_submit(node->hand, packet);
}

#if 0
static void copy_sockaddr(void *dst, void *src)
{
	*(struct sockaddr *)dst = *(struct sockaddr *)src;
}
#endif

static void node_hand_fn(void* opaque, uint8_t *data, int len)
{
	int ret;
	node_info_t *node = (node_info_t *)opaque;
	pack_head_t *head;
	task_t *task;
	void *payload;

	if(data == NULL || len < sizeof(*head))
		return;

	head = (pack_head_t *)data;
	payload = head + 1; 

	if(head->magic != SERV_MAGIC ||
		   	head->version != SERV_VERSION)
		return;

	switch(head->type) {
		case MSG_TASK_ASSIGN_RESPONSE:
		{
			struct pack_task_assign_response *pt;
			pt = (struct pack_task_assign_response *)payload;
			response_post(&node->waits, MSG_TASK_ASSIGN_RESPONSE, pt->taskid, &pt->addr);
			break;
		}
		default:
			break;
	}
}

static void node_close_fn(void *user)
{
	node_info_t *node = (node_info_t *)user;
	node_unregister(node->mgr, node);
}

static node_info_t *nodemgr_choice_node(node_mgr_t *mgr, int priority)
{

}


static int init_task_assign_pkt(task_handle_t *task, task_baseinfo_t *base,
	   	struct pack_task_assign *pkt)
{
	struct task_operations *ops = task->ops;

	if(ops->init_assign_pkt)
		return ops->init_assign_pkt(base, pkt);

	return default_init_assign_pkt(base, pkt);
}


task_handle_t *nodemgr_task_assign(node_mgr_t *mgr, int type, int priority,
		task_baseinfo_t *base)
{
	int len;
	node_info_t *node;
	struct pack_task_assign *pkt;
	task_handle_t *task;

	if(!mgr)
		return NULL;

	task = malloc(sizeof(*task));
	if(!task)
		return NULL;

	node = nodemgr_choice_node(mgr, priority);

	task->node = node;
	task->taskid = alloc_taskid(mgr);
	task->type = type;
	task->priority = priority;
	task->ops = find_task_protos_by_type(type);

	pkt = (struct pack_task_assign *)nodemgr_task_pkt_alloc(node);

	len = init_task_assign_pkt(task, base, pkt);

	pkt->type = task->type;
	pkt->taskid = task->taskid;
	pkt->priority = task->priority;

	nodemgr_task_pkt_send(node, MSG_TASK_ASSIGN, pkt, len);

	wait_for_response(&node->waits, MSG_TASK_ASSIGN_RESPONSE, task->taskid, &task->addr);

	return task;
}


static int init_task_reclaim_pkt(task_handle_t *task, task_baseinfo_t *base,
	   	struct pack_task_reclaim *pkt)
{
	struct task_operations *ops = task->ops;

	if(ops->init_reclaim_pkt)
		return ops->init_reclaim_pkt(base, pkt);

	return default_init_reclaim_pkt(base, pkt);
}


int nodemgr_task_reclaim(node_mgr_t *mgr, task_handle_t *task,
		task_baseinfo_t *base)
{
	int len;
	node_info_t *node;
	struct pack_task_reclaim *pkt;

	if(!mgr)
		return -EINVAL;

	node = task->node;

	pkt = (struct pack_task_reclaim *)nodemgr_task_pkt_alloc(node);

	len = init_task_reclaim_pkt(task, base, pkt);

	pkt->taskid = task->taskid;
	pkt->type = task->type;

	nodemgr_task_pkt_send(node, MSG_TASK_RECLAIM, pkt, len);
	return 0;
}


static int init_task_control_pkt(task_handle_t *task, task_baseinfo_t *base,
	   	struct pack_task_control *pkt)
{
	struct task_operations *ops = task->ops;

	if(ops->init_control_pkt)
		return ops->init_control_pkt(base, pkt);

	return default_init_control_pkt(base, pkt);
}


int nodemgr_task_control(node_mgr_t *mgr, task_handle_t *task,
	   	int opt, task_baseinfo_t *base)
{
	int len;
	node_info_t *node;
	struct pack_task_control *pkt;

	if(!task || !mgr)
		return -EINVAL;

	node = task->node;

	pkt = (struct pack_task_control *)nodemgr_task_pkt_alloc(node);

	len = init_task_control_pkt(task, base, pkt);

	pkt->taskid = task->taskid;
	pkt->type = task->type;
	pkt->opt = opt;

	nodemgr_task_pkt_send(node, MSG_TASK_CONTROL, pkt, len);
	return 0;
}


static void nodemgr_accept_fn(void* user, int acceptfd)
{
	node_info_t *node;
	node_mgr_t *mgr = (node_mgr_t *)user;

	node = malloc(sizeof(*node));
	if(!node)
		return;

	node->fd = acceptfd;
	node->mgr = mgr;
	node->hand = fdhandler_create(acceptfd, node_hand_fn, node_close_fn, node);
	node->nextseq = 0;

	response_wait_init(&node->waits, HASH_WAIT_OBJ_DEFAULT_CAPACITY);
	
	node_register(mgr, node);
}

static void nodemgr_close_fn(void *user)
{
}


node_mgr_t *node_mgr_init(void)
{
	int sock;
	node_mgr_t *nodemgr;

	nodemgr = malloc(sizeof(*nodemgr));
	if(!nodemgr)
		return NULL;

	nodemgr->hand = fdhandler_accept_create(sock, nodemgr_accept_fn, nodemgr_close_fn, nodemgr);
	list_init(&nodemgr->nodelist);

	list_init(&task_protos_list);

	return nodemgr;
}

