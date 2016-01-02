#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stddef.h>
#include <pthread.h>
#include <errno.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include <common/iohandler.h>
#include <common/hashmap.h>
#include <common/list.h>
#include <common/wait.h>
#include <common/sockets.h>
#include <common/pack.h>

#include "task.h"
#include "serv.h"

#define HASH_WORKER_CAPACITY 	(256)
#define WORKER_MAX_TASK_COUNT 	(512)

struct _node_serv;
typedef struct _node_serv  node_serv_t;


/* ns: node server */

struct _node_serv {
	int worker_count;
	struct listnode worker_list;
	fdhandler_t *mgr_hand;
	int nextseq;

	int task_count;
	task_worker_t *suit_worker;
};

struct _task_worker {
	fdhandler_t *hand;
	int nextseq;
	struct sockaddr addr;

	int task_count;
	struct Hashmap *tasks_map; 	/*key: task id*/

	node_serv_t *owner;
	struct listnode node;
};



static node_serv_t node_serv;


task_t *create_task(int priv_size)
{
	task_t *task;

	task = malloc(sizeof(*task) + priv_size);
	return task;
}

void release_task(task_t *task) 
{
	free(task);
}


task_t *find_node_serv_task(node_serv_t *ns, int taskid)
{
	task_t *task;
	task_worker_t *worker;

	list_for_each_entry(worker, &ns->worker_list, node) {
		task = hashmapGet(worker->tasks_map, (void *)taskid);
		if(task) {
			return task;
		}
	}

	return NULL;
}


void *task_worker_pkt_alloc(task_t *task)
{
	task_worker_t *worker = task->worker;
	packet_t *packet;

	packet = fdhandler_pkt_alloc(worker->hand);

	return packet->data + pack_head_len();

}

void task_worker_pkt_sendto(task_t *task, int type, 
		void *data, int len, struct sockaddr *to)
{
	pack_head_t *head;
	task_worker_t *worker = task->worker;

	packet_t *packet = (packet_t *)((uint8_t *)data - pack_head_len());

	head = (pack_head_t *)packet->data;
	init_pack(head, type, len);
	head->seqnum = worker->nextseq++;

	packet->len = len + pack_head_len();
	packet->addr = *to;

	fdhandler_pkt_submit(worker->hand, packet);
}

/*XXX*/
static int task_req_handle(node_serv_t *ns, struct pack_task_req *pack)
{
	task_t *task;
	struct task_operations *ops;

	ops = find_task_protos_by_type(pack->type);
	if(!ops)
		return -EINVAL;

	task = find_node_serv_task(ns, pack->taskid);
	if(!task)
		return -EINVAL;

	return ops->task_handle(task, pack);
}


static void task_worker_handle(void *opaque, uint8_t *data, int len, void *from)
{
	int ret;
	task_worker_t *worker = (task_worker_t *)opaque;
	pack_head_t *head;
	void *payload;

	if(data == NULL || len < sizeof(*head))
		return;

	head = (pack_head_t *)data;
	payload = head + 1; 

	if(head->magic != SERV_MAGIC ||
			head->version != SERV_VERSION)
		return;

	switch(head->type) {
		case MSG_TASK_REQ:
		{
			struct pack_task_req *pack = (struct pack_task_req *)payload;
			task_req_handle(worker->owner, pack);
			break;
		}
		default:
			break;
	}
}


static void task_worker_close(void *opaque)
{

}


static task_worker_t *create_task_worker(node_serv_t *ns)
{
	int sock;
	int port;
	struct sockaddr_in addr;
	socklen_t addrlen;
	task_worker_t *tworker;

	sock = socket_inaddr_any_server(0, SOCK_DGRAM);

	/* get the actual port number assigned by the system */
	addrlen = sizeof(addr);
	memset(&addr, 0, sizeof(addr));

	if (getsockname(sock, (struct sockaddr*)&addr, &addrlen) < 0) {
		close(sock);
		return NULL;
	}

	tworker = malloc(sizeof(*tworker));
	if(!tworker)
		goto out;

	tworker->addr = *((struct sockaddr *)&addr);
	tworker->task_count = 0;
	tworker->owner = ns;

	tworker->hand = fdhandler_udp_create(sock, task_worker_handle,
		   	task_worker_close, tworker);
	tworker->tasks_map = hashmapCreate(HASH_WORKER_CAPACITY, int_hash, int_equals);
	tworker->nextseq = 0;

	list_add_tail(&ns->worker_list, &tworker->node);
out:
	return tworker;
}

static void free_task_worker(task_worker_t *worker) 
{

}

static void *node_serv_pkt_alloc(node_serv_t *ns)
{
	packet_t *packet;

	packet = fdhandler_pkt_alloc(ns->mgr_hand);

	return packet->data + pack_head_len();

}

static void node_serv_pkt_send(node_serv_t *ns, int type, void *data, int len)
{
	pack_head_t *head;

	packet_t *packet = (packet_t *)((uint8_t *)data - pack_head_len());

	head = (pack_head_t *)packet->data;
	init_pack(head, type, len);
	head->seqnum = ns->nextseq++;

	packet->len = len + pack_head_len();

	fdhandler_pkt_submit(ns->mgr_hand, packet);
}


static task_t *node_serv_task_assign(struct pack_task_assign *pt)
{
	task_t *task;
	struct task_operations *ops;

	ops = find_task_protos_by_type(pt->type);
	if(!ops)
		return -EINVAL;

	task = ops->assign_handle(pt);

	task->taskid = pt->taskid;
	task->type = pt->type;
	task->priority = pt->priority;

	task->ops = ops;

	return task;
}

static inline int node_serv_task_reclaim(task_t *task, struct pack_task_reclaim *pt)
{
	struct task_operations *ops = task->ops;

	if(ops->reclaim_handle)
		return ops->reclaim_handle(task, pt);

	return -EINVAL;
}

static inline int node_serv_task_control(task_t *task, int opt, struct pack_task_control *pt)
{
	struct task_operations *ops = task->ops;

	if(ops->control_handle)
		return ops->control_handle(task, opt, pt);

	return -EINVAL;
}


static inline int init_task_assign_response_pkt(task_t *task,
	   	struct pack_task_assign_response *pkt)
{
	struct task_operations *ops = task->ops;

	if(ops->init_assign_response_pkt)
		return ops->init_assign_response_pkt(task, pkt);

	return default_init_assign_response_pkt(task, pkt);
}


static int task_assign_response(node_serv_t *ns, task_t *task)
{
	int len;
	void *buf;
	struct pack_task_assign_response *pkt;
	task_worker_t *worker = task->worker;
	struct task_operations *ops = task->ops;

	pkt = (struct pack_task_assign_response *)node_serv_pkt_alloc(ns);

	len = init_task_assign_response_pkt(task, pkt);

	pkt->taskid = task->taskid;
	pkt->type = task->type;
	pkt->addr = worker->addr;

	node_serv_pkt_send(ns, MSG_TASK_ASSIGN_RESPONSE, pkt, len);
}

static void worker_add_task(task_worker_t *worker, task_t *task)
{
	worker->task_count++;

	hashmapPut(worker->tasks_map, (void*)task->taskid, task);
}


static void worker_remove_task(task_worker_t *worker, task_t *task)
{
	hashmapRemove(worker->tasks_map, (void *)task->taskid);
	worker->task_count--;
}

static int node_serv_task_register(node_serv_t *ns, task_t *task)
{
	task_worker_t *pos, *worker = NULL;
	int count = WORKER_MAX_TASK_COUNT;

	worker = ns->suit_worker;
	if(worker && worker->task_count < WORKER_MAX_TASK_COUNT)
		goto found;

	/* slow path */
	list_for_each_entry(pos, &ns->worker_list, node) {
		if(count < pos->task_count) {
			count = pos->task_count;
			worker = pos;
		}
	}

	if(count != WORKER_MAX_TASK_COUNT) {
		goto found;
	} else {
		worker = create_task_worker(ns);
		if(!worker)
			return -EINVAL;
	}

found:
	ns->task_count++;
	worker_add_task(worker, task);

	ns->suit_worker = worker;	
	return 0;
}

static void node_serv_task_unregister(node_serv_t *ns, task_t *task)
{
	task_worker_t *worker = task->worker;

	worker_remove_task(worker, task);
	ns->task_count--;
	task->worker = NULL;
}


static void node_serv_handle(void *opaque, uint8_t *data, int len)
{
	int ret;
	node_serv_t *ns = (node_serv_t *)opaque;
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
		case MSG_TASK_ASSIGN:
		{
			struct pack_task_assign *pt = (struct pack_task_assign *)payload;
			task = node_serv_task_assign(pt);
			node_serv_task_register(ns, task);

			task_assign_response(ns, task);
			break;
		}
		case MSG_TASK_RECLAIM:
		{
			struct pack_task_reclaim *pt = (struct pack_task_reclaim *)payload;
			task = find_node_serv_task(ns, pt->taskid);

			node_serv_task_unregister(ns, task);
			node_serv_task_reclaim(task, pt);
			break;
		}
		case MSG_TASK_CONTROL:
		{
			struct pack_task_control *pt = (struct pack_task_control *)payload;
			task = find_node_serv_task(ns, pt->taskid);

			node_serv_task_control(task, pt->opt, pt);
			break;
		}
		default:
			break;
	}
}


static void node_serv_close(void *opaque)
{

}


int node_serv_init(const char *host)
{
	int socket;
	node_serv_t *ns = &node_serv;

	socket = socket_network_client(host, NODE_SERV_LOGIN_PORT, SOCK_STREAM);

	ns->mgr_hand = fdhandler_create(socket, node_serv_handle, node_serv_close, ns);
	ns->task_count = 0;
	ns->nextseq = 0;

	return 0;
}

