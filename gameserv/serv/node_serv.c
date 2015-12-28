#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>

#include <common/iohandler.h>

#define WORKER_MAX_TASK_COUNT 	(512)


typedef struct _task_worker {
	fdhandler_t *hand;
	int port;

	int task_count;
	struct Hashmap tasks_map; 	/*key: task id*/

	struct listnode node;
} task_worker_t;


struct task {
	int taskid;
	int type;
	int priority;
	task_worker_t *worker;
	uint8_t priv_data[0];
};

/* ns: node server */

typedef struct _node_serv {
	int worker_count;
	struct listnode worker_list;
	fdhandler_t *mgr_hand;

	int task_count;
	task_worker_t *suit_worker;
} node_serv_t;

static node_serv_t node_serv;


task_t *create_task(int priv_size)
{
	task_t *task;

	task = malloc(sizeof(*task) + priv_size);
	return task;
}

static void release_task(task_t *task) 
{
	free(task);
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
	list_for_each_entry(pos, ns, node) {
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


task_t find_node_serv_task(int taskid)
{
	task_t *task;
	task_worker_t *worker;

	list_for_each_entry(worker, ns, node) {
		task = hashmapGet(worker->tasks_map, taskid);
		if(task) {
			return task;
		}
	}

	return NULL;
}

/*XXX*/
static int task_req_handle(struct pack_task_req *pack)
{
	struct task_operations *ops;

	ops = find_task_protos_by_type(pack->type);
	if(!ops)
		return -EINVAL;

	task = find_node_serv_task(pack->taskid);
	if(!task)
		return -EINVAL;

	return ops->task_handle(task, pack);
}


int task_worker_send_packet(task_t *task, void *data, int len, struct sockaddr *to)
{
	task_worker_t *worker = task->worker;

	fdhandler_sendto(worker->hand, data, len, to);
}


static void task_worker_handle(void *opaque, uint8_t *data, int len)
{
	int ret;
	task_worker_t *worker = (task_worker_t *)opaque;
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
		case MSG_TASK_REQ:
			struct pack_task_req *pack = (struct pack_task_req *)payload;
			task_req_handle(pack);
			break;
		default:
			break;
	}
}


static void task_worker_close(task_worker_t *worker)
{

}

#define HASH_WORKER_CAPACITY 	(256)

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
		close(m_sock);
		return NULL;
	}

	tworker = malloc(sizeof(*tworker));
	if(!tworker)
		goto out;

	tworker->port = ntohs(addr.sin_port);
	tworker->task_count = 0;

	tworker->hand = fdhandler_udp_create(sock, task_worker_handle,
		   	task_worker_close, tworker);
	tworker->tasks_map = hashmapCreate(HASH_WORKER_CAPACITY, int_hash, int_equals);

	list_add_tail(&ns->worker_list, &tworker->node);
out:
	return tworker;
}

static void free_task_worker(task_worker_t *worker) 
{

}


static task_t *node_serv_task_assign(struct pack_task_assign *pa)
{
	struct task_operations *ops;

	ops = find_task_protos_by_type(task->type);
	if(!ops)
		return -EINVAL;

	task = ops->assign_handle(pkt);

	task->taskid = taskid;
	task->type = type;
	task->priority = priority;

	return task;
}

static int node_serv_task_reclaim(task_t *task, struct pack_task_reclaim *pr)
{
	struct task_operations *ops;

	ops = find_task_protos_by_type(task->type);
	if(!ops)
		return -EINVAL;

	return ops->reclaim_handle(task, pkt);
}

static int node_serv_task_control(task_t *task, struct pack_task_control *pc)
{
	struct task_operations *ops;

	ops = find_task_protos_by_type(task->type);
	if(!ops)
		return -EINVAL;

	return ops->control_handle(task, pkt);
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

	if(head->magic != TURN_SERV_MAGIC ||
		   	head->version != TURN_VERSION)
		return;

	switch(head->type) {
		case MSG_TASK_ASSIGN:
			struct pack_task_assign *ta = (struct pack_task_assign *)payload;

			task = node_serv_task_assign(ta);
			node_serv_task_register(ns, task);
			break;
		case MSG_TASK_RECLAIM:
			struct pack_task_reclaim *tr = (struct pack_task_reclaim *)payload;

			task = find_node_serv_task(tr->taskid);
			node_serv_task_unregister(ns, task);
			node_serv_task_reclaim(task, tr);
			break;
		case MSG_TASK_CONTROL:
			struct pack_task_control *tc = (struct pack_task_control *)payload;

			task = find_node_serv_task(tr->taskid);
			node_serv_task_control(task, tc);
			break;
	}

}

static void node_serv_close(node_serv_t *ns)
{

}


int node_serv_init(const char *host)
{
	int socket;
	node_serv_t *ns = &node_serv;

	socket = socket_network_client(host, CENTER_SERV_NODE_PORT, SOCK_STREAM);

	ns->mgr_hand = fdhandler_create(socket, node_serv_handle, node_serv_close, ns);
	ns->task_count = 0;

	ns->task_hand = fdhandler_create();

	return 0;
}

