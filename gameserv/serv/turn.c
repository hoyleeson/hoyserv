#include <stdio.h>

#include <protos.h>
#include "turn.h"
#include "protos_internal.h"

struct turn_assign_data {
	task_baseinfo_t base;
	group_info_t *group;
};

struct turn_control_data {
	task_baseinfo_t base;
	int opt;
	user_info_t *user;
};


enum turn_control_type {
	TURN_TYPE_USER_JOIN,
	TURN_TYPE_USER_LEAVE,
};


unsigned int turn_task_assign(node_mgr_t *mgr, group_info_t *group)
{
	turn_assign_data data;

	init_taskbase_info(&data.base);
	data.group = group;

	return nodemgr_task_assign(mgr, TASK_TURN, TASK_PRIORITY_NORMAL, &data.base);
}

int turn_task_reclaim(node_mgr_t *mgr, unsigned int handle)
{
	return nodemgr_task_reclaim(mgr, NULL);
}


int turn_task_user_join(node_mgr_t *mgr, unsigned int handle, user_info_t *user)
{
	return nodemgr_task_control(mgr, handle, TURN_TYPE_USER_JOIN, user);
}

int turn_task_user_leave(node_mgr_t *mgr, unsigned int handle, user_info_t *user)
{
	return nodemgr_task_control(mgr, handle, TURN_TYPE_USER_LEAVE, user);
}

static inline int turn_task_control(node_mgr_t *mgr, unsigned int handle, int opt, user_info_t *user)
{
	turn_control_t data;

	data.opt = opt;
	data.user = user;
	return nodemgr_task_control(mgr, &data.base);
}


int turn_task_control(node_mgr_t *mgr, unsigned int handle, int opt, )
{
	return nodemgr_task_control(mgr, NULL);
}


static int create_turn_task_assign(task_baseinfo_t *base, struct pack_task_assign **pkt)
{
	int i = 0;
	int len;
	struct pack_turn_assign *ta;
	struct user_info_t *user;
	struct turn_assign_data *turn = (struct turn_assign_data *)data;
	group_info_t *group = turn->group;

	if(!group)
		return;

	len = sizeof(*ta) + sizeof(client_tuple_t)*turn->cli_count;
	*pkt = (struct pack_task_assign *)malloc(len);
	ta = *pkt;

	ta->groupid = group->groupid;
	ta->cli_count = group->users;

	list_for_each_entry(user, &group->userlist) {
		if(i >= ta->cli_count)
			fatal("group count bug.\n");

		tuple[i].userid = user->userid;
		tuple[i].addr = user->addr;
		i++;
	}

	return len;	
}


static void create_turn_task_reclaim(task_baseinfo_t *base,
	   	struct pack_task_reclaim **pkt)
{
	int len;

	len = sizeof(struct pack_task_reclaim);
	*pkt = (struct pack_task_reclaim *)malloc(len);

	return len;	
}


static void create_turn_task_control(task_baseinfo_t *base,
	   	struct pack_task_control **pkt)
{
	int i = 0;
	int len;
	struct pack_turn_control *tc;
	struct user_info_t *user;
	struct turn_control_data *data = (struct turn_control_data *)base;

	user = data->user;

	len = sizeof(*tc);
	*pkt = (struct pack_task_control *)malloc(len);
	tc = *pkt;

	tc->opt = data->opt;
	tc->tuple.addr = user->addr;

	return len;	
}


struct turn_task {
	uint64_t groupid;
	int cli_count;
	client_tuple_t tuple[GROUP_MAX_USER];
};

static task_t *turn_task_assign_handle(struct pack_task_assign *pkt)
{
	int i;
	struct pack_turn_assign *ta;
	task_t *task;
	struct turn_task *ttask;

	ta = (struct pack_turn_assign *)pkt;

	task = create_task(sizeof(*ttask));
	ttask = &task->priv_data;
	ttask->groupid = ta->groupid;
	ttask->cli_count = ta->cli_count;

	for(i=0; i<ta->cli_count; i++) {
		ttask->tuple[i] = ta->tuple[i];
	}

	return task;
}


static int turn_task_reclaim_handle(task_t *task, struct pack_task_reclaim *pkt)
{
/*	struct pack_turn_reclaim *tr;

	tr = (struct pack_turn_reclaim *)pkt;
*/
	release_task(task);
	return 0;
}

static int turn_task_control_handle(task_t *task, struct pack_task_control *pkt)
{
	struct pack_turn_control *tc;
	struct turn_task *ttask;

	tc = (struct pack_turn_control *)pkt;
	ttask = (struct turn_task *)task->priv_data;

	switch(tc->opt) {
		case TURN_TYPE_USER_JOIN:
			if(ttask->cli_count >= GROUP_MAX_USER)
				return -EINVAL;

			ttask->tuple[ttask->cli_count++] = tc->tuple[0];
			break;
		case TURN_TYPE_USER_LEAVE:
			for(i=0; i<ttask->cli_count; i++) {
				if(ttask->tuple[i].userid == tc->tuple[0].userid) {
					ttask->tuple[i] = ttask->tuple[--ttask->cli_count];
					break;
				}
			}
			break;
		default:
			break;
	}

	return 0;
}


static int turn_task_handle(task_t *task, struct pack_task_req *pack)
{
	struct turn_task *ttask;
	pack_head_t *head;
	int len;

	ttask = &task->priv_data;

	head = create_pack(PACK_, pack->datalen);

	len = sizeof(*head) + pack->datalen;
	memcpy(head->data, pack->data, pack->datalen);

	for(i=0; i<ta->cli_count; i++) {
		if(pack->userid == ttask->userid)
			continue;

		task_worker_send_packet(task, (void *)head, len, ttask->tuple[i].addr);
	}

	return 0;
}

struct task_operations turn_ops = {
	.type = TASK_TURN,

	/* used by node manager only */
	.create_assign_pkt = create_turn_task_assign,
	.create_reclaim_pkt = create_turn_task_reclaim,
	.create_control_pkt = create_turn_task_control,

	/* used by node server only */
	.assign_handle = turn_task_assign_handle,
	.reclaim_handle = turn_task_reclaim_handle,
	.control_handle = turn_task_control_handle,

	.task_handle = turn_task_handle,
};


