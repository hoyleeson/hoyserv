#include <stdio.h>

#include <protos.h>
#include "turn.h"
#include "protos_internal.h"


static int create_task_turn_assign(void *data, struct pack_task_assign **pkt)
{
	int i = 0;
	int len;
	struct pack_turn_assign *ta;
	struct user_info_t *user;
	task_turn_t *turn = (task_turn_t *)data;
	group_info_t *group = turn->group;

	if(!group)
		return;

	len = sizeof(*ta) + sizeof(client_tuple_t)*turn->cli_count;
	*pkt = (struct pack_task_assign *)malloc(len);
	ta = &(*pkt)->data;

	ta->groupid = group->groupid;
	ta->cli_count = group->users;

	list_for_each_entry(user, &group->userlist) {
		if(i >= ta->cli_count)
			fatal("group count bug.\n");

		tuple[i].addr = user->addr;
		i++;
	}

	return len;	
}


static void create_task_turn_reclaim(void *data, struct pack_task_reclaim **pkt)
{
	int i = 0;
	int len;
	struct pack_turn_reclaim *tr;
	struct user_info_t *user;
	task_turn_t *turn = (task_turn_t *)data;
	group_info_t *group = turn->group;

	if(!group)
		return;

	len = sizeof(*tr);
	*pkt = (struct pack_task_reclaim *)malloc(len);
	tr = &(*pkt)->data;

	tr->groupid = group->groupid;
	return len;	
}


static void create_task_turn_control(void *data, struct pack_task_control **pkt)
{
	int i = 0;
	int len;
	struct pack_turn_control *tr;
	struct user_info_t *user;
	task_turn_t *turn = (task_turn_t *)data;
	group_info_t *group = turn->group;

	if(!group)
		return;

	len = sizeof(*tr);
	*pkt = (struct pack_task_control *)malloc(len);
	tr = &(*pkt)->data;

	tr->groupid = group->groupid;

	return len;	
}

static int task_turn_assign_handle(void *data, struct pack_task_assign *pkt)
{
	struct pack_turn_assign *ta;

	ta = (struct pack_turn_assign *)pkt;

	return 0;
}


static int task_turn_reclaim_handle(void *data, struct pack_task_reclaim *pkt)
{
	struct pack_turn_reclaim *ta;

	tr = (struct pack_turn_reclaim *)pkt;

	return 0;
}

static int task_turn_control_handle(void *data, struct pack_task_control *pkt)
{
	struct pack_turn_control *ta;

	tc = (struct pack_turn_control *)pkt;


	return 0;
}

static int task_turn_handle()
{

}

struct task_operations {
	.type = TASK_TURN,

	/* used by node manager only */
	.create_assign_pkt = create_task_turn_assign,
	.create_reclaim_pkt = create_task_turn_reclaim,
	.create_control_pkt = create_task_turn_control,

	/* used by node server only */
	.assign_handle = task_turn_assign_handle,
	.reclaim_handle = task_turn_reclaim_handle,
	.control_handle = task_turn_control_handle,

	.task_handle = task_turn_handle,
};


