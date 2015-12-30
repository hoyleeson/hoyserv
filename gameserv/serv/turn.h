#ifndef _SERV_TURN_H_
#define _SERV_TURN_H_

struct turn_info
{
	uint32_t taskid;
	struct sockaddr addr;
};

unsigned long turn_task_assign(node_mgr_t *mgr, group_info_t *group);
int turn_task_reclaim(node_mgr_t *mgr, unsigned long handle);
int turn_task_control(node_mgr_t *mgr, unsigned long handle, int opt, user_info_t *user);

int get_turn_info(node_mgr_t *mgr, unsigned long handle, struct turn_info *info);

static inline int turn_task_user_join(node_mgr_t *mgr, unsigned long handle, user_info_t *user)
{
	return turn_task_control(mgr, handle, TURN_TYPE_USER_JOIN, user);
}

static inline int turn_task_user_leave(node_mgr_t *mgr, unsigned long handle, user_info_t *user)
{
	return turn_task_control(mgr, handle, TURN_TYPE_USER_LEAVE, user);
}


#endif

