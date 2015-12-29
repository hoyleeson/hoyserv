#ifndef _SERV_TURN_H_
#define _SERV_TURN_H_

unsigned long turn_task_assign(node_mgr_t *mgr, group_info_t *group);
int turn_task_reclaim(node_mgr_t *mgr, unsigned int handle);
int turn_task_control(node_mgr_t *mgr, unsigned int handle, int opt, user_info_t *user);

struct sockaddr *get_turn_serv_addr(node_mgr_t *mgr, unsigned int handle);

static inline int turn_task_user_join(node_mgr_t *mgr, unsigned int handle, user_info_t *user)
{
	return turn_task_control(mgr, handle, TURN_TYPE_USER_JOIN, user);
}

static inline int turn_task_user_leave(node_mgr_t *mgr, unsigned int handle, user_info_t *user)
{
	return turn_task_control(mgr, handle, TURN_TYPE_USER_LEAVE, user);
}


#endif

