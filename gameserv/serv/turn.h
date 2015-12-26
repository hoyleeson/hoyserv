#ifndef _TURN_SERV_TURN_H_
#define _TURN_SERV_TURN_H_

typedef struct _task_turn {
	task_info_t task;
	group_info_t *group;
} task_turn_t;


enum turn_control_type {
	TURN_TYPE_ADDUSER,
	TURN_TYPE_DELUSER,
};

#endif
