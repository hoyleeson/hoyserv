#ifndef _SERV_PROTOS_INTERNAL_H_
#define _SERV_PROTOS_INTERNAL_H_

#define CENTER_SERV_NODE_PORT 	(9123)


/* node server ------> center server */
enum node_center_msg_type {
	/* 
	 * MSG_NODE_REGISTER,
	 * MSG_NODE_UNREGISTER, 
	 */
	MSG_TASK_ASSIGN_RESULT,
};

/* center server ----> node server */
enum center_node_msg_type {
	MSG_TASK_ASSIGN,
	MSG_TASK_RECLAIM,
	MSG_TASK_CONTROL,
};

enum task_type {
	TASK_TURN,
}

#define TASK_PRIORITY_MIN 		(0)
#define TASK_PRIORITY_MAX 		(8)
#define TASK_PRIORITY_NORMAL 	TASK_PRIORITY_MIN

#if 0
struct pack_task_assign {
	uint32_t taskid;
	uint8_t type;
	uint8_t priority;
	uint8_t data[0];
};

struct pack_task_reclaim {
	uint32_t taskid;
	uint8_t type;
	uint8_t data[0];
};

struct pack_task_control {
	uint32_t taskid;
	uint8_t type;
	uint8_t data[0];
};
#endif

struct pack_task_base {
	uint32_t taskid;
	uint8_t type;
	uint8_t data[0];
};


typedef struct _client_tuple {
	uint32_t userid;
	struct sockaddr addr;
} client_tuple_t;


struct pack_turn_assign {
	struct pack_task_base base;
	uint32_t groupid;
	int cli_count;
	client_tuple_t tuple[0];
};

struct pack_turn_reclaim {
	struct pack_task_base base;
};

struct pack_turn_control {
	struct pack_task_base base;
	int opt;
	client_tuple_t tuple;
};


#endif
