#ifndef _TURN_PROTOS_INTERNAL_H_
#define _TURN_PROTOS_INTERNAL_H_

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

struct pack_task_assign {
	int8_t type;
	uint8_t data[0];
};

struct pack_task_reclaim {
	int8_t type;
	uint8_t data[0];
};

struct pack_task_control {
	int8_t type;
	uint8_t data[0];
};

typedef struct _client_tuple {
	struct sockaddr ip;
} client_tuple_t;


struct pack_turn_assign {
	struct pack_task_assign base;
	uint64_t groupid;
	int cli_count;
	client_tuple_t tuple[0];
};

struct pack_turn_reclaim {
	struct pack_task_reclaim base;
	uint64_t groupid;
};

struct pack_turn_change {
	struct pack_task_config base;
	int type;
	uint64_t groupid;
	int cli_count;
	client_tuple_t tuple[0];
};


#endif
