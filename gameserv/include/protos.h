#ifndef _TURN_PROTOS_H_
#define _TURN_PROTOS_H_

#include <stdint.h>

#define SERV_MAGIC 			(0x2016)	
#define SERV_VERSION 		(1)

#define CENTER_SERV_CLI_PORT 	(8123)

#define CLI_CONTROL_LISTEN_PORT 	(8124)
//#define CLI_TASK_LISTEN_PORT 		(8125)

#define INVAILD_USERID 		(~0LL)
#define INVAILD_GROUPID 	(~0LL)

/*client  ---->  center server */
enum cli_center_msg_type {
	MSG_CLI_ACK,
	MSG_CLI_HBEAT,
	MSG_CLI_LOGIN,
	MSG_CLI_LOGOUT,

	MSG_CLI_CREATE_GROUP,
	MSG_CLI_DELETE_GROUP,
	MSG_CLI_LIST_GROUP,
	MSG_CLI_JOIN_GROUP,
	MSG_CLI_LEAVE_GROUP,
};

/* center server ----> client */
enum center_cli_msg_type {
	MSG_CENTER_ACK,
	MSG_LOGIN_RESULT,
	MSG_LIST_GROUP_RESULT,
	MSG_HANDLE_ERR,
};

enum {
	MSG_TASK_REQ,
	MSG_TURN_PACK,
};

/* client A <----------> client B */
enum client_msg_type {
	PACK_COMMAND = 1,
	PACK_STATE_IMG,
};

typedef struct _pack_header {
	uint16_t magic;
	uint8_t version;
	uint8_t type;
	uint16_t seqnum;
	uint8_t _reserved1;
	uint8_t _reserved2;
	uint32_t datalen;
	uint8_t data[0];
}__attribute__((packed)) pack_head_t;

#define GROUP_NAME_MAX 		(32)
#define GROUP_PASSWD_MAX 	(32)

#define GROUP_TYPE_NEED_PASSWD 	(1 << 0)
#define GROUP_TYPE_OPENED 		(1 << 1)

struct pack_creat_group {
	uint32_t userid;
	uint16_t flags;
	uint8_t name[GROUP_NAME_MAX];
	uint8_t passwd[GROUP_PASSWD_MAX];
};

struct pack_del_group {
	uint32_t userid;
};

struct pack_list_group {
	uint32_t userid;
};

struct pack_join_group {
	uint32_t userid;
	uint32_t groupid;

	uint8_t passwd[GROUP_PASSWD_MAX];
};

struct pack_leave_group {
	uint32_t userid;
};


struct pack_creat_group_result {
	uint32_t taskid;
	struct sockaddr addr;
};


/* send to node server */
struct pack_task_req {
	uint32_t taskid;
	uint32_t userid;
	uint8_t type;
	uint32_t datalen;
	uint8_t data[0];
};

typedef struct _user {

} user_t;


typedef struct _group {
	uint32_t groupid;
	uint16_t flags;
	uint32_t namelen;
	char name[0];
} group_t;



static inline pack_head_t *create_pack(uint8_t type, uint32_t len)
{
	pack_head_t *pack;
	pack = malloc(sizeof(*pack) + size);	
	if(!pack)
		return NULL;

	pack->magic = SERV_MAGIC;
	pack->version = SERV_VERSION;

	pack->type = type;
	pack->datalen = len;
	return pack;
}

static inline void free_pack(pack_head_t *pack)
{
	free(pack);
}


#endif


