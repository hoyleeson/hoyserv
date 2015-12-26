#ifndef _CONN_CLI_MGR_H_
#define _CONN_CLI_MGR_H_

#include <common/list.h>
#include <common/hashmap.h>

#include <protos.h>

typedef struct _user_info user_info_t;
typedef struct _group_info group_info_t;

enum user_state {
	USER_STATE_FREE,
	USER_STATE_LOGIN,
};

#define HBEAT_INIT 		(5)

struct _user_info {
	uint64_t userid;
	int state;
	struct sockaddr addr;
	group_info_t *group;
	int heard;

	struct listnode node;
};

#define GROUP_MAX_USER 		(8)

struct _group_info {
	uint64_t groupid;
	uint16_t flags;
	char name[GROUP_NAME_MAX];
	char passwd[GROUP_PASSWD_MAX];

	int users;
	struct listnode userlist;
	unsigned int worker_handle;
};

typedef _cli_mgr {
	uint64_t uid_pool; 	/* user id pool */
	uint64_t rid_pool; 	/* group id pool */
	fdhandler_t *hand;

	Hashmap *user_map;
	Hashmap *group_map;
	int user_count;
	int group_count;

	uint16_t nextseq;
	struct listnode group_list;
} cli_mgr_t;

#endif

