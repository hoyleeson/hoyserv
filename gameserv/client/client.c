#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netdb.h>

#include <protos.h>
#include <common/iohandler.h>

#include "client.h"

#define FRAGMENT_MAX_LEN 	(512)

struct pack_cli_msg {
	struct pack_task_req base;

	uint8_t type;
	uint8_t frag:1;
	uint8_t frag_count:7;
	uint16_t frag_offset;
	uint8_t seq;
	uint32_t datalen;
	uint8_t data[0];
};


struct client_control {
	fdhandler_t *hand;
	uint16_t nextseq;
	struct sockaddr_in serv_addr;
};


struct client_task {
	fdhandler_t *hand;
	uint16_t nextseq;
	struct sockaddr_in serv_addr;
};

enum client_mode {
	MODE_SERV_TURN,
	MODE_CLI_P2P,
};

struct client {	
	uint64_t userid;
	uint64_t groupid;
	int mode;
	event_cb callback;
	struct client_control control;
	struct client_task task;
};

static struct client _client;

static pack_head_t *create_pack(uint8_t type, uint32_t len)
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


static void client_send_pack(pack_head_t *pkt) 
{
	struct client *cli = _client;
	
	int len = sizeof(pack_head_t) + pkt->datalen;
	pkt->seqnum = cli->control.nextseq++;
	
	fdhandler_sendto(cli->control.hand, (const uint8_t *)pkt, len,
		   	&cli->control.serv_addr);
}


int client_login(void)
{
	pack_head_t *pack;
	struct client *cli = _client;

	pack = create_pack(MSG_CLI_LOGIN, 0);

	client_send_pack(pack);

	wait();

	cli->userid = userid;

	return 0;
}

void client_logout(void)
{
	pack_head_t *pack;
	struct client *cli = _client;

	pack = create_pack(MSG_CLI_LOGOUT, sizeof(uint64_t));
	*(uint64_t *)pack->data = cli->userid;

	client_send_pack(pack);
}


int client_create_group(int open, const char *name, const char *passwd)
{
	pack_head_t *pack;
	struct client *cli = _client;
	struct pack_creat_group *p;

	pack = create_pack(MSG_CLI_CREATE_GROUP, sizeof(*p));
	p = (struct pack_creat_group *)pack->data;
	p->userid = cli->userid;
	p->flags = 0;
	if(open)
		p->flags |= GROUP_TYPE_OPENED;

	if(name)
		strncpy(p->name, name, GROUP_NAME_MAX);

	if(passwd) {
		p->flags |= GROUP_TYPE_NEED_PASSWD;
		strncpy(p->passwd, passwd, GROUP_PASSWD_MAX);
	}

	client_send_pack(pack);

	cli->groupid = groupid;
	return 0;
}

void client_delete_group(void)
{
	pack_head_t *pack;
	struct pack_del_group *p;
	struct client *cli = _client;

	pack = create_pack(MSG_CLI_DELETE_GROUP, sizeof(*p));
	p = (struct pack_creat_group *)pack->data;

	p->userid = cli->userid;

	client_send_pack(pack);
}

int client_list_group(group_t *group)
{
	pack_head_t *pack;
	struct pack_del_group *p;
	struct client *cli = _client;

	pack = create_pack(MSG_CLI_LIST_GROUP, sizeof(*p));
	p = (struct pack_creat_group *)pack->data;

	p->userid = cli->userid;

	client_send_pack(pack);
	wait();
	
}


void client_join_group(group_t *group, const char *passwd)
{
	pack_head_t *pack;
	struct pack_join_group *p;
	struct client *cli = _client;

	pack = create_pack(MSG_CLI_JOIN_GROUP, sizeof(*p));
	p = (struct pack_creat_group *)pack->data;

	p->userid = cli->userid;
	p->groupid = group->groupid;

	client_send_pack(pack);
}


void client_leave_group(void)
{
	pack_head_t *pack;
	struct pack_join_group *p;
	struct client *cli = _client;

	pack = create_pack(MSG_CLI_LEAVE_GROUP, sizeof(*p));
	p = (struct pack_creat_group *)pack->data;

	p->userid = cli->userid;

	client_send_pack(pack);
}


static pack_head_t *create_task_req_pack(int type, uint32_t priv_size)
{
	pack_head_t *pack;
	struct client *cli = _client;
	struct pack_task_req *p;

	pack = create_pack(MSG_TASK_REQ, priv_size);
	p = (struct pack_creat_group *)pack->data;

	p->taskid = cli->task.taskid;
	p->userid = cli->userid;
	p->type = type;
	return pack;
}

void client_send_command(void *data, int len)
{
	pack_head_t *pack;
	struct pack_cli_msg *p;

	pack = create_task_req_pack(TASK_TURN, sizeof(*p)+len);
	p = (struct pack_creat_group *)pack->data;

	p->type = PACK_COMMAND;
	p->datalen = len;
	memcpy(p->data, data, len);

	client_send_pack(pack);
}

void client_send_state_img(void *data, int len)
{
	pack_head_t *pack;
	struct pack_cli_msg *p;

	pack = create_task_req_pack(TASK_TURN, sizeof(*p)+len);
	p = (struct pack_creat_group *)pack->data;

	p->type = PACK_STATE_IMG;
	p->datalen = len;
	memcpy(p->data, data, len);

	client_send_pack(pack);
}


static void client_hbeat(struct group_t *group)
{
	pack_head_t *pack;
	struct pack_del_group *p;

	pack = create_pack(MSG_CLI_HBEAT, sizeof(*p));

	client_send_pack(pack);
}


static void cli_msg_handle(void* user, uint8_t *data, int len, void *from)
{
	struct client *cli = user;
	pack_head_t *head;
	void *payload;
	struct sockaddr *cliaddr = from;

	if(data == NULL || len < sizeof(*head))
		return;

	head = (pack_head_t *)data;
	payload = head + 1; 

	if(head->magic != SERV_MAGIC ||
		   	head->version != SERV_VERSION)
		return;

	if(head->type == MSG_CENTER_ACK) {
		cli_ack_handle(cm, head->seqnum);
	}

	cli_mgr_send_ack(cm, head);

	switch(head->type) {
		case MSG_LOGIN_RESULT:
			break;
		case MSG_LIST_GROUP_RESULT:
			break;
		case MSG_HANDLE_ERR:
			break;
		default:
			break;
	}
	
	return;
}

static void cli_msg_close(void *user)
{
}

static void pack_command_handle(struct pack_cli_msg *msg) 
{
	int ret;
	struct client *cli = _client;
	
	ret = cli->callback(EVENT_COMMAND, (void *)msg->data, (void *)msg->datalen);
	if(ret) {
		loge("client handle fail.\n");	
	}
}

static void pack_state_img_handle(struct pack_cli_msg *msg) 
{
	/*XXX*/
}

static void cli_pack_handle(struct pack_cli_msg *msg) 
{
	switch(msg->type) {
		case PACK_COMMAND:
			pack_command_handle(msg);
			break;
		case PACK_STATE_IMG:
			pack_state_img_handle(msg);
			break;
		default:
			break;
	}
}

static void cli_task_handle(void* user, uint8_t *data, int len, void *from)
{
	struct client *cli = user;
	pack_head_t *head;
	void *payload;
	struct sockaddr *cliaddr = from;

	if(data == NULL || len < sizeof(*head))
		return;

	head = (pack_head_t *)data;
	payload = head + 1; 

	if(head->magic != SERV_MAGIC ||
		   	head->version != SERV_VERSION)
		return;

	if(head->type == MSG_CENTER_ACK) {
		cli_ack_handle(cm, head->seqnum);
	}

	cli_mgr_send_ack(cm, head);

	switch(head->type) {
		case MSG_TURN_PACK:
		case MSG_P2P_PACK:
			struct pack_cli_msg *msg = (struct pack_cli_msg *)payload;
			cli_pack_handle(msg);
			break;
		default:
			break;
	}
	
	return;
}

static void cli_task_close(void *user)
{
}


static void *client_thread_handle(void *args)
{
	iohandler_loop();
	return 0;
}


int client_task_start(const char *host, int port, uint64_t userid, uint64_t groupid)
{
	int taskfd;
    struct hostent *hp;
	int ret;
	struct client *cli = &_client;

	taskfd = socket_inaddr_any_server(port, SOCK_DGRAM);

    hp = gethostbyname(host);
    if(hp == 0){
		cli->task.serv_addr.sin_addr.s_addr = inet_addr(host);
	} else 
		memcpy(&cli->task.serv_addr.sin_addr, hp->h_addr, hp->h_length);

	cli->task.serv_addr.sin_family = AF_INET;
    cli->task.serv_addr.sin_port = htons(CENTER_SERV_CLI_PORT);
	cli->task.nextseq = 0;
	cli->userid = userid;
	cli->groupid = userid;

	cli->task.hand = fdhandler_udp_create(cli->fd, cli_task_handle, cli_task_close, cli);

	return 0;
}

int client_init(const char *host, int mode) 
{
	int ctlfd;
    struct hostent *hp;
	int ret;
	struct client *cli = &_client;
	pthread th;

	iohandler_init();

	ret = pthread_create(&th, NULL, client_thread_handle, cli);
	if(ret)
		return ret;

	if(mode == CLI_MODE_CONTROL_ONLY || mode == CLI_MODE_TASK_ONLY) {
		ctlfd = socket_inaddr_any_server(CLI_LISTEN_PORT, SOCK_DGRAM);

		hp = gethostbyname(host);
		if(hp == 0){
			cli->control.serv_addr.sin_addr.s_addr = inet_addr(host);
		} else 
			memcpy(&cli->control.serv_addr.sin_addr, hp->h_addr, hp->h_length);

		cli->control.serv_addr.sin_family = AF_INET;
		cli->control.serv_addr.sin_port = htons(CENTER_SERV_CLI_PORT);
		cli->control.nextseq = 0;
		cli->userid = INVAILD_USERID;
		cli->groupid = INVAILD_GROUPID;

		cli->control.hand = fdhandler_udp_create(cli->control.fd,
				cli_msg_handle, cli_msg_close, cli);
	}
	return 0;
}


