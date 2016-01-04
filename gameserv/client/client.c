#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netdb.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include <protos.h>
#include <common/iohandler.h>
#include <common/wait.h>
#include <common/pack.h>
#include <common/sockets.h>
#include <common/log.h>

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


struct client_peer {
	uint32_t taskid;
	fdhandler_t *hand;
	uint16_t nextseq;
	struct sockaddr_in serv_addr;
};

#if 0
struct client_task {
	uint32_t taskid;
	fdhandler_t *hand;
	uint16_t nextseq;
	struct sockaddr_in serv_addr;
};
#endif

enum client_conn_mode {
	MODE_SERV_TURN,
	MODE_CLI_P2P,
};

struct client {	
	uint32_t userid;
	uint32_t groupid;
	int mode;
	event_cb callback;
	response_wait_t waits;
	int running;

	struct client_peer control; 	/* connect with center serv, taskid is invaild */
	struct client_peer task;
};

static struct client _client;


static void *client_pkt_alloc(struct client_peer *peer)
{
	packet_t *packet;

	packet = fdhandler_pkt_alloc(peer->hand);

	return packet->data + pack_head_len();

}

static void client_pkt_send(struct client_peer *peer, int type, void *data, int len)
{
	packet_t *packet;
	pack_head_t *head;

	head = (pack_head_t *)((uint8_t *)data - pack_head_len());
	packet = data_to_packet(head);

	/* init header */
	init_pack(head, type, len);
	head->seqnum = peer->nextseq++;

	packet->len = len + pack_head_len();
	packet->addr = *((struct sockaddr*)&peer->serv_addr);

	fdhandler_pkt_submit(peer->hand, packet);
}


int client_login(void)
{
	int ret;
	int userid;
	void *data;
	struct client *cli = &_client;

	data = client_pkt_alloc(&cli->control);

	client_pkt_send(&cli->control, MSG_CLI_LOGIN, data, 0);

	ret = wait_for_response(&cli->waits, MSG_LOGIN_RESPONSE, 0, &userid);
	if(ret)
		return -EINVAL;

	cli->userid = userid;
	logd("client login success, userid:%u.\n", userid);

	return 0;
}

void client_logout(void)
{
	uint32_t *userid;
	struct client *cli = &_client;

	userid = (uint32_t *)client_pkt_alloc(&cli->control);

	*userid = cli->userid;

	client_pkt_send(&cli->control, MSG_CLI_LOGOUT, userid, sizeof(uint32_t));
}


int client_create_group(int open, const char *name, const char *passwd)
{
	int ret;
	struct client *cli = &_client;
	struct pack_creat_group *p;
	struct pack_creat_group_result result;

	p = (struct pack_creat_group *)client_pkt_alloc(&cli->control);

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

	client_pkt_send(&cli->control, MSG_CLI_CREATE_GROUP, p, sizeof(*p));

	ret = wait_for_response(&cli->waits, MSG_CREATE_GROUP_RESPONSE, 0, &result); /* XXX seq */
	if(ret)
		return -EINVAL;

	cli->groupid = result.groupid;
	cli->task.taskid = result.taskid;
	cli->task.serv_addr = *((struct sockaddr_in*)&result.addr);

	if(cli->mode == CLI_MODE_FULL_FUNCTION) {
		client_task_start(cli->userid, cli->groupid, &cli->task.serv_addr);
	}

	return 0;
}

void client_delete_group(void)
{
	struct pack_del_group *p;
	struct client *cli = &_client;

	p = (struct pack_del_group *)client_pkt_alloc(&cli->control);

	p->userid = cli->userid;

	client_pkt_send(&cli->control, MSG_CLI_DELETE_GROUP, p, sizeof(*p));
}

int client_list_group(int pos, int count, struct group_description *gres, int *rescount)
{
#define RESULT_MAX_LEN 	 	(4000)
	int ret;
	char result[RESULT_MAX_LEN];
	struct pack_list_group *p;
	group_desc_t *gdesc;
	int retlen, ofs = 0;
	struct group_description *gp = gres;
	struct client *cli = &_client;

	p = (struct pack_list_group *)client_pkt_alloc(&cli->control);

	p->userid = cli->userid;
	p->pos = pos;
	p->count = count;

	client_pkt_send(&cli->control, MSG_CLI_LIST_GROUP, p, sizeof(*p));

	ret = wait_for_response_data(&cli->waits, MSG_LOGIN_RESPONSE, 0, 
			result, &retlen); /* XXX */
	if(ret)
		return -EINVAL;

	*rescount = 0;
	/* XXX: current version: group_desc_t equals struct group_description */
	while(ofs < retlen) {
		gdesc = (group_desc_t *)result + ofs;

		gp->groupid = gdesc->groupid;
		gp->flags = gdesc->flags;
		memcpy(gp->name, gdesc->name, gdesc->namelen);
		gp->name[gdesc->namelen] = '\0';

		gp++;
		ofs += sizeof(group_desc_t) + gdesc->namelen;
		(*rescount)++;
	}

	return 0;
}


int client_join_group(struct group_description *group, const char *passwd)
{
	int ret;
	struct pack_join_group *p;
	struct client *cli = &_client;
	struct pack_creat_group_result result;

	p = (struct pack_join_group *)client_pkt_alloc(&cli->control);

	p->userid = cli->userid;
	p->groupid = group->groupid;

	client_pkt_send(&cli->control, MSG_CLI_JOIN_GROUP, p, sizeof(*p));

	ret = wait_for_response(&cli->waits, MSG_LOGIN_RESPONSE, 0, &result); /* XXX */
	if(ret)
		return -EINVAL;

	cli->groupid = result.groupid;
	cli->task.taskid = result.taskid;
	cli->task.serv_addr = *((struct sockaddr_in*)&result.addr);

	if(cli->mode == CLI_MODE_FULL_FUNCTION) {
		client_task_start(cli->userid, cli->groupid, &cli->task.serv_addr);
	}

	return 0;
}


void client_leave_group(void)
{
	struct pack_join_group *p;
	struct client *cli = &_client;

	p = (struct pack_join_group *)client_pkt_alloc(&cli->control);

	p->userid = cli->userid;

	client_pkt_send(&cli->control, MSG_CLI_LEAVE_GROUP, p, sizeof(*p));
}


static void *create_task_req_pack(struct client *cli, int type)
{
	struct pack_task_req *p;

	p = (struct pack_task_req *)client_pkt_alloc(&cli->task);

	p->taskid = cli->task.taskid;
	p->userid = cli->userid;
	p->type = type;

	return &p->data;
}

static void task_req_pack_send(struct client *cli, void *data, int size)
{
	struct pack_task_req *p;
	p = (struct pack_task_req *)((uint8_t *)data - sizeof(struct pack_task_req));

	client_pkt_send(&cli->control, MSG_TASK_REQ, p, sizeof(*p) + size);
}

void client_send_command(void *data, int len)
{
	struct pack_cli_msg *p;
	struct client *cli = &_client;

	if(cli->task.taskid == INVAILD_TASKID) {
		return;	
	}

	p = create_task_req_pack(cli, TASK_TURN);

	p->type = PACK_COMMAND;
	p->datalen = len;
	memcpy(p->data, data, len);

	task_req_pack_send(cli, p, sizeof(*p) + len);
}

void client_send_state_img(void *data, int len)
{
	struct pack_cli_msg *p;
	struct client *cli = &_client;

	if(cli->task.taskid == INVAILD_TASKID) {
		return;	
	}

	p = create_task_req_pack(cli, TASK_TURN);

	p->type = PACK_STATE_IMG;
	p->datalen = len;
	memcpy(p->data, data, len);

	task_req_pack_send(cli, p, sizeof(*p) + len);
}


static void client_hbeat(void)
{
	uint32_t *userid;
	struct client *cli = &_client;

	userid = (uint32_t *)client_pkt_alloc(&cli->control);

	*userid = cli->userid;

	client_pkt_send(&cli->control, MSG_CLI_HBEAT, userid, sizeof(uint32_t));
}


static void cli_msg_handle(void* user, uint8_t *data, int len, void *from)
{
	struct client *cli = user;
	pack_head_t *head;
	void *payload;
	struct sockaddr *cliaddr = from;

	logd("client receive pack. len:%d\n", len);

	if(data == NULL || len < sizeof(*head))
		return;

	dump_data("client receive data", data, len);

	head = (pack_head_t *)data;
	payload = head + 1; 

	logd("pack: type:%d, seq:%d, datalen:%d\n", head->type, head->seqnum, head->datalen);

	if(head->magic != SERV_MAGIC ||
		   	head->version != SERV_VERSION)
		return;

	if(head->type == MSG_CENTER_ACK) {
		//cli_ack_handle(cm, head->seqnum);
	}

	//cli_mgr_send_ack(cm, head);

	switch(head->type) {
		case MSG_LOGIN_RESPONSE:
		{
			uint32_t userid = *(uint32_t *)payload;
			response_post(&cli->waits, head->type, 0, &userid);
			break;
		}
		case MSG_CREATE_GROUP_RESPONSE:
		case MSG_JOIN_GROUP_RESPONSE:
		{
			struct pack_creat_group_result *gres;
			gres = (struct pack_creat_group_result *)payload;

			response_post(&cli->waits, head->type, 0, gres);
			break;
		}
		case MSG_LIST_GROUP_RESPONSE:
		{
			post_response_data(&cli->waits, head->type, 0, payload, head->datalen);
			break;
		}
		case MSG_GROUP_DELETE:
			cli->groupid = INVAILD_GROUPID;
			cli->task.taskid = INVAILD_TASKID;
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
	struct client *cli = &_client;
	
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
		//cli_ack_handle(cm, head->seqnum);
	}

	//cli_mgr_send_ack(cm, head);

	switch(head->type) {
		case MSG_TURN_PACK:
		case MSG_P2P_PACK:
		{
			struct pack_cli_msg *msg = (struct pack_cli_msg *)payload;
			cli_pack_handle(msg);
			break;
		}
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
	struct client *cli = &_client;

    for (;;) {
		if(!cli->running)
			break;

		iohandler_once();
    }

	return 0;
}


int client_task_start(uint32_t userid, uint32_t groupid, struct sockaddr_in *addr)
{
	int sock;
    struct hostent *hp;
	int ret;
	struct client *cli = &_client;

	sock = socket_inaddr_any_server(CLIENT_TASK_PORT, SOCK_DGRAM);

	cli->userid = userid;
	cli->groupid = groupid;

	cli->task.serv_addr = *addr;
	cli->task.nextseq = 0;

	cli->task.hand = fdhandler_udp_create(sock, cli_task_handle, cli_task_close, cli);

	return 0;
}

#define HASH_WAIT_OBJ_CAPACITY 	(256)

int client_init(const char *host, int mode, event_cb callback) 
{
	int sock;
    struct hostent *hp;
	int ret;
	struct sockaddr_in addr; 	/* used for debug */
	int addrlen; 	/* used for debug */
	struct client *cli = &_client;
	pthread_t th;

	iohandler_init();

	response_wait_init(&cli->waits, HASH_WAIT_OBJ_CAPACITY);

	cli->callback = callback;
	cli->mode = mode;
	cli->running = 1;

/*	if(mode == CLI_MODE_CONTROL_ONLY || mode == CLI_MODE_TASK_ONLY) { */
	/* dynamic alloc port by system. */
	sock = socket_inaddr_any_server(0, SOCK_DGRAM);

	if (getsockname(sock, (struct sockaddr*)&addr, &addrlen) < 0) {
		close(sock);
		return -EINVAL;
	}
	logi("bind to %s, %d.\n", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));

	hp = gethostbyname(host);
	if(hp == 0){
		cli->control.serv_addr.sin_addr.s_addr = inet_addr(host);
	} else 
		memcpy(&cli->control.serv_addr.sin_addr, hp->h_addr, hp->h_length);

	cli->control.serv_addr.sin_family = AF_INET;
	cli->control.serv_addr.sin_port = htons(CLIENT_LOGIN_PORT);
	cli->control.nextseq = 0;
	cli->userid = INVAILD_USERID;
	cli->groupid = INVAILD_GROUPID;

	cli->control.hand = fdhandler_udp_create(sock,
			cli_msg_handle, cli_msg_close, cli);
/*	} */

	ret = pthread_create(&th, NULL, client_thread_handle, cli);
	if(ret)
		return ret;

	return 0;
}

int client_state_serialize(struct cli_context_state *state)
{
	struct client *cli = &_client;

	state->userid = cli->userid;
	state->groupid = cli->groupid;
	state->addr = cli->task.serv_addr;

	return 0;
}

int client_state_deserialize(void *data, struct cli_context_state *state)
{
	struct cli_context_state *s;

	s = (struct cli_context_state *)data;

	*state = *s;
	return 0;
}


