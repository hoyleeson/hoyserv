#include <stddef.h>
#include <common/log.h>

static int create_cli_mgr_channel(void)
{
	return socket_inaddr_any_server(CLI_CONN_PORT, SOCK_DGRAM);
}

static pack_head_t *create_pack(uint8_t type, uint32_t size)
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


static int cli_mgr_send_pack(cli_mgr_t *cm, pack_head_t *pkt, void *to)
{
	int len = sizeof(pack_head_t) + pkt->datalen;
	pkt->seqnum = cm->nextseq++;

	fdhandler_sendto(cm->hand, (const uint8_t *)pkt, len, to);

	return 0;
}

static inline int cli_mgr_alloc_uid(cli_mgr_t *cm)
{
	return cm->uid_pool++;
}

static inline int cli_mgr_alloc_rid(cli_mgr_t *cm)
{
	return cm->rid_pool++;
}

static int cli_ack_handle(cli_mgr_t *cm, uint16_t seqnum)
{

}

static int cmd_login_handle(cli_mgr_t *cm, struct sockaddr *from)
{
	user_info_t *uinfo;

	uinfo = malloc(sizeof(*uinfo));
	if(!uinfo)
		return -EINVAL;

	uinfo->userid = cli_mgr_alloc_uid(cm);
	uinfo->addr = *from;
	uinfo->group = NULL;
	uinfo->state = 0;
	uinfo->head = HBEAT_INIT;

	cm->user_count++;
	hashmapPut(cm->user_map, &uinfo->userid, uinfo);
	return 0;
}

static int cmd_logout_handle(cli_mgr_t *cm, uint64_t uid)
{
	user_info_t *uinfo;
	uinfo = hashmapRemove(cm->user_map, &uid);
	if(!uinfo)
		return -EINVAL;

	cm->user_count--;

	if(uinfo->group != NULL) {
		exit_from_group(); /*XXX*/
	}
	free(uinfo);
	return 0;
}

static int cmd_create_group_handle(cli_mgr_t *cm, struct pack_creat_group *pr)
{
	group_info_t *ginfo;
	user_info_t *creater;

	creater = hashmapGet(cm->user_map, &pr->userid);
	if(!creater)
		return -EINVAL;

	ginfo = malloc(sizeof(*ginfo));
	if(!uinfo)
		return -EINVAL;

	ginfo->groupid = cli_mgr_alloc_rid(cm);
	ginfo->flags = pr->flags;
	list_init(ginfo->userlist);

	strncpy(ginfo->name, pr->name, GROUP_NAME_MAX);

	if(ginfo->flags & GROUP_TYPE_NEED_PASSWD)
		strncpy(ginfo->passwd, pr->passwd, GROUP_PASSWD_MAX);

	list_add_tail(&ginfo->userlist, &creater->node);
	ginfo->users++;
	cm->group_count++;
	hashmapPut(cm->group_map, &ginfo->groupid, ginfo);
	return 0;
}


static int cmd_delete_group_handle(cli_mgr_t *cm, struct pack_del_group *pr)
{
	group_info_t *ginfo;
	user_info_t *creater;

	ginfo = hashmapRemove(cm->group_map, &ginfo->groupid);
	if(!ginfo)
		return -EINVAL;

	cm->group_count--;
	creater = node_to_item(list_head, user_info_t, node);
	if(creater->userid != pr->userid) {
		return -EINVAL;
	}

	/*XXX notify node server and user */
	free(ginfo);
	return 0;
}

struct group_list_tmp {
	int count;
	
	int index;
	uint8_t data[4000];
};

static bool hash_entry_cb(void* key, void* value, void* context)
{
	group_t *group;
	group_info_t *ginfo = (group_info_t *)value;
	struct group_list_tmp *rtmp = (struct group_list_tmp *)context;

	group = (group_t *)(data + index);
	group->groupid = ginfo->groupid;
	group->flags = ginfo->flags;
	group->namelen = strlen(ginfo->name);

	strncpy(group->name, ginfo->name, GROUP_NAME_MAX);
	rtmp->index += (sizeof(group_t) + group->namelen);
	rtmp->count++;
	
	return true;
}


static int cmd_list_group_handle(cli_mgr_t *cm, struct pack_list_group *pr)
{
	user_info_t *uinfo;
	struct group_list_tmp rtmp;

	uinfo = hashmapGet(cm->user_map, &pr->userid);
	if(!uinfo)
		return -EINVAL;

	rtmp.index = 0;
	rtmp.count = 0;
	hashmapForEach(cm->group_map, hash_entry_cb, &rtmp);

	send
	return i;
}


static int cmd_join_group_handle(cli_mgr_t *cm, struct pack_join_group *pr)
{
	user_info_t *uinfo;
	group_info_t *ginfo;

	uinfo = hashmapGet(cm->user_map, &pr->userid);
	if(!uinfo)
		return -EINVAL;

	group = hashmapGet(cm->group_map, &pr->groupid);
	if(!group)
		return -EINVAL;

	uinfo->group = group;
	list_add_tail(&ginfo->userlist, &uinfo->node);
	ginfo->users++;

	return 0;
}


static int cmd_leave_group_handle(cli_mgr_t *cm, struct pack_leave_group *pr)
{
	user_info_t *uinfo;
	group_info_t *ginfo;

	uinfo = hashmapGet(cm->user_map, &pr->userid);
	if(!uinfo)
		return -EINVAL;

	ginfo = uinfo->group;
	if(ginfo != NULL) 
		return -EINVAL;

	ginfo->users--;
	list_remove(uinfo->node);
	
	leave_group();

	/*XXX notify node server and user */
	free(ginfo);
}

static int cmd_hbeat_handle(cli_mgr_t *cm)
{
	user_info_t *uinfo;

	uinfo = hashmapPut(cm->user_map, &pr->userid);
	if(!uinfo)
		return -EINVAL;

	uinfo->heard = HBEAT_INIT;
	return 0;
}


static void cli_mgr_handle(void *opaque, uint8_t *data, int len, void *from)
{
	int ret;
	cli_mgr_t *cm = (conn_serv_t *)opaque;
	pack_head_t *head;
	void *payload;
	struct sockaddr *cliaddr = from;

	if(data == NULL || len < sizeof(*head))
		return;

	head = (pack_head_t *)data;
	payload = head + 1; 

	if(head->magic != TURN_SERV_MAGIC ||
		   	head->version != TURN_VERSION)
		return;

	if(head->type == MSG_CLI_ACK) {
		cli_ack_handle(cm, head->seqnum);
	}

	cli_mgr_send_ack(cm, head);

	switch(head->type) {
		case MSG_CLI_LOGIN:
			//uint64_t id = period; /*XXX*/
			ret = cmd_login_handle(cm, addr);
			break;
		case MSG_CLI_LOGOUT:
			uint64_t uid = *(uint64_t *)period;
			ret = cmd_logout_handle(cm, uid);
			break;
		case MSG_CLI_CREATE_GROUP:
			ret = cmd_create_group_handle(cm, (struct pack_creat_group *)payload);
			break;
		case MSG_CLI_DELETE_GROUP:
			ret = cmd_delete_group_handle(cm, (struct pack_del_group *)payload);
			break;
		case MSG_CLI_LIST_GROUP:
			ret = cmd_list_group_handle(cm, (struct pack_list_group *)payload);
			break;
		case MSG_CLI_JOIN_GROUP:
			ret = cmd_join_group_handle(cm, (struct pack_join_group *)payload);
			break;
		case MSG_CLI_LEAVE_GROUP:
			ret = cmd_leave_group_handle(cm, (struct pack_leave_group *)payload);
			break;
		case MSG_CLI_HBEAT:
			ret = cmd_hbeat_handle(cm);
			break;
		default:
			logw("unknown packet. type:%d\n", head->type);
			break;
	}

	if(ret) {
		logw("packet handle fatal. type:%d\n", head->type);
	}
}


static void cli_mgr_close(void *opaque)
{

}


#define ID_FRIST_NUM 	(1)

#define HASH_USER_CAPACITY 		(256)
#define HASH_GROUP_CAPACITY 		(256)

static int int64_hash(void *key)
{
	return hashmapHash(key, sizeof(int64_t));
}

static bool int64_equals(void* keyA, void* keyB) 
{
	int64_t a = *(int64_t *)keyA;
	int64_t b = *(int64_t *)keyB;

	return (a == b);
}

cli_mgr_t *cli_mgr_init(void) 
{
	int clifd;
	cli_mgr_t *cm;

   	cm = malloc(sizeof(*cm));
	if(!cm)
		return NULL;

	cm->uid_pool = ID_FRIST_NUM;
	cm->rid_pool = ID_FRIST_NUM;
	cm->user_count = 0;
	cm->group_count = 0;
	cm->nextseq = 0;

	clifd = create_cli_mgr_channel();
	cm->hand = fdhandler_udp_create(clifd, cli_mgr_handle, cli_mgr_close, cm);
	cm->user_map = hashmapCreate(HASH_USER_CAPACITY, int64_hash, int64_equals);
	cm->group_map = hashmapCreate(HASH_GROUP_CAPACITY, int64_hash, int64_equals);
	return cm;
}

