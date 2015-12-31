#ifndef _TURN_CLIENT_H_
#define _TURN_CLIENT_H_

#ifdef __cplusplus
extern "C" {
#endif

enum client_mode {
	CLI_MODE_CONTROL_ONLY,
	CLI_MODE_TASK_ONLY,
	CLI_MODE_FULL_FUNCTION,
};

/* event callback routine.
 * event: EVENT_*
 * arg1, arg2: event dependent args.
 * return: 0 success, other fail */
typedef int (*event_cb)(int event, void *arg1, void *arg2);

int client_login(void);
int client_create_group(int open, const char *name, const char *passwd);
void client_delete_group(void);

int client_list_group(group_t *group);
int client_join_group(group_t *group, const char *passwd);
void client_leave_group(void);

void client_send_command(void *data, int len);
void client_send_state_img(void *data, int len);

int client_init(const char *host, int mode, event_cb callback);
int client_task_start(const char *host, int port, uint32_t userid, uint32_t groupid);

enum {
	EVENT_NONE,

	  /* arg1: void *, receive data.
	   * arg2: int, data length. */
	EVENT_COMMAND,

	/* arg1: void *, receive state image.
	 * arg2: int, image length. */
	EVENT_STATE_IMG,
};


#ifdef __cplusplus
}
#endif

#endif
