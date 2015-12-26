#ifndef _TURN_CLIENT_H_
#define _TURN_CLIENT_H_

#ifdef __cplusplus
extern "C" {
#endif

enum client_mode {
	CLI_MODE_CONTROL_ONLY,
	CLI_MODE_TASK_ONLY,
	CLI_MODE_FULL_FUNCTION,
}

int client_login(void);
void client_create_group(int open, const char *name, const char *passwd);
void client_delete_group(void);

int client_list_group(group_t *group);
void client_join_group(group_t *group, const char *passwd);
void client_leave_group(void);

int client_init(const char *host);

#ifdef __cplusplus
}
#endif

#endif
