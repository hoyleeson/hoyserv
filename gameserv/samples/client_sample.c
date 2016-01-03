#include <stdio.h>

#include "client.h"

#define DEFAULT_IP 		"127.0.0.1"

int cli_callback(int event, void *arg1, void *arg2)
{

	return 0;
}

int main(int argc, void **argv)
{
	char host[32] = {0};

	if(argc < 2) {
		sprintf(host, "%s", DEFAULT_IP);
	}
#if 1
	client_init(host, CLI_MODE_CONTROL_ONLY, cli_callback);

	client_login();
	client_create_group(1, "testroom", NULL);

	client_delete_group();

//	client_list_group(group);
//	client_join_group(group, passwd);
//	client_leave_group();
#endif
	return 0;
}

