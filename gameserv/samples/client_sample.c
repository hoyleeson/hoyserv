#include <stdio.h>

#include "client.h"

#define DEFAULT_IP 		"127.0.0.1"

int main(int argc, void **argv)
{
	char host[32] = {0};

	if(argc < 2) {
		sprintf(host, "%s", DEFAULT_IP);
	}

	client_init(host);

	client_login();
	client_create_group(open, name, passwd);



	client_delete_group();

	client_list_group(group);
	client_join_group(group, passwd);
	client_leave_group(group);
}

