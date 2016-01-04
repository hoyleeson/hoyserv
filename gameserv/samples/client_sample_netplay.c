#include <stdio.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "client.h"

#define DEFAULT_IP 		"127.0.0.1"

const char *fifo_name = "/tmp/sample_fifo";

int cli_callback(int event, void *arg1, void *arg2)
{
	return 0;
}


int main(int argc, char **argv)
{
	int ret;
	int pipe_fd = -1;  
	int open_mode = O_RDONLY;
	struct cli_context_state state;

	pipe_fd = open(fifo_name, open_mode);  
	ret = read(pipe_fd, &state, sizeof(state));
	if(ret < 0)
		return 0;
	close(pipe_fd);

	client_init(DEFAULT_IP, CLI_MODE_TASK_ONLY, cli_callback);
	client_task_start(state.userid, state.groupid, &state.addr);

	while(1)
		sleep(1);

	return 0;
}

