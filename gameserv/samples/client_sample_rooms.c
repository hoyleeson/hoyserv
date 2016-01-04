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
#define CFG_MAXARGS 	(64)

#define ARRAY_SIZE(s) 	(sizeof(s)/sizeof((s)[0]))

const char *fifo_name = "/tmp/sample_fifo";

struct cmd_ops {
	char *cmd;
	int (*func)(int argc, char **argv);
};


int parse_cmds(char *line, char *argv[])
{
	int nargs = 0;

	while(nargs < CFG_MAXARGS)
	{
		while((*line ==' ') || (*line == '\t'))
		{
			++line;
		}

		if(*line == '\0')
		{
			argv[nargs] = NULL;
			return nargs;
		}

		argv[nargs++] = line;

		while(*line && (*line != ' ') && (*line != '\t'))
			++line;

		if(*line == '\0')
		{
			argv[nargs] = NULL;
			return nargs;
		}
		*line++ = '\0';
	}

	return nargs;
}

static void run_netplay()
{
	int ret;
	int pid, w;
	int status;
	int pipe_fd = -1; 
	const int open_mode = O_WRONLY;
	struct cli_context_state state;

	client_state_serialize(&state);

	pid = fork();
	if(pid == 0) {
		char *newargv[] = { NULL, NULL };
		char *newenviron[] = { NULL };

		execve("./sample_netplay", newargv, newenviron);
	} else {

		if(access(fifo_name, F_OK) == -1) {  
			ret = mkfifo(fifo_name, 0777);  
			if(ret != 0) {  
				printf("Could not create fifo %s\n", fifo_name);  
				exit(EXIT_FAILURE);  
			}  
		}  

		pipe_fd = open(fifo_name, open_mode);
		ret = write(pipe_fd, &state, sizeof(state));
		close(pipe_fd);

		do {
			w = waitpid(pid, &status, WUNTRACED | WCONTINUED);
			if (w == -1) {
				perror("waitpid");
				exit(EXIT_FAILURE);
			}

			if (WIFEXITED(status)) {
				printf("exited, status=%d\n", WEXITSTATUS(status));
			} else if (WIFSIGNALED(status)) {
				printf("killed by signal %d\n", WTERMSIG(status));
			} else if (WIFSTOPPED(status)) {
				printf("stopped by signal %d\n", WSTOPSIG(status));
			} else if (WIFCONTINUED(status)) {
				printf("continued\n");
			}
		} while (!WIFEXITED(status) && !WIFSIGNALED(status));
	}
}

static int create_group(int argc, char **argv) 
{
	int open = 1;
	char *name;
	char *passwd;

	if(argc > 1)
		name = argv[1];
	else
		name = "testroom";

	if(argc > 2)
		passwd = argv[2];
	else
		passwd = "123456";

	if(argc > 3)
		open = atoi(argv[3]);
	else
		open = 1;

	client_create_group(open, name, passwd);
	run_netplay();

	return 0;
}

static int delete_group(int argc, char **argv)
{
	client_delete_group();
	return 0;
}

static int list_group(int argc, char **argv)
{
	struct group_description group[50];

	client_list_group(&group);
	return 0;
}

static int join_group(int argc, char **argv)
{
	char *passwd;
	struct group_description group;
	if(argc < 2)
		return -1;

	group.groupid = atoi(argv[1]);

	if(argc > 2)
		passwd = argv[2];
	else
		passwd = "123456";

	client_join_group(&group, passwd);

	run_netplay();
	return 0;
}

static int leave_group(int argc, char **argv)
{
	client_leave_group();
	return 0;
}


static struct cmd_ops cmds[] = {
	{ "create", create_group },
	{ "delete", delete_group },
	{ "join", join_group },
	{ "leave", leave_group },
	{ "list", list_group },
};



int cli_callback(int event, void *arg1, void *arg2)
{

	return 0;
}


int main(int argc, char **argv)
{
	int ret;
	char buf[1024];
	char host[32] = {0};
	char* cmd_argv[CFG_MAXARGS];
	struct group_description group[50];

	if(argc < 2) {
		sprintf(host, "%s", DEFAULT_IP);
	}

	client_init(host, CLI_MODE_CONTROL_ONLY, cli_callback);

	client_login();

	client_list_group(group);


	while(fgets(buf, sizeof(buf), stdin)) {
		int i;

		if(strcmp(buf, "quit")) {
			break;
		}

		ret = parse_cmds(buf, cmd_argv);

		if(ret <= 0)
			continue;

		for(i=0; i<ARRAY_SIZE(cmds); i++) {
			if(!strcmp(cmds[i].cmd, cmd_argv[0])) {
				cmds[i].func(ret, cmd_argv);
				break;
			}
		}
	}

	return 0;
}
