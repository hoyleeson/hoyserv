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

int running = 0;
int cli_callback(int event, void *arg1, void *arg2)
{
    printf("receive event(%d):%s, len:%d\n", event, (char *)arg1, (int)arg2);
    switch(event) {
        case EVENT_CHECKIN:
            running = 1;
            break;
        case EVENT_COMMAND:
            running = 1; /*XXX*/
            break;
        default:
            break;
    }
    return 0;
}


int main(int argc, char **argv)
{
    int ret;
    int pipe_fd = -1;  
    int open_mode = O_RDONLY;
    struct cli_context_state state;
    char buf[512] = {0};
    int seq = 0;

    printf("sample netplay enter..\n");

    pipe_fd = open(fifo_name, open_mode);  
    ret = read(pipe_fd, &state, sizeof(state));
    if(ret < 0)
        return 0;
    close(pipe_fd);
    client_state_dump(&state);

    client_init(DEFAULT_IP, CLI_MODE_TASK_ONLY, cli_callback);
    client_state_load(&state);
    client_task_start();


    while(1) {
        if(running == 0) {
            printf(".");
            fflush(stdout);
            sleep(1);
            continue;
        }

        sprintf(buf, "test hello world.%d.\n", seq++);
        client_send_command(buf, strlen(buf));
        sleep(1);
    }

    return 0;
}

