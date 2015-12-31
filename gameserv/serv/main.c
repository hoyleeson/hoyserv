#include <unistd.h>
#include <stdio.h>
#include <getopt.h>

#include <protos.h>

#define SERV_MODE_CENTER_SERV  	(1 << 0)
#define SERV_MODE_NODE_SERV 	 	(1 << 1)
#define SERV_MODE_FULL_FUNC 		(SERV_MODE_CENTER_SERV | SERV_MODE_NODE_SERV)
#define SERV_MODE_UNKNOWN  			(0)

struct {
	char *keystr;
	int mode;
} mode_maps[] = {
	{ "center", SERV_MODE_CENTER_SERV },
	{ "node", SERV_MODE_NODE_SERV}, 
	{ "full", SERV_MODE_FULL_FUNC }, 
};

#define ARRAY_SIZE(x) 	(sizeof(x)/sizeof((x)[0]))

static const struct option longopts[] = {
	{"mode", required_argument, 0, 'm'},
	{"version", 0, 0, 'v'},
	{"help", 0, 0, 'h'},
	{0, 0, 0, 0}
};


static int serv_mode_parse(const char *m) 
{
	int i;
	int mode;

	for(i=0; i<ARRAY_SIZE(mode_maps); i++) {
		if(strcmp(mode_maps[i].keystr, m))	
			return mode_maps[i].mode;
	}

	return SERV_MODE_UNKNOWN;
}

int main(int argc, char **argv)
{
	int opt;
	int mode = SERV_MODE_FULL_FUNC;

	while((opt = getopt_long(argc, argv, "m:vh", longopts, NULL)) > 0) {
		switch(opt) {
			case 'm':
				mode = serv_mode_parse(optarg);
				break;
			case 'v':
				info("compilation date: %s,time: %s, version: %d\n", 
						__DATE__, __TIME__, SERV_VERSION);
				return 0;
			case 'h':
			default:
				break;
		}
	}

	iohandler_init();

	if(mode & SERV_MODE_CENTER_SERV)
		center_serv_init();

	if(mode & SERV_MODE_NODE_SERV)
		node_serv_init();

	iohandler_loop();
	return 0;
}

