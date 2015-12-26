#include <stdlib.h>

#include "cli_mgr.h"
#include "turn_mgr.h"

typedef struct _center_serv {
	cli_mgr_t *climgr;
	nodeserv_mgr_t *nsmgr;
} center_serv_t;

static center_serv_t center_serv;


int center_serv_init(void) 
{
	center_serv_t *cs = &center_serv;

	cs->climgr = cli_mgr_init();
	cs->nsmgr = node_mgr_init();

	return 0;
}

