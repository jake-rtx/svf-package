#ifndef __LOC_PROTOCOL_H
#define __LOC_PROTOCOL_H

#include "config.h"

typedef struct responsedata {
	void * buf;
	int bufsz;
} responsedata;

/* configure the # of operations this server supports */
void init_protocol_elements(bool, bool, bool, bool);

/* process io from user source */
responsedata * auth_and_execute(char *);

#endif
