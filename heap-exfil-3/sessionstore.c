#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "config.h"
#include "sessionstore.h"

static void * sessions_on_heap = NULL;
static int sessions_idx = 0;

void * session_peak() {
	return sessions_on_heap;
}

/* logs a limited # of session commands in a fixed circular buffer.
 *  - NOTE: this will store session cookies and commands (i.e., enabling heartbleed)
 */       
void session_log(const char * session, const char * cmd) {
	char * idx = &(((char *) sessions_on_heap)[sessions_idx*BUFSIZE]);
	char * root = idx;
	int slen = strlen(session);
	int clen = strlen(cmd);
	
	printf("[slot: %d] session: '%s' cmd: '%s'\n", sessions_idx, session, cmd);
	
	/* zero old entry (if any) */
	memset(idx, '\0', BUFSIZE);

	/* store user/cmd */
	memcpy((void*) idx, (void*) session, slen);
	idx+=slen;
	*idx++ = '|';
	memcpy((void*)idx, (void*)cmd, clen);
	
	printf("Logged: '%s'\n", root);

	if (++sessions_idx % SESSION_HISTORY == 0) {
		sessions_idx = 0;
	}
}

void session_storage_create() {
	sessions_on_heap = calloc(SESSION_HISTORY, BUFSIZE);
	printf("Allocated session store at %p\n", sessions_on_heap);
}

void session_storage_free() {
	free(sessions_on_heap);
}
