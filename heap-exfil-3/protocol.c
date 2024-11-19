#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/fsuid.h>

#include "config.h"
#include "zero.h"
#include "sessionstore.h"
#include "protocol.h"

#define SESSION_ADMIN "admin"

#define OP_OPEN_FILE "openfile"
#define OP_HEARTBLEED "heartbleed"
#define OP_DUMP_SESSIONS "dumpsessions"
#define OP_OVERRUN "overrun"

#define OP_OPEN_FILE_SUCCESS "SUCCESS"
#define OP_OPEN_FILE_FAIL "FAILURE"

/* admin has read, others do not*/
#define ROOT_PRIV_TEST_FILE "/proc/slabinfo"

struct dispatch_object {
	struct responsedata * (*p_openfile)(int);
	struct responsedata * (*p_dumpsessions)(int);
	struct responsedata * (*p_heartbleed)(const char *);
	struct responsedata * (*p_overrun)(int, const char *);
};

struct dispatch_object function_table;

static int upfsprivs() {
	/* update to root so we can do things like open slabinfo */
	return setfsuid(0);
}

static void restoreprivs(int olduid) {
	/* restore permission */
	setfsuid(olduid);
}

/*
 * Inspired by an old weakness in openssh server,
 * where a user supplied buffer should be echoed, but the
 * implementation allows the attacker to control the buffer size
*/
static responsedata * op_heartbleed(const char * attacker_input) {
	responsedata * response = malloc(sizeof (struct responsedata) * 1);

	/* This whole thing works b/c of heap memory layout.
	 * in this code base, the zero copy pool is allocated on the heap prior
	 * to the session logging pool. If the attacker is on a thread using a
	 * zero copy buffer (which attacker_input here will likely be), then
	 * this faulty logic can be used to overrun a copy operation into the
	 * session space to exfile session cookies (e.g., to have admin rights).
	*/

	/* find the pipe in the users input */
	char * idx = strstr(attacker_input, "|");
	if (idx != NULL) {
		/* null the pipe */
		*idx = '\0';

	    /* attacker is providing size and buffer for echoing in the from "4096|x" */
		response->bufsz = atoi(attacker_input);
		response->buf = (char *) malloc(sizeof(char)*response->bufsz);
		/* idx is small ideally, like a single character 'x',
		 * so this is an excessive copy starting from the zero copy buffer if the attacker is lucky
		 */
		memcpy((void*) response->buf, (void*) ++idx, response->bufsz);

		printf("attacker is attempting to copy %d bytes of heap. starting from address: %p\n", response->bufsz, idx);
	} else {
		/* malformed input */
		response->bufsz = 6;
		response->buf = malloc(sizeof(char)*response->bufsz);
		memcpy(response->buf, "BADIO\0", response->bufsz);
	}

	return response;
}

/* to support simple c-strings, we just concat responses. */
static responsedata * op_dumpsessions(int admin) {
	char * idx = NULL;
	int i = 0;
	int ct = 0;
	int len = 0;
	char * ret = NULL;
	char * retroot = NULL;
	responsedata * response = malloc (sizeof(struct responsedata) * 1);
	response->buf = NULL;
	response->bufsz = -1;

	if (admin) {
		/* count */
		idx = (char *) session_peak();
		while (i<SESSION_HISTORY) {
			if (*idx != '\0') {
				ct++;
				printf("[slot: %d] '%s'\n", i, idx);
			} else {
				printf("[slot: %d] is empty: \n", i);
			}
			i++;
			idx = &((char*)session_peak())[i*BUFSIZE];
		}
		if (ct > 0) {
			printf("%d session entries have logging data. setup return on heap.\n", ct);

			/* alloc ret */
			retroot = ret = (char *) calloc(ct, BUFSIZE);

			/* copy data */
			idx = (char *) session_peak();
			i = 0;
			while(i<SESSION_HISTORY) {
				if (*idx != '\0') {

					len = strlen(idx);
					memcpy((void*) ret, (void*) idx, len);
					ret+=len;

				}
				i++;
				idx = &((char*)session_peak())[i*BUFSIZE];
			}

			printf("'%s'\n", retroot);

			response->buf = retroot;
			response->bufsz = strlen(retroot);
		}

	}

	return response;
}

static responsedata * cmd_test_open_file(const char * file) {
	responsedata * ret = malloc (sizeof(struct responsedata) * 1);
	int fd = open (file, O_RDONLY);

	if (fd == -1) {
		perror("could not open file");
		ret->buf = strdup(OP_OPEN_FILE_FAIL);
		ret->bufsz = strlen(OP_OPEN_FILE_FAIL) + 1;
	} else {
		printf("successfully opened %s\n", file);
		ret->buf = strdup(OP_OPEN_FILE_SUCCESS);
		ret->bufsz = strlen(OP_OPEN_FILE_SUCCESS) + 1;
		close(fd);
	}

	return ret;
}

static responsedata * op_openfile(int asadmin) {
	responsedata * ret;
	int olduid;
	if (asadmin) {
		olduid = upfsprivs();
	}

	ret = cmd_test_open_file(ROOT_PRIV_TEST_FILE);

	if (asadmin) {
		restoreprivs(olduid);
	}

	return ret;
}

static responsedata * op_overrun(int asadmin, const char * attacker_input) {
	responsedata * response;
	int changePriv[1] = {asadmin};

	// Split here

	char filename[15] = {0};
	char * idx = strstr(attacker_input, "|");
	if (idx != NULL) {
		*idx = '\0';
		int size = atoi(attacker_input);
		printf("Attacker size: %d\n", size);
		memcpy((void*) filename, (void*) ++idx, size);
		filename[14] = '\0';
	} else {
		response = malloc (sizeof(struct responsedata) * 1);
		response->bufsz = 6;
		response->buf = malloc(sizeof(char)*response->bufsz);
		memcpy(response->buf, "BADIO\0", response->bufsz);
	}

	int olduid;
	if (*changePriv) {
		olduid = upfsprivs();
	}

	printf("Attempting to read from file: %s\n", filename);
	response = cmd_test_open_file(filename);

	if (*changePriv) {
		restoreprivs(olduid);
	}

	return response;
}

/* asadmin is not a unique concept, powershell has verb/runas, linux has sudo */
static responsedata * process_cmd(const char * cmd, int asadmin) {
	responsedata * ret;

	if (strncmp(cmd, OP_OPEN_FILE, strlen(OP_OPEN_FILE)) == 0) {
		if (function_table.p_openfile != NULL) {
			return (*function_table.p_openfile)(asadmin);
		}
	}

	if (strncmp(cmd, OP_DUMP_SESSIONS, strlen(OP_DUMP_SESSIONS)) == 0) {
		if (function_table.p_dumpsessions != NULL) {
			return (*function_table.p_dumpsessions)(asadmin);
		}
	}

	if (strncmp(cmd, OP_HEARTBLEED, strlen(OP_HEARTBLEED)) == 0) {
		/* heartbleed|<ascii-int>|<char-buf>
		      minimum size "heartbleed|9|a" */
		if ((strlen(OP_HEARTBLEED)+4) <= strlen(cmd)) {
			if (function_table.p_heartbleed != NULL) {
				/* past some minimal input validation. skip the 'heartbleed|' */
				return (*function_table.p_heartbleed)(&cmd[strlen(OP_HEARTBLEED) + 1]);
			}
		}
	}

	if (strncmp(cmd, OP_OVERRUN, strlen(OP_OVERRUN)) == 0) {
		/* overrun|<ascii-int>|<char-buf> */
		if ((strlen(OP_OVERRUN)+4) <= strlen(cmd)) {
			if (function_table.p_overrun != NULL) {
				return (*function_table.p_overrun)(asadmin, &cmd[strlen(OP_OVERRUN) + 1]);
			}
		}
	}

	/* default return */
	ret = malloc (sizeof (struct responsedata) * 1);
	ret->bufsz = 5;
	ret->buf = malloc(ret->bufsz);
	strncpy(ret->buf, "NACK\0", ret->bufsz);

	return ret;
}

void init_protocol_elements(bool enable_op_dumpsession,
                bool enable_op_openfile,
                bool enable_op_heartbleed,
								bool enable_op_overrun) {
	memset((void*) &function_table, 0x00, sizeof(struct dispatch_object));
	if (enable_op_dumpsession) {
		function_table.p_dumpsessions = op_dumpsessions;
		printf("Enable op_dumpsessions\n");
	}
	if (enable_op_openfile) {
		function_table.p_openfile = op_openfile;
		printf("Enable op_openfile\n");
	}
	if (enable_op_heartbleed) {
		function_table.p_heartbleed = op_heartbleed;
		printf("Enable op_heartbleed\n");
	}
	if (enable_op_overrun) {
		function_table.p_overrun = op_overrun;
		printf("Enable op_overrun\n");
	}
}

responsedata * auth_and_execute(char * io) {
	/*
         * simple parser for simple top-level "<session>|<command>" protocol.
	 */
	char * session = io;
	char * cmd = strstr(io, "|");
	*cmd = '\0';
	cmd++;

	/* Log session info and command on heap */
	session_log(session, cmd);

	/* Check session/cookie/user and do something in that context */
	if (strncmp(SESSION_ADMIN, session, 5) == 0) {
		return process_cmd(cmd, 1);
	} else {
		return process_cmd(cmd, 0);
	}
}
