#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>

#include "config.h"
#include "zero.h"
#include "sessionstore.h"
#include "protocol.h"

typedef struct managedtask {
	pthread_t * task;
	struct managedtask * next;
} managedtask;

static managedtask * taskstack;
static managedtask * taskstack_top;

static int isrunning = 1;

static void * worker(void * arg) {
	int fd = *((int*)arg);
	responsedata * response;
	workerdata resources = zc_get_buffer();
	char * buf = resources.buf;
	if (buf == NULL) {
		/* fending for ourselves, no ZC buffer.*/
		printf("Dynamic buffer allocation.\n");
		buf = malloc (sizeof(char) * BUFSIZE);
	}

	printf("read fd:%d into buffer:%p\n", fd, buf);

	/* read messages in loop, until EOF */
    	while (
		(isrunning==1) &&
	       	(read(fd, buf, BUFSIZE) > 0)
	       ) {
		if (buf != NULL) {
			/* dispatch message */
			response = auth_and_execute(buf);

			/* manage any responses to the input */
			if (response != NULL) {
				if (response->buf != NULL && response->bufsz > 0) {
					write(fd, response->buf, response->bufsz);
					/* fullfil protocol's contract, buffer cleanup */
					free(response->buf);
				}
				/* fullfil protocol's contract, object cleanup */
				free(response);
			}
		}

		/* cleanup read buffer */
		memset(buf, 0x00, BUFSIZE);
	}

	close(fd);
	if (resources.buf == NULL) {
		/* self managed resource, not a ZC pool */
		free(buf);
	} else {
		/* fullfill zc contract */
		zc_restore_buffer(resources);
	}


	printf("Exiting worker thread\n");
	return NULL;
}

static void spawn_unpriv_worker(int fd) {
	/* resource for worker */
	int * arg = malloc (sizeof(int)*1);
	/* task mgmt for cleanup */
	managedtask * newtask = (managedtask *) malloc(sizeof(managedtask)*1);
	newtask->task = (pthread_t *) malloc (sizeof(pthread_t) * 1);
	if (taskstack == NULL) {
		taskstack = newtask;
	} else {
		taskstack_top->next = newtask;
	}
	taskstack_top = newtask;
	taskstack_top->next = NULL;
	*arg = fd;
    /*
	 * ARC/CPM:
	 * like malloc, pthread* api provides rich semantics to define new task creation
	 * this thread will have the euid of the calling context */
	pthread_create(newtask->task, NULL, &worker, (void*) arg);
}

static void start_priv_server(int effectiveuid,
		bool enable_op_dumpsession,
                bool enable_op_openfile,
                bool enable_op_heartbleed,
								bool enable_op_overrun) {
   int store_euid;

   struct sockaddr_in serveraddr;
   struct sockaddr_in clientaddr;
   int optval = 1;
   int unsigned clen;
   int cfd;
   int sfd = socket(AF_INET, SOCK_STREAM, 0);
   setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, (const void *) &optval , sizeof(int));

   bzero((char *) &serveraddr, sizeof(serveraddr));
   serveraddr.sin_family = AF_INET;
   serveraddr.sin_addr.s_addr = htonl(INADDR_ANY);
   serveraddr.sin_port = htons((unsigned short) 88);

   /* root or capabilities are required to bind to 88 */
   /* libc/binds rich semantics define access requirements */
   bind(sfd, (struct sockaddr *) &serveraddr, sizeof(serveraddr));
   listen(sfd, 5);

   /* store/drop privs */
   store_euid = geteuid();
   seteuid(effectiveuid);

   printf("Set effective privs to %d\n", geteuid());

   /* setup zero copy buffer pool */
   zc_storage_create();

   /* setup session storage */
   session_storage_create();

   /* configure protocols */
   init_protocol_elements(enable_op_dumpsession,
                enable_op_openfile,
                enable_op_heartbleed,
								enable_op_overrun);

   /* loop and accept connections and create workers */
   while (1) {
    	clen = sizeof(clientaddr);
	cfd = accept(sfd, (struct sockaddr *) &clientaddr, &clen);
	if (cfd > 0) {
		spawn_unpriv_worker(cfd);
	} else {
		isrunning = 0;
		break;
	}
   }

   /* clean up zero copy and session stores */
   zc_storage_free();
   session_storage_free();

   /* Not yet implemented, clean up worker threads (e.g., joins)*/

   /* restore privs (as needed for cleanup xxx)*/
   seteuid(store_euid);
   close(sfd);
}

static void usage(char ** argv) {
	printf("./%s [-e <EUID>] [-d] [-o] [-h] [-r]\n", argv[0]);
	printf("  -e <EUID>: a user id (as required int) to change to after the libc:bind on port 88.\n");
	printf("  -d: enable protocol op_dumpsession\n");
	printf("  -o: enable protocol op_openfile\n");
	printf("  -h: enable protocol op_heartbleed\n");
	printf("  -r: enable protocol op_overrun\n");
	printf("./%s must be launched by a root user.\n", argv[0]);
}

int main (int argc, char ** argv) {
	int euid = 0;
	bool enable_op_dumpsession = false;
	bool enable_op_openfile = false;
	bool enable_op_heartbleed = false;
	bool enable_op_overrun = false;
	int opt;

	if (argc <= 1) {
		usage(argv);
            	exit(EXIT_FAILURE);
	}

	while ((opt = getopt(argc, argv, "dohre:")) != -1) {
        	switch (opt) {
	        	case 'e': euid = atoi(optarg) ; break;
	        	case 'd': enable_op_dumpsession = true ; break;
	        	case 'o': enable_op_openfile = true; break;
		        case 'h': enable_op_heartbleed = true; break;
		        case 'r': enable_op_overrun = true; break;
        		default: break;
	        }
	}

	if ((getuid() == 0 || geteuid() == 0)) {
		/* root privs or specific OS capabilites are required to bind */
		/* this function follows a bind then reduce priv model, like most webservers */
		start_priv_server(euid,
				enable_op_dumpsession,
				enable_op_openfile,
				enable_op_heartbleed,
				enable_op_overrun);
	}

	return 0;
}
