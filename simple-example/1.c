#include <stdlib.h>
#include "2.h"

typedef struct responsedata {
	void * buf;
	int bufsz;
} responsedata;


static char *foo() {
	responsedata * response;
	workerdata resources = zc_get_buffer();
	char * buf = resources.buf;
	if (buf == NULL) {
		buf = malloc (sizeof(char) * 1024);
	}
  char *buf2 = buf;
  return buf2;
}

int main() {
  zc_storage_create();
  foo();
  zc_storage_free();
}
