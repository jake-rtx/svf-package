#include <stdlib.h>
#include "2.h"

static void *zc_on_heap = NULL;
static int *zc_buf_tracker = NULL;

workerdata zc_get_buffer() {
	int i = 0;
	workerdata ret; 
	ret.buf = NULL;
	ret.bufid = -1;
	do {
		if (zc_buf_tracker[i] == 0) {
			zc_buf_tracker[i] = 1;
			ret.bufid = i;
			ret.buf = zc_on_heap + (i*1024);
			return ret;
		}
	} while (++i < 10);

	return ret;
}

void zc_storage_create() {
	zc_on_heap = calloc(10, 1024);
	zc_buf_tracker = calloc(10, sizeof(int));
}

void zc_storage_free() {
	free(zc_on_heap);
	free(zc_buf_tracker);
}
