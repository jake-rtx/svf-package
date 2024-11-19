#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "config.h"
#include "zero.h"

static void * zc_on_heap = NULL;
static int * zc_buf_tracker;

void zc_restore_buffer(workerdata data) {
	/* trust someone*/
	if (data.bufid >= 0 && data.bufid < ZC_COUNT) {
		memset((void*) data.buf, 0x00, BUFSIZE);
		zc_buf_tracker[data.bufid] = 0;
	}
}

workerdata zc_get_buffer() {
	int i = 0;
	workerdata ret; 
	ret.buf = NULL;
	ret.bufid = -1;
	do {
		if (zc_buf_tracker[i] == 0) {
			zc_buf_tracker[i] = 1;
			ret.bufid = i;
			ret.buf = zc_on_heap + (i*BUFSIZE);
			return ret;
		}
	} while (++i < ZC_COUNT);

	/* nothing left, caller has to fend for themselves */	
	printf("ZC pool is exhausted.\n");
	return ret;
}

void zc_storage_create() {
	zc_on_heap = calloc(ZC_COUNT, BUFSIZE);
	zc_buf_tracker = calloc(ZC_COUNT, sizeof(int));
        printf("Allocated zero copy pool at %p\n", zc_on_heap);

}

void zc_storage_free() {
	free(zc_on_heap);
	free(zc_buf_tracker);
}
