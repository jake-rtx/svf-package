#ifndef __LOC_ZERO_H
#define __LOC_ZERO_H

typedef struct workerdata {
	char * buf;
	int bufid;
} workerdata;

workerdata zc_get_buffer();
void zc_storage_create();
void zc_storage_free();

#endif
