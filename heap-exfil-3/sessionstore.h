#ifndef __LOC_SESSIONSTORE_H_
#define __LOC_SESSIONSTORE_H_

void session_log(const char * session, const char * cmd);
void * session_peak();
void session_storage_create();
void session_storage_free();

#endif
