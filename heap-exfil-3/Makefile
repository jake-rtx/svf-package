CC = gcc
#CFLAGS = -ggdb -Wall -fcallgraph-info
#CFLAGS = -ggdb -Wall -fdump-tree-all-graph 
#CFLAGS = -ggdb -Wall -M
CFLAGS = -ggdb -Wall
#CFLAGS = -Xclang -ast-dump -fsyntax-only -fno-color-diagnostics -Wno-visibility
#CFLAGS = -Xclang -ast-dump=json -fsyntax-only -fno-color-diagnostics -Wno-visibility

SRCS=$(wildcard *.c)
OBJS=$(subst .c,.o,$(SRCS))

.PHONY: all

all: server

%.o: %.c
	$(CC) ${CFLAGS} -c $<

server: $(OBJS)
	$(CC) $(OBJS) -o $@  -l pthread 

.PHONY: clean
clean:
	rm -f *.o server
