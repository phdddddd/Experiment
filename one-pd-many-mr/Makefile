.PHONY: clean

CFLAGS  := -Wall -Werror -g
LD      := gcc
LDFLAGS := ${LDFLAGS} -lrdmacm -lpthread -libverbs 

APPS    :=   rdma-server-epoll #rdma-client #rdma-server

all: ${APPS}

# rdma-client: rdma-common.o rdma-client.o
# 	${LD} -o $@ $^ ${LDFLAGS}

# rdma-server: rdma-common.o rdma-server.o
# 	${LD} -o $@ $^ ${LDFLAGS}

rdma-server-epoll: rdma-common.o rdma-server-epoll.o
	${LD} -o $@ $^ ${LDFLAGS}

clean:
	rm -f *.o ${APPS}

