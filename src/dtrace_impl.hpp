#ifndef __ZMQ_DTRACE_IMPL_H_INCLUDED__
#define __ZMQ_DTRACE_IMPL_H_INCLUDED__

#include "../include/zmq.h"

typedef struct {
    char starting;
    char terminating;
} dzmq_ctx_t;

typedef struct {
    dzmq_ctx_t *ctx;
    unsigned char type;
    int ticks;
    char rcvmore;
    int fd;
} dzmq_socket_t;

typedef struct {
    char *data;
    size_t size;
    unsigned char flags;
    unsigned char type;
} dzmq_msg_t;

typedef zmq_pollitem_t dzmq_pollitem_t;

#endif