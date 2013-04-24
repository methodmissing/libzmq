#ifndef __ZMQ_DTRACE_H_INCLUDED__
#define __ZMQ_DTRACE_H_INCLUDED__

#include "dtrace_impl.hpp"

#define ZMQ_TRACE_CTX_DECL dzmq_ctx_t dctx;
#define ZMQ_TRACE_SOCKET_DECL dzmq_socket_t ds;
#define ZMQ_TRACE_MSG_DECL dzmq_msg_t dmsg;
#define ZMQ_TRACE_DESTMSG_DECL dzmq_msg_t ddest;
#define ZMQ_TRACE_SRCMSG_DECL dzmq_msg_t dsrc;

void zmq_ctx_dtrace_cast (dzmq_ctx_t *dctx_, void *ctx_)
{
    ((zmq::ctx_t*) ctx_)->dtrace_cast (dctx_);
}

void zmq_socket_dtrace_cast (dzmq_ctx_t *dctx_, dzmq_socket_t *ds_, void *s_)
{
    ((zmq::socket_base_t*) s_)->dtrace_cast (dctx_, ds_);
}

void zmq_msg_dtrace_cast (dzmq_msg_t *dmsg_, zmq_msg_t *msg_)
{
    ((zmq::msg_t*) msg_)->dtrace_cast (dmsg_);
}

#endif