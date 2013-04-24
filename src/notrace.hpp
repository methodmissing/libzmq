#ifndef __ZMQ_NOTRACE_H_INCLUDED__
#define __ZMQ_NOTRACE_H_INCLUDED__

typedef char dzmq_ctx_t;
typedef char dzmq_socket_t;
typedef char dzmq_msg_t;
typedef char dzmq_pollitem_t;

#define ZMQ_TRACE_START (msg, obj)
#define ZMQ_TRACE_START_ENABLED () (0)
#define ZMQ_TRACE_DONE (msg, obj)
#define ZMQ_TRACE_DONE_ENABLED () (0)

#define zmq_ctx_dtrace_cast (dctx, ctx)
#define zmq_socket_dtrace_cast (dctx, ds, s)
#define zmq_msg_dtrace_cast (dmsg, msg)

#endif