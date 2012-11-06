/*
    Copyright (c) 2009-2011 250bpm s.r.o.
    Copyright (c) 2007-2010 iMatix Corporation
    Copyright (c) 2007-2011 Other contributors as noted in the AUTHORS file

    This file is part of 0MQ.

    0MQ is free software; you can redistribute it and/or modify it under
    the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    0MQ is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef __ZMQ_TLS_LISTENER_HPP_INCLUDED__
#define __ZMQ_TLS_LISTENER_HPP_INCLUDED__

#include "platform.hpp"

#if defined ZMQ_HAVE_TLS

#include "tls.hpp"
#include "tcp_listener.hpp"
#include "fd.hpp"
#include "own.hpp"
#include "stdint.hpp"
#include "io_object.hpp"
#include "tcp_address.hpp"
#include "../include/zmq.h"

namespace zmq
{

    class io_thread_t;
    class socket_base_t;

    class tls_listener_t : public tcp_listener_t
    {
    public:

        tls_listener_t (zmq::io_thread_t *io_thread_,
            zmq::socket_base_t *socket_, const options_t &options_);
        ~tls_listener_t ();

        //  Set address to listen on.
        int set_address (const char *addr_);

    protected:

        //  Handlers for I/O events.
        void in_event ();

        //  Close the listening socket.
        void close ();

    private:

        int tls_init ();

        int tls_accept (fd_t fd_);

        void tls_terminate ();

        SSL_CTX* ssl_ctx;

        SSL*  ssl;

        tls_listener_t (const tls_listener_t&);
        const tls_listener_t &operator = (const tls_listener_t&);
    };

}

#endif

#endif