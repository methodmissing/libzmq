/*
    Copyright (c) 2009-2011 250bpm s.r.o.
    Copyright (c) 2007-2009 iMatix Corporation
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

#ifndef __TLS_CONNECTER_HPP_INCLUDED__
#define __TLS_CONNECTER_HPP_INCLUDED__

#include "platform.hpp"

#if defined ZMQ_HAVE_TLS

#include "tls.hpp"
#include "tcp_connecter.hpp"
#include "fd.hpp"
#include "own.hpp"
#include "stdint.hpp"
#include "io_object.hpp"
#include "../include/zmq.h"

namespace zmq
{

    class io_thread_t;
    class session_base_t;
    struct address_t;

    class tls_connecter_t : public tcp_connecter_t
    {
    public:

        //  If 'delayed_start' is true connecter first waits for a while,
        //  then starts connection process.
        tls_connecter_t (zmq::io_thread_t *io_thread_,
            zmq::session_base_t *session_, const options_t &options_,
            const address_t *addr_, bool delayed_start_);
        ~tls_connecter_t ();

    protected:

        void out_event ();
        //  Close the connecting socket.
        void close ();

    private:

        int tls_init ();

        SSL *ssl;

        tls_connecter_t (const tls_connecter_t&);
        const tls_connecter_t &operator = (const tls_connecter_t&);
    };

}

#endif

#endif