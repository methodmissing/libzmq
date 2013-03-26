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

#ifndef __ZMQ_TLS_STREAM_ENGINE_HPP_INCLUDED__
#define __ZMQ_TLS_STREAM_ENGINE_HPP_INCLUDED__

#include "stream_engine.hpp"
#include "tls.hpp"

namespace zmq
{

    class io_thread_t;
    class session_base_t;

    //  This engine handles any socket with SOCK_STREAM semantics,
    //  e.g. TCP socket or an UNIX domain socket.

    class tls_stream_engine_t : public stream_engine_t
    {

    public:

        tls_stream_engine_t (SSL *ssl_, bool server, const options_t &options_, const std::string &endpoint);
        ~tls_stream_engine_t ();

        void plug (zmq::io_thread_t *io_thread_,
           zmq::session_base_t *session_);

        //  i_poll_events interface implementation.
        void in_event ();
        void out_event ();

        int write_plaintext (const void *data_, size_t size_);

        int read_plaintext (void *data_, size_t size_);

    protected:

        //  Writes data to the socket. Returns the number of bytes actually
        //  written (even zero is to be considered to be a success). In case
        //  of error or orderly shutdown by the other peer -1 is returned.
        int write (const void *data_, size_t size_);

        //  Reads data from the socket (up to 'size' bytes). Returns the number
        //  of bytes actually read (even zero is to be considered to be
        //  a success). In case of error or orderly shutdown by the other
        //  peer -1 is returned.
        int read (void *data_, size_t size_);

        void error ();

        void unplug ();

    private:

        int tls_start ();
        int tls_begin ();
        void tls_continue ();

        void tls_error ();

        void tls_term ();

        enum tls_state {
            TLS_NONE, TLS_WAIT, TLS_CONNECTING, TLS_CONNECTED, TLS_ERROR
        };

        tls_state state;

        SSL *ssl;

        bool listener;

        bool tls_read_needs_write;
        bool tls_write_needs_read;

        tls_stream_engine_t (const stream_engine_t&);
        const tls_stream_engine_t &operator = (const tls_stream_engine_t&);
    };

}

#endif
