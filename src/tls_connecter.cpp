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

#include "platform.hpp"

#if defined ZMQ_HAVE_TLS

#include <new>
#include <string>

#include "tls_connecter.hpp"
#include "tls_stream_engine.hpp"
#include "io_thread.hpp"
#include "platform.hpp"
#include "random.hpp"
#include "err.hpp"
#include "ip.hpp"
#include "tcp.hpp"
#include "address.hpp"
#include "tcp_address.hpp"
#include "session_base.hpp"

#if defined ZMQ_HAVE_WINDOWS
#include "windows.hpp"
#else
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <netdb.h>
#include <fcntl.h>
#ifdef ZMQ_HAVE_OPENVMS
#include <ioctl.h>
#endif
#endif

zmq::tls_connecter_t::tls_connecter_t (class io_thread_t *io_thread_,
      class session_base_t *session_, const options_t &options_,
      const address_t *addr_, bool delayed_start_) :
      tcp_connecter_t (io_thread_, session_, options_, addr_, delayed_start_)
{
    zmq_assert (addr->protocol == "tls");
}

zmq::tls_connecter_t::~tls_connecter_t ()
{
    zmq_assert (!timer_started);
    zmq_assert (!handle_valid);
    zmq_assert (s == retired_fd);
}

void zmq::tls_connecter_t::out_event ()
{
    fd_t fd = connect ();
    rm_fd (handle);
    handle_valid = false;

    //  Handle the error condition by attempt to reconnect.
    if (fd == retired_fd) {
        close ();
        add_reconnect_timer ();
        return;
    }

    if (tls_init () == -1) {
        close ();
        terminate ();
        return;
    }

    tune_tcp_socket (fd);
    tune_tcp_keepalives (fd, options.tcp_keepalive, options.tcp_keepalive_cnt, options.tcp_keepalive_idle, options.tcp_keepalive_intvl);

    SSL_set_fd (ssl, fd);
    //  Create the engine object for this connection.
    tls_stream_engine_t *engine = new (std::nothrow) tls_stream_engine_t (ssl, false, options, endpoint);
    alloc_assert (engine);

    //  Attach the engine to the corresponding session object.
    send_attach (session, engine);

    //  Shut the connecter down.
    terminate ();

    socket->event_connected (endpoint, fd);
}

void zmq::tls_connecter_t::close ()
{
    if (ssl) {
        if (SSL_get_shutdown (ssl) & SSL_RECEIVED_SHUTDOWN)
            SSL_shutdown (ssl);
        SSL_free (ssl);
        ssl = NULL;
    }

    zmq::tcp_connecter_t::close ();
}

int zmq::tls_connecter_t::tls_init ()
{
    ssl = SSL_new ( socket-> get_tls_ctx () );
    if (!ssl) {
        errno = ETLS;
        return -1;
    }

    return 0;
}

#endif