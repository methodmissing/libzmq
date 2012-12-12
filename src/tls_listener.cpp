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

#include "platform.hpp"

#if defined ZMQ_HAVE_TLS

#include <new>

#include <string>

#include "platform.hpp"
#include "tls_listener.hpp"
#include "tls_stream_engine.hpp"
#include "io_thread.hpp"
#include "session_base.hpp"
#include "config.hpp"
#include "err.hpp"
#include "ip.hpp"
#include "tcp.hpp"
#include "socket_base.hpp"

#ifdef ZMQ_HAVE_WINDOWS
#include "windows.hpp"
#else
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <netdb.h>
#include <fcntl.h>
#endif

#ifdef ZMQ_HAVE_OPENVMS
#include <ioctl.h>
#endif

zmq::tls_listener_t::tls_listener_t (io_thread_t *io_thread_,
      socket_base_t *socket_, const options_t &options_) :
    tcp_listener_t (io_thread_, socket_, options_)
{
}

zmq::tls_listener_t::~tls_listener_t ()
{
    zmq_assert (s == retired_fd);
    zmq_assert (ssl == NULL);
    zmq_assert (ssl_ctx == NULL);
}

void zmq::tls_listener_t::in_event ()
{
    fd_t fd = accept ();

    //  If connection was reset by the peer in the meantime, just ignore it.
    //  TODO: Handle specific errors like ENFILE/EMFILE etc.
    if (fd == retired_fd) {
        socket->event_accept_failed (endpoint.c_str(), zmq_errno());
        return;
    }

    tune_tcp_socket (fd);
    tune_tcp_keepalives (fd, options.tcp_keepalive, options.tcp_keepalive_cnt, options.tcp_keepalive_idle, options.tcp_keepalive_intvl);

    SSL_set_fd (ssl, fd);
    //  Create the engine object for this connection.
    tls_stream_engine_t *engine = new (std::nothrow) tls_stream_engine_t (ssl, true, options, endpoint);
    alloc_assert (engine);

    //  Choose I/O thread to run connecter in. Given that we are already
    //  running in an I/O thread, there must be at least one available.
    io_thread_t *io_thread = choose_io_thread (options.affinity);
    zmq_assert (io_thread);

    //  Create and launch a session object. 
    session_base_t *session = session_base_t::create (io_thread, false, socket,
        options, NULL);
    errno_assert (session);
    session->inc_seqnum ();
    launch_child (session);
    send_attach (session, engine, false);
    socket->event_accepted (endpoint.c_str(), fd);
}

void zmq::tls_listener_t::close ()
{
    if (ssl) {
        if (SSL_get_shutdown (ssl) & SSL_RECEIVED_SHUTDOWN)
            SSL_shutdown (ssl);
        else
            SSL_clear (ssl);
        SSL_free (ssl);
        ssl = NULL;
    }

    if (ssl_ctx) {
        SSL_CTX_free (ssl_ctx);
        ssl_ctx = NULL;
    }

    tcp_listener_t::close ();
}

int zmq::tls_listener_t::set_address (const char *addr_)
{
    int rc = zmq::tcp_listener_t::set_address (addr_);
    if (tls_init () == -1)
        goto error;
    return rc;

error:
    int err = errno;
    close ();
    errno = err;
    return -1;
}

int zmq::tls_listener_t::tls_init ()
{
    int rc;
    ssl_ctx = SSL_CTX_new ( SSLv23_server_method() );
    if (!ssl_ctx) {
        errno = ETLSCTX;
        return -1;
    }

    SSL_CTX_set_options (ssl_ctx, SSL_OP_ALL | SSL_OP_NO_SSLv2);

    rc = SSL_CTX_set_cipher_list (ssl_ctx, "ALL:!ADH:!LOW:!EXP:!MD5:@STRENGTH");
    if (rc == 0) {
        errno = ETLSCIPHER;
        return -1;
    }

    if (options.tls_ca_file || options.tls_ca_dir) {
        if (options.tls_ca_file) {
            rc = SSL_CTX_load_verify_locations (ssl_ctx, (const char*)options.tls_ca_file, NULL);
        } else {
            rc = SSL_CTX_load_verify_locations (ssl_ctx, NULL, (const char*)options.tls_ca_dir);
        }
        if (rc == 0) {
            errno = ETLSCA;
            return -1;
        }
    }

#if (OPENSSL_VERSION_NUMBER < 0x00905100L)
    SSL_CTX_set_verify_depth (ssl_ctx, 1);
#endif
    SSL_CTX_set_verify (ssl_ctx, SSL_VERIFY_PEER, tls_verify_callback);
    SSL_CTX_set_read_ahead (ssl_ctx, 1);

    if (options.tls_cert_file) {
        rc = SSL_CTX_use_certificate_file (ssl_ctx, (const char*)options.tls_cert_file, SSL_FILETYPE_PEM);
        if (rc != 1) {
            errno = ETLSCERT;
            return -1;
        }
    }

    if (options.tls_key_file) {
        rc = SSL_CTX_use_PrivateKey_file (ssl_ctx, (const char*)options.tls_key_file, SSL_FILETYPE_PEM);
        if (rc != 1) {
            errno = ETLSKEY;
            return -1;
        }

        rc = SSL_CTX_check_private_key(ssl_ctx);
        if (rc != 1) {
            errno = ETLSKEYINVALID;
            return -1;
        }
    }

    RSA *rsa = RSA_generate_key (1024, RSA_F4, NULL, NULL);

    if (!SSL_CTX_set_tmp_rsa (ssl_ctx, rsa)) {
        RSA_free (rsa);
        errno = ETLSRSA;
        return -1;
    }

    RSA_free (rsa);

    ssl = SSL_new (ssl_ctx);
    if (!ssl) {
        errno = ETLS;
        return -1;
    }

    return 0;
}

#endif