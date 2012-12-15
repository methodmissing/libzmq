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

#ifdef ZMQ_HAVE_TLS

#if defined ZMQ_HAVE_WINDOWS
#include "windows.hpp"
#endif

#include <string.h>
#include <new>

#include "tls_stream_engine.hpp"

zmq::tls_stream_engine_t::tls_stream_engine_t (SSL *ssl_, bool listener_, const options_t &options_, const std::string &endpoint_) :
    stream_engine_t (SSL_get_fd (ssl_), options_, endpoint_),
    ssl (ssl_),
    listener (listener_),
    tls_read_needs_write (false),
    tls_write_needs_read (false)
{
    tls_init ();
}

void zmq::tls_stream_engine_t::plug (io_thread_t *io_thread_,
    session_base_t *session_)
{
    zmq::stream_engine_t::plug (io_thread_, session_);
    tls_handshake ();
}

void zmq::tls_stream_engine_t::tls_init ()
{
    SSL_set_app_data (ssl, this);

    BIO *bio = BIO_new_stream (static_cast<zmq::tls_stream_engine_t *>(this));
    if (!bio) {
        error ();
        return;
    }

    BIO_set_nbio (bio, 1);
    SSL_set_mode (ssl, SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
    SSL_set_bio (ssl, bio, bio);

    bio = NULL;

    if (listener) {
        SSL_set_accept_state (ssl);
    } else {
        SSL_set_connect_state (ssl);
    }
}

zmq::tls_stream_engine_t::~tls_stream_engine_t ()
{
}

int zmq::tls_stream_engine_t::tls_handshake ()
{
    int rc;

    if (SSL_is_init_finished (ssl))
        return 0;

    if (listener) {
        rc = SSL_accept (ssl);
    } else {
        rc = SSL_connect (ssl);
    }

    switch (SSL_get_error (ssl, rc)) {
    case SSL_ERROR_NONE:
         break;
    case SSL_ERROR_WANT_READ:
         break;
    case SSL_ERROR_WANT_WRITE:
         break;
    case SSL_ERROR_ZERO_RETURN:
    default:
         return (rc != 0) ? rc : -1;
      }

    return 0;
}

int zmq::tls_stream_engine_t::write_plaintext (const void *data_, size_t size_)
{
    return zmq::stream_engine_t::write (data_, size_);
}

int zmq::tls_stream_engine_t::read_plaintext (void *data_, size_t size_)
{
    return zmq::stream_engine_t::read (data_, size_);
}

int zmq::tls_stream_engine_t::write (const void *data_, size_t size_)
{
    if (size_ == 0)
        return 0;

    tls_write_needs_read = false;

    int nbytes = SSL_write (ssl, data_, size_);
    switch (SSL_get_error (ssl, nbytes)) {
    case SSL_ERROR_NONE:
         return nbytes;
    case SSL_ERROR_WANT_READ:
         tls_write_needs_read = true;
         errno = EAGAIN;
         break;
    case SSL_ERROR_WANT_WRITE:
         errno = EAGAIN;
         break;
    case SSL_ERROR_ZERO_RETURN:
         errno = EAGAIN;
         break;
    default:
         break;
    }

  return 0;
}

int zmq::tls_stream_engine_t::read (void *data_, size_t size_)
{
    if (size_ == 0)
        return 0;

    tls_read_needs_write = false;

    int nbytes = SSL_read (ssl, data_, size_);
    switch (SSL_get_error (ssl, nbytes)) {
    case SSL_ERROR_NONE:
         return nbytes;
    case SSL_ERROR_WANT_READ:
         errno = EAGAIN;
         break;
    case SSL_ERROR_WANT_WRITE:
         tls_read_needs_write = true;
         errno = EAGAIN;
         break;
    case SSL_ERROR_ZERO_RETURN:
         errno = EAGAIN;
         break;
    default:
         break;
    }

    return 0;
}

void zmq::tls_stream_engine_t::in_event ()
{
    if (tls_handshake () != 0)
        return;

    if (!SSL_is_init_finished (ssl))
        return;

    if (tls_write_needs_read)  {
        zmq::stream_engine_t::out_event ();
    }

    zmq::stream_engine_t::in_event ();
}

void zmq::tls_stream_engine_t::out_event ()
{
    if (tls_handshake () != 0)
        return;

    if (!SSL_is_init_finished (ssl))
        return;

    if (tls_read_needs_write)  {
        zmq::stream_engine_t::in_event ();
    }

    zmq::stream_engine_t::out_event ();
}

#endif