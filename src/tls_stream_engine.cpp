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
    state (TLS_NONE),
    ssl (ssl_),
    listener (listener_),
    tls_read_needs_write (false),
    tls_write_needs_read (false)
{
    tls_start ();
}

int zmq::tls_stream_engine_t::tls_start ()
{
    if (state != TLS_NONE) {
        return -1;
    }

    if (!plugged) {
        state = TLS_WAIT;
        return 0;
    }

    state = TLS_CONNECTING;
    tls_begin ();

    return 0;
}

int zmq::tls_stream_engine_t::tls_begin ()
{
    assert (state = TLS_CONNECTING);

    SSL_set_app_data (ssl, this);

    BIO *bio = BIO_new_stream (this);
    if (!bio) {
        error ();
        return -1;
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

    tls_continue ();

    return 0;
}

void zmq::tls_stream_engine_t::tls_continue ()
{
    int rc;
    X509 *peer_cert;
    X509_name_st* name;
    char cname[512];

    assert (state == TLS_CONNECTING);

    if (listener) {
        rc = SSL_accept (ssl);
    } else {
        rc = SSL_connect (ssl);
    }

    switch (SSL_get_error (ssl, rc)) {
    case SSL_ERROR_NONE:
         state = TLS_CONNECTED;
         break;
    case SSL_ERROR_WANT_READ:
         break;
    case SSL_ERROR_WANT_WRITE:
         break;
    case SSL_ERROR_ZERO_RETURN:
    default:
         if (rc == 0)
             error ();
    }

    long verify_result = SSL_get_verify_result (ssl);
    if (verify_result == X509_V_OK) {
        peer_cert = SSL_get_peer_certificate (ssl);
        if (options.tls_cert_common_name_size && peer_cert) {
            name = X509_get_subject_name (peer_cert);
            X509_NAME_get_text_by_NID (name, NID_commonName, cname, 512);
            cname[sizeof(cname)-1] = 0;
            if (strcmp ((const char *)options.tls_cert_common_name, cname) != 0) {
                errno = ETLSCNAME;
                goto error;
            }
        }
    } else {
        errno = ETLSVERIFY;
        goto error;
    }

    X509_free (peer_cert);
    return;

error:
    int err = errno;
    tls_error ();
    rm_fd (handle);
    errno = err;
}

void zmq::tls_stream_engine_t::plug (io_thread_t *io_thread_,
    session_base_t *session_)
{
    zmq::stream_engine_t::plug (io_thread_, session_);
    state = TLS_CONNECTING;
    tls_begin ();
}

zmq::tls_stream_engine_t::~tls_stream_engine_t ()
{
}

void zmq::tls_stream_engine_t::unplug ()
{
    state = TLS_NONE;
    tls_read_needs_write = false;
    tls_write_needs_read = false;
    zmq::stream_engine_t::unplug ();
}

void zmq::tls_stream_engine_t::tls_term ()
{
    int rc;
    if (ssl) {
        rc = SSL_shutdown (ssl);
        if (rc == 0)
            SSL_shutdown (ssl);
        SSL_free (ssl);
        ssl = NULL;
    }
}

void zmq::tls_stream_engine_t::tls_error ()
{
    state = TLS_ERROR;

    tls_term ();
}

void zmq::tls_stream_engine_t::error ()
{
    tls_error ();
    zmq::stream_engine_t::error ();
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
    switch (state) {
    case TLS_NONE:
        return zmq::stream_engine_t::write (data_, size_);

    case TLS_WAIT:
    case TLS_CONNECTING:
        errno = EAGAIN;
        return 0;

    case TLS_CONNECTED:
        break;
    case TLS_ERROR:
        return -1;
        break;
    }

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
         return 0;
         break;
    case SSL_ERROR_WANT_WRITE:
         errno = EAGAIN;
         return 0;
         break;
    case SSL_ERROR_ZERO_RETURN:
         return -1;
         break;
    default:
         break;
    }

  return nbytes;
}

int zmq::tls_stream_engine_t::read (void *data_, size_t size_)
{
    switch (state) {
    case TLS_NONE:
        return zmq::stream_engine_t::read (data_, size_);

    case TLS_WAIT:
    case TLS_CONNECTING:
        errno = EAGAIN;
        return 0;

    case TLS_CONNECTED:
        break;
    case TLS_ERROR:
        return -1;
        break;
    }

    if (size_ == 0)
        return 0;

    tls_read_needs_write = false;

    int nbytes = SSL_read (ssl, data_, size_);

    switch (SSL_get_error (ssl, nbytes)) {
    case SSL_ERROR_NONE:
         return nbytes;
    case SSL_ERROR_WANT_READ:
         errno = EAGAIN;
         return 0;
         break;
    case SSL_ERROR_WANT_WRITE:
         tls_read_needs_write = true;
         errno = EAGAIN;
         return 0;
         break;
    case SSL_ERROR_ZERO_RETURN:
         return -1;
         break;
    default:
         break;
    }

    if (nbytes == 0)
        return -1;

    return nbytes;
}

void zmq::tls_stream_engine_t::in_event ()
{
    if (state == TLS_NONE) {
        zmq::stream_engine_t::in_event ();
        return;
    }

    if (state == TLS_CONNECTING) {
        tls_continue ();
        return;
    }

    if (state != TLS_CONNECTED)
        return;

    if (tls_write_needs_read)
        zmq::stream_engine_t::out_event ();

    zmq::stream_engine_t::in_event ();
}

void zmq::tls_stream_engine_t::out_event ()
{
    if (state == TLS_NONE) {
        zmq::stream_engine_t::out_event ();
        return;
    }

    if (state == TLS_CONNECTING) {
        tls_continue ();
        return;
    }

    if (state != TLS_CONNECTED)
        return;

    if (tls_read_needs_write)
        zmq::stream_engine_t::in_event ();

    zmq::stream_engine_t::out_event ();
}

#endif