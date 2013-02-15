/*
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

#ifndef __ZMQ_TLS_HPP_INCLUDED__
#define __ZMQ_TLS_HPP_INCLUDED__

#include "platform.hpp"

#if defined ZMQ_HAVE_TLS

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>

#include "../include/zmq.h"

namespace zmq
{
    class tls_stream_engine_t;

    int tls_password_callback (char* buffer_, int num_, int rwflag_, void *userdata_);

    int tls_verify_callback (int ok_, X509_STORE_CTX* store_);

    void print_tls_err ();

    void tls_info_callback (const SSL* s_, int where_, int ret_);

    int tls_stream_write (BIO* b_, const char* buf_, int num_);

    int tls_stream_read (BIO* b_, char* buf_, int size_);

    int tls_stream_puts (BIO* b_, const char* str_);

    long tls_stream_ctrl (BIO* b_, int cmd_, long arg1_, void *arg2_);

    int tls_stream_new (BIO* b_);

    int tls_stream_free (BIO* data_);

    BIO *BIO_new_stream (tls_stream_engine_t *engine_);
}

#endif

#endif