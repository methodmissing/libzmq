/*
    Copyright (c) 2010-2011 250bpm s.r.o.
    Copyright (c) 2011 VMware, Inc.
    Copyright (c) 2010-2011 Other contributors as noted in the AUTHORS file

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

#include "tls.hpp"
#include "tls_stream_engine.hpp"

namespace zmq
{

    int tls_password_callback (char* buffer_, int num_, int rwflag_, void* userdata_) {
        char *cert_passwd = (char*) userdata_;
        if ((!cert_passwd) || num_ < (int)(strlen (cert_passwd) + 1)) {
            errno = ETLSPASS;
            return 0;
        }
        strcpy (buffer_, cert_passwd);
        return strlen (cert_passwd);
    }

    int tls_verify_callback (int ok_, X509_STORE_CTX* store_) {
        if (!ok_)
            errno = ETLSCERT;

         return ok_;
    }

    static BIO_METHOD tls_methods_stream = {
      BIO_TYPE_BIO,
      "stream",
      tls_stream_write,
      tls_stream_read,
      tls_stream_puts,
      0,
      tls_stream_ctrl,
      tls_stream_new,
      tls_stream_free,
      NULL,
    };

    BIO_METHOD* BIO_s_stream() { return (&tls_methods_stream); }

    int tls_stream_write (BIO* b_, const char* buf_, int size_)
    {
        if (!buf_)
            return -1;

        zmq::tls_stream_engine_t *engine = static_cast<zmq::tls_stream_engine_t *> (b_->ptr);
        BIO_clear_retry_flags (b_);
        int nbytes = engine->write_plaintext (buf_, size_);
        if (nbytes > 0) {
            return nbytes;
        } else if (nbytes == -1) {
            b_->num = 1;
#ifdef ZMQ_HAVE_WINDOWS
        } else if (nbytes == 0 && WSAGetLastError () == WSAEWOULDBLOCK) {
#else
        } else if (nbytes == 0 && errno == EAGAIN) {
#endif
            BIO_set_retry_write (b_);
        }
        return -1;
    }

    int tls_stream_read (BIO* b_, char* buf_, int size_)
    {
        if (!buf_) {
            return -1;
        }

        zmq::tls_stream_engine_t *engine = static_cast<zmq::tls_stream_engine_t *> (b_->ptr);   

        BIO_clear_retry_flags (b_);
        int nbytes = engine->read_plaintext (buf_, size_);
        if (nbytes > 0) {
            return nbytes;
        } else if (nbytes == -1) {
            b_->num = 1;
#ifdef ZMQ_HAVE_WINDOWS
        } else if (nbytes == 0 && WSAGetLastError () == WSAEWOULDBLOCK) {
#else
        } else if (nbytes == 0 && errno == EAGAIN) {
#endif
            BIO_set_retry_read (b_);
        }
        return -1;
    }

    int tls_stream_puts (BIO* b_, const char *str_)
    {
        return tls_stream_write (b_, str_, strlen (str_));
    }

    long tls_stream_ctrl (BIO* b_, int cmd_, long arg1_, void *arg2_)
    {
        switch (cmd_) {
        case BIO_CTRL_RESET:
             return 0;
        case BIO_CTRL_EOF:
             return b_->num;
        case BIO_CTRL_WPENDING:
        case BIO_CTRL_PENDING:
             return 0;
        case BIO_CTRL_FLUSH:
             return 1;
        default:
             return 0;
        }
    }

    int tls_stream_new (BIO* b_)
    {
        b_->shutdown = 0;
        b_->init = 1;
        b_->num = 0;
        b_->ptr = 0;
        return 1;
    }

    int tls_stream_free (BIO* b_)
    {
        if (b_ == NULL)  
            return 0;
        return 1;
    }

    BIO *BIO_new_stream (zmq::tls_stream_engine_t *engine_)
    {
        BIO* ret = BIO_new (BIO_s_stream ());
        if (ret == NULL)
            return NULL;
        ret->ptr = engine_;
        return ret;
    }

    void print_tls_err ()
    {
        int err;
        while ((err = ERR_get_error())) {
            const char *msg = (const char*)ERR_reason_error_string (err);
            const char *lib = (const char*)ERR_lib_error_string (err);
            const char *func = (const char*)ERR_func_error_string (err);

            printf("%s in %s %s\n", msg, lib, func);
        }
    }

    void tls_info_callback (const SSL* s_, int where_, int ret_) {
        const char* str = "undefined";
        int w = where_ & ~SSL_ST_MASK;
        if (w & SSL_ST_CONNECT) {
            str = "SSL_connect";
        } else if (w & SSL_ST_ACCEPT) {
            str = "SSL_accept";
        }
        if (where_ & SSL_CB_LOOP) {
            printf("TLS %p: %s:%s\n", s_, str, SSL_state_string_long (s_));
        } else if (where_ & SSL_CB_ALERT) {
            printf("TLS %p: %s:%s:%s\n", s_, ((where_ & SSL_CB_READ) ? "read" : "write"), SSL_alert_type_string_long (ret_), SSL_alert_desc_string_long (ret_));
        } else if (where_ & SSL_CB_EXIT) {
            if (ret_ == 0) {
                printf("TLS %p: %s failed in %s\n", s_, str, SSL_state_string_long (s_));
            } else if (ret_ < 0) {
                printf("TLS %p: %s error in %s\n", s_, str, SSL_state_string_long (s_));
            }
       }
    }
}

#endif