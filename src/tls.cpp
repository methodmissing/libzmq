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

namespace zmq
{

    int tls_password_callback (char* buffer_, int num_, int rwflag_, void* userdata_) {
        char *cert_passwd = (char*) userdata_;
        if ((!cert_passwd) || num_ < (strlen (cert_passwd) + 1)) {
            errno = ESSLPASS;
            return 0;
        }
        strcpy (buffer_, cert_passwd);
        return strlen (cert_passwd);
    }

    int tls_verify_callback (int ok_, X509_STORE_CTX* store_) {
        if (!ok_)
            errno = ESSLCERT;

         return ok_;
    }

    void print_ssl_err ()
    {
        int err;
        while ((err = ERR_get_error())) {
            const char *msg = (const char*)ERR_reason_error_string (err);
            const char *lib = (const char*)ERR_lib_error_string (err);
            const char *func = (const char*)ERR_func_error_string (err);

            printf("%s in %s %s\n", msg, lib, func);
        }
    }
}

#endif