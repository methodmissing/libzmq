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

zmq::tls_stream_engine_t::tls_stream_engine_t (SSL *ssl_, const options_t &options_, const std::string &endpoint_) :
    stream_engine_t (SSL_get_fd (ssl_), options_, endpoint_),
    ssl (ssl_)
{
}

zmq::tls_stream_engine_t::~tls_stream_engine_t ()
{
}

int zmq::tls_stream_engine_t::write (const void *data_, size_t size_)
{
    int err;
    ERR_clear_error();
    ssize_t nbytes = SSL_write (ssl, data_, size_);

    if (nbytes < 0){
        switch (err = SSL_get_error (ssl, nbytes)) {
        case SSL_ERROR_WANT_READ:
#ifdef ZMQ_HAVE_WINDOWS
            WSASetLastError (WSAEWOULDBLOCK);
#else
            errno = EAGAIN;
#endif
            nbytes = -1;
            break;
        case SSL_ERROR_WANT_WRITE:
#ifdef ZMQ_HAVE_WINDOWS
            WSASetLastError (WSAEWOULDBLOCK);
#else
            errno = EAGAIN;
#endif
            nbytes = -1;
            break;
         case SSL_ERROR_SYSCALL:
            if (ERR_get_error () == 0)
                return -1;
            break;
         case SSL_ERROR_ZERO_RETURN:
            return -1;
         default:
            break;
         }
    }

#ifdef ZMQ_HAVE_WINDOWS

    //  If not a single byte can be written to the socket in non-blocking mode
    //  we'll get an error (this may happen during the speculative write).
    if (nbytes == SOCKET_ERROR && WSAGetLastError () == WSAEWOULDBLOCK)
        return 0;
		
    //  Signalise peer failure.
    if (nbytes == SOCKET_ERROR && (
          WSAGetLastError () == WSAENETDOWN ||
          WSAGetLastError () == WSAENETRESET ||
          WSAGetLastError () == WSAEHOSTUNREACH ||
          WSAGetLastError () == WSAECONNABORTED ||
          WSAGetLastError () == WSAETIMEDOUT ||
          WSAGetLastError () == WSAECONNRESET))
        return -1;

    wsa_assert (nbytes != SOCKET_ERROR);
    return nbytes;

#else

    //  Several errors are OK. When speculative write is being done we may not
    //  be able to write a single byte from the socket. Also, SIGSTOP issued
    //  by a debugging tool can result in EINTR error.
    if (nbytes == -1 && (errno == EAGAIN || errno == EWOULDBLOCK ||
          errno == EINTR))
        return 0;

    //  Signalise peer failure.
    if (nbytes == -1) {
        errno_assert (errno != EACCES
                   && errno != EBADF
                   && errno != EDESTADDRREQ
                   && errno != EFAULT
                   && errno != EINVAL
                   && errno != EISCONN
                   && errno != EMSGSIZE
                   && errno != ENOMEM
                   && errno != ENOTSOCK
                   && errno != EOPNOTSUPP);
        return -1;
    }

    return (size_t) nbytes;

#endif
}

int zmq::tls_stream_engine_t::read (void *data_, size_t size_)
{
    int err;
    ERR_clear_error();
    ssize_t nbytes = SSL_read (ssl, data_, size_);

    if (nbytes <= 0){
        switch (err = SSL_get_error (ssl, nbytes)) {
        case SSL_ERROR_WANT_READ:
#ifdef ZMQ_HAVE_WINDOWS
            WSASetLastError (WSAEWOULDBLOCK);
#else
            errno = EAGAIN;
#endif
            nbytes = -1;
            break;
        case SSL_ERROR_WANT_WRITE:
#ifdef ZMQ_HAVE_WINDOWS
            WSASetLastError (WSAEWOULDBLOCK);
#else
            errno = EAGAIN;
#endif
            nbytes = -1;
            break;
         case SSL_ERROR_SYSCALL:
            if (ERR_get_error () == 0)
                return -1;
            break;
         case SSL_ERROR_ZERO_RETURN:
            return -1;
         default:
            break;
         }
    }

#ifdef ZMQ_HAVE_WINDOWS

    //  If not a single byte can be read from the socket in non-blocking mode
    //  we'll get an error (this may happen during the speculative read).
    if (nbytes == SOCKET_ERROR && WSAGetLastError () == WSAEWOULDBLOCK)
        return 0;

    //  Connection failure.
    if (nbytes == SOCKET_ERROR && (
          WSAGetLastError () == WSAENETDOWN ||
          WSAGetLastError () == WSAENETRESET ||
          WSAGetLastError () == WSAECONNABORTED ||
          WSAGetLastError () == WSAETIMEDOUT ||
          WSAGetLastError () == WSAECONNRESET ||
          WSAGetLastError () == WSAECONNREFUSED ||
          WSAGetLastError () == WSAENOTCONN))
        return -1;

    wsa_assert (nbytes != SOCKET_ERROR);

    //  Orderly shutdown by the other peer.
    if (nbytes == 0)
        return -1; 

    return nbytes;

#else
    //  Several errors are OK. When speculative read is being done we may not
    //  be able to read a single byte from the socket. Also, SIGSTOP issued
    //  by a debugging tool can result in EINTR error.
    if (nbytes == -1 && (errno == EAGAIN || errno == EWOULDBLOCK ||
          errno == EINTR))
        return 0;

    //  Signalise peer failure.
    if (nbytes == -1) {
        errno_assert (errno != EBADF
                   && errno != EFAULT
                   && errno != EINVAL
                   && errno != ENOMEM
                   && errno != ENOTSOCK);
        return -1;
    }

    //  Orderly shutdown by the peer.
    if (nbytes == 0)
        return -1;

    return (size_t) nbytes;

#endif
}

#endif