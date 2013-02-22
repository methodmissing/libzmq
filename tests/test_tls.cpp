/*
    Copyright (c) 2010-2011 250bpm s.r.o.
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

#include "../include/zmq.h"
#include "../include/zmq_utils.h"
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include "testutil.hpp"

#undef NDEBUG
#include <assert.h>

void *req, *rep;
void *push, *pull;

void *tls_server_socket (void *ctx_, int type_, const char *addr_)
{
    int rc;
    void *s = zmq_socket (ctx_, type_);
    assert (s);

    rc = zmq_setsockopt (s, ZMQ_TLS_CA_FILE, "tls/test-ca.crt", 15);
    assert (rc == 0);

    rc = zmq_setsockopt (s, ZMQ_TLS_CERT_FILE, "tls/server.crt", 14);
    assert (rc == 0);

    rc = zmq_setsockopt (s, ZMQ_TLS_KEY_FILE, "tls/server.key", 14);
    assert (rc == 0);

    rc = zmq_bind (s, addr_);
    assert (rc != -1);

    return s;
}

void *tls_client_socket (void *ctx_, int type_, const char *addr_)
{
    int rc;
    void *s = zmq_socket (ctx_, type_);
    assert (s);

    rc = zmq_setsockopt (s, ZMQ_TLS_CA_FILE, "tls/test-ca.crt", 15);
    assert (rc == 0);

    rc = zmq_setsockopt (s, ZMQ_TLS_CERT_FILE, "tls/client.crt", 14);
    assert (rc == 0);

    rc = zmq_setsockopt (s, ZMQ_TLS_KEY_FILE, "tls/client.key", 14);
    assert (rc == 0);

    rc = zmq_connect (s, addr_);
    assert (rc != -1);

    return s;
}

int main (void)
{
    fprintf (stderr, "test_tls running...\n");

    int rc;
    size_t size;
    char buffer[9];

    //  Create the infrastructure
    void *ctx = zmq_init (1);
    assert (ctx);

    rep = zmq_socket (ctx, ZMQ_REP);
    assert (rep);

    rc = zmq_setsockopt (rep, ZMQ_TLS_CA_DIR, "/a/path", 7);
    assert (rc == 0);

    size = 7;
    memset (buffer, 0, sizeof (buffer));
    rc = zmq_getsockopt (rep, ZMQ_TLS_CA_DIR, &buffer, &size);
    assert (rc == 0);
    assert (!strcmp ("/a/path", buffer));

    rc = zmq_setsockopt (rep, ZMQ_TLS_CA_FILE, "/a/file", 7);
    assert (rc == 0);

    size = 7;
    memset (buffer, 0, sizeof (buffer));
    rc = zmq_getsockopt (rep, ZMQ_TLS_CA_FILE, &buffer, &size);
    assert (rc == 0);
    assert (!strcmp ("/a/file", buffer));

    rc = zmq_setsockopt (rep, ZMQ_TLS_CERT_DIR, "/a/path", 7);
    assert (rc == 0);

    size = 7;
    memset (buffer, 0, sizeof (buffer));
    rc = zmq_getsockopt (rep, ZMQ_TLS_CERT_DIR, &buffer, &size);
    assert (rc == 0);
    assert (!strcmp ("/a/path", buffer));

    rc = zmq_setsockopt (rep, ZMQ_TLS_CERT_FILE, "/a/file", 7);
    assert (rc == 0);

    size = 7;
    memset (buffer, 0, sizeof (buffer));
    rc = zmq_getsockopt (rep, ZMQ_TLS_CERT_FILE, &buffer, &size);
    assert (rc == 0);
    assert (!strcmp ("/a/file", buffer));

    rc = zmq_setsockopt (rep, ZMQ_TLS_KEY_FILE, "/a/file", 7);
    assert (rc == 0);

    size = 7;
    memset (buffer, 0, sizeof (buffer));
    rc = zmq_getsockopt (rep, ZMQ_TLS_KEY_FILE, &buffer, &size);
    assert (rc == 0);
    assert (!strcmp ("/a/file", buffer));

    rc = zmq_bind (rep, "tls://127.0.0.1:5560");
    assert (rc == -1);
    assert (errno == ETLSCA);

    rc = zmq_setsockopt (rep, ZMQ_TLS_CA_FILE, "tls/test-ca.crt", 15);
    assert (rc == 0);

    rc = zmq_bind (rep, "tls://127.0.0.1:5560");
    assert (rc == -1);
    assert (errno == ETLSCERT);

    rc = zmq_setsockopt (rep, ZMQ_TLS_CERT_FILE, "tls/server.crt", 14);
    assert (rc == 0);

    rc = zmq_bind (rep, "tls://127.0.0.1:5560");
    assert (rc == -1);
    assert (errno == ETLSKEY);

    rc = zmq_setsockopt (rep, ZMQ_TLS_KEY_FILE, "tls/server.key", 14);
    assert (rc == 0);

    rc = zmq_setsockopt (rep, ZMQ_TLS_CERT_PASSWD, "password", 8);
    assert (rc == 0);

    size = 8;
    memset (buffer, 0, sizeof (buffer));
    rc = zmq_getsockopt (rep, ZMQ_TLS_CERT_PASSWD, &buffer, &size);
    assert (rc == 0);
    assert (!strcmp ("password", buffer));

    rc = zmq_close (rep);
    assert (rc == 0);

    rep = tls_server_socket (ctx, ZMQ_REP, "tls://127.0.0.1:5560");

    req = tls_client_socket (ctx, ZMQ_REQ, "tls://127.0.0.1:5560");

    zmq_sleep (1);

    bounce (rep, req);

    rc = zmq_unbind (rep, "tls://127.0.0.1:5560");
    assert (rc == 0);

    zmq_sleep (1);

    rc = zmq_bind (rep, "tls://127.0.0.1:5560");
    assert (rc == 0);

    zmq_sleep (1);

    rc = zmq_disconnect (req, "tls://127.0.0.1:5560");
    assert (rc == 0);

    zmq_sleep (1);

    rc = zmq_connect (req, "tls://127.0.0.1:5560");
    assert (rc == 0);

    bounce (rep, req);

    rc = zmq_close (req);
    assert (rc == 0);

    rc = zmq_close (rep);
    assert (rc == 0);

    char buf [32];
    const char *content = "12345678ABCDEFGH12345678abcdefgh";

    push = tls_server_socket (ctx, ZMQ_PUSH, "tls://127.0.0.1:5580");

    pull = tls_client_socket (ctx, ZMQ_PULL, "tls://127.0.0.1:5580");

    zmq_sleep (2);

    rc = zmq_send (push, content, 32, 0);
    assert (rc == 32);

    rc = zmq_send (push, content, 32, 0);
    assert (rc == 32);

    rc = zmq_recv (pull, buf, 32, 0);
    assert (rc == 32);

    rc = zmq_recv (pull, buf, 32, 0);
    assert (rc == 32);

    rc = zmq_close (push);
    assert (rc == 0);

    rc = zmq_close (pull);
    assert (rc == 0);

    rc = zmq_term (ctx);
    assert (rc == 0);

    return 0 ;
}

