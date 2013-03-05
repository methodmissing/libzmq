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

int rc, val;
void *req, *rep;
void *paira, *pairb;
void *router, *dealer;
void *xpub, *xsub;
void *pub, *sub;
void *push, *pull;

//  Creates a TLS server socket
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

    if (addr_) {
        rc = zmq_bind (s, addr_);
        assert (rc != -1);
    }

    return s;
}

//  Creates a TLS client socket
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

    if (addr_) {
        rc = zmq_connect (s, addr_);
        assert (rc != -1);
    }

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

    //  Trusted CA directory socket option
    rc = zmq_setsockopt (rep, ZMQ_TLS_CA_DIR, "/a/path", 7);
    assert (rc == 0);

    size = 7;
    memset (buffer, 0, sizeof (buffer));
    rc = zmq_getsockopt (rep, ZMQ_TLS_CA_DIR, &buffer, &size);
    assert (rc == 0);
    assert (!strcmp ("/a/path", buffer));

    //  Trusted CA file socket option
    rc = zmq_setsockopt (rep, ZMQ_TLS_CA_FILE, "/a/file", 7);
    assert (rc == 0);

    size = 7;
    memset (buffer, 0, sizeof (buffer));
    rc = zmq_getsockopt (rep, ZMQ_TLS_CA_FILE, &buffer, &size);
    assert (rc == 0);
    assert (!strcmp ("/a/file", buffer));

    //  Certificate directory socket option
    rc = zmq_setsockopt (rep, ZMQ_TLS_CERT_DIR, "/a/path", 7);
    assert (rc == 0);

    size = 7;
    memset (buffer, 0, sizeof (buffer));
    rc = zmq_getsockopt (rep, ZMQ_TLS_CERT_DIR, &buffer, &size);
    assert (rc == 0);
    assert (!strcmp ("/a/path", buffer));

    //  Certificate file socket option
    rc = zmq_setsockopt (rep, ZMQ_TLS_CERT_FILE, "/a/file", 7);
    assert (rc == 0);

    size = 7;
    memset (buffer, 0, sizeof (buffer));
    rc = zmq_getsockopt (rep, ZMQ_TLS_CERT_FILE, &buffer, &size);
    assert (rc == 0);
    assert (!strcmp ("/a/file", buffer));

    //  Certificate file socket option
    size = sizeof (val);
    rc = zmq_getsockopt (rep, ZMQ_TLS_VERIFY_PEER, &val, &size);
    assert (rc == 0);
    assert (val == 1);

    //  Manipulate the underlying TLS handshake verification
    val = 0;
    rc = zmq_setsockopt (rep, ZMQ_TLS_VERIFY_PEER, &val, size);
    assert (rc == 0);

    rc = zmq_getsockopt (rep, ZMQ_TLS_VERIFY_PEER, &val, &size);
    assert (rc == 0);
    assert (val == 0);

    val = 1;
    rc = zmq_setsockopt (rep, ZMQ_TLS_VERIFY_PEER, &val, size);
    assert (rc == 0);

    //  Key file socket option
    rc = zmq_setsockopt (rep, ZMQ_TLS_KEY_FILE, "/a/file", 7);
    assert (rc == 0);

    //  Assert TLS specific error codes
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

    //  Certificate password socket option
    rc = zmq_setsockopt (rep, ZMQ_TLS_CERT_PASSWD, "password", 8);
    assert (rc == 0);

    size = 8;
    memset (buffer, 0, sizeof (buffer));
    rc = zmq_getsockopt (rep, ZMQ_TLS_CERT_PASSWD, &buffer, &size);
    assert (rc == 0);
    assert (!strcmp ("password", buffer));

    rc = zmq_close (rep);
    assert (rc == 0);

    //  Assert compatibility with unbind and disconnect semantics
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

    //  PAIR topology
    paira = tls_server_socket (ctx, ZMQ_PAIR, "tls://127.0.0.1:5580");

    pairb = tls_client_socket (ctx, ZMQ_PAIR, "tls://127.0.0.1:5580");
    
    bounce (paira, pairb);

    rc = zmq_close (paira);
    assert (rc == 0);

    rc = zmq_close (pairb);
    assert (rc == 0);

    //  ROUTER / DEALER topology

    //  Create a req/rep device.
    dealer = tls_server_socket (ctx, ZMQ_DEALER, "tls://127.0.0.1:5560");

    router = tls_server_socket (ctx, ZMQ_ROUTER, "tls://127.0.0.1:5561");

    //  Create a worker.
    rep = tls_client_socket (ctx, ZMQ_REP, "tls://127.0.0.1:5560");

    //  Create a client.
    req = tls_client_socket (ctx, ZMQ_REQ, "tls://127.0.0.1:5561");

    //  Send a request.
    rc = zmq_send (req, "ABC", 3, ZMQ_SNDMORE);
    assert (rc == 3);
    rc = zmq_send (req, "DEF", 3, 0);
    assert (rc == 3);

    //  Pass the request through the device.
    for (int i = 0; i != 4; i++) {
        zmq_msg_t msg;
        rc = zmq_msg_init (&msg);
        assert (rc == 0);
        rc = zmq_msg_recv (&msg, router, 0);
        assert (rc >= 0);
        int rcvmore;
        size_t sz = sizeof (rcvmore);
        rc = zmq_getsockopt (router, ZMQ_RCVMORE, &rcvmore, &sz);
        assert (rc == 0);
        rc = zmq_msg_send (&msg, dealer, rcvmore? ZMQ_SNDMORE: 0);
        assert (rc >= 0);
    }

    //  Receive the request.
    char buff [3];
    rc = zmq_recv (rep, buff, 3, 0);
    assert (rc == 3);
    assert (memcmp (buff, "ABC", 3) == 0);
    int rcvmore;
    size_t sz = sizeof (rcvmore);
    rc = zmq_getsockopt (rep, ZMQ_RCVMORE, &rcvmore, &sz);
    assert (rc == 0);
    assert (rcvmore);
    rc = zmq_recv (rep, buff, 3, 0);
    assert (rc == 3);
    assert (memcmp (buff, "DEF", 3) == 0);
    rc = zmq_getsockopt (rep, ZMQ_RCVMORE, &rcvmore, &sz);
    assert (rc == 0);
    assert (!rcvmore);

    //  Send the reply.
    rc = zmq_send (rep, "GHI", 3, ZMQ_SNDMORE);
    assert (rc == 3);
    rc = zmq_send (rep, "JKL", 3, 0);
    assert (rc == 3);

    //  Pass the reply through the device.
    for (int i = 0; i != 4; i++) {
        zmq_msg_t msg;
        rc = zmq_msg_init (&msg);
        assert (rc == 0);
        rc = zmq_msg_recv (&msg, dealer, 0);
        assert (rc >= 0);
        int rcvmore;
        rc = zmq_getsockopt (dealer, ZMQ_RCVMORE, &rcvmore, &sz);
        assert (rc == 0);
        rc = zmq_msg_send (&msg, router, rcvmore? ZMQ_SNDMORE: 0);
        assert (rc >= 0);
    }

    //  Receive the reply.
    rc = zmq_recv (req, buff, 3, 0);
    assert (rc == 3);
    assert (memcmp (buff, "GHI", 3) == 0);
    rc = zmq_getsockopt (req, ZMQ_RCVMORE, &rcvmore, &sz);
    assert (rc == 0);
    assert (rcvmore);
    rc = zmq_recv (req, buff, 3, 0);
    assert (rc == 3);
    assert (memcmp (buff, "JKL", 3) == 0);
    rc = zmq_getsockopt (req, ZMQ_RCVMORE, &rcvmore, &sz);
    assert (rc == 0);
    assert (!rcvmore);

    rc = zmq_close (req);
    assert (rc == 0);
    rc = zmq_close (rep);
    assert (rc == 0);
    rc = zmq_close (router);
    assert (rc == 0);
    rc = zmq_close (dealer);
    assert (rc == 0);

    //  Subscription forwarding

    //  First, create an intermediate device
    xpub = tls_server_socket (ctx, ZMQ_XPUB, "tls://127.0.0.1:5560");

    xsub = tls_server_socket (ctx, ZMQ_XSUB, "tls://127.0.0.1:5561");

    //  Create a publisher
    pub = tls_client_socket (ctx, ZMQ_PUB, "tls://127.0.0.1:5561");

    //  Create a subscriber
    sub = tls_client_socket (ctx, ZMQ_SUB, "tls://127.0.0.1:5560");

    //  Subscribe for all messages.
    rc = zmq_setsockopt (sub, ZMQ_SUBSCRIBE, "", 0);
    assert (rc == 0);

    //  Pass the subscription upstream through the device
    char b [32];
    rc = zmq_recv (xpub, b, sizeof (b), 0);
    assert (rc >= 0);
    rc = zmq_send (xsub, b, rc, 0);
    assert (rc >= 0);

    //  Wait a bit till the subscription gets to the publisher
    struct timespec t = { 0, 250 * 1000000 };
    nanosleep (&t, NULL);

    //  Send an empty message
    rc = zmq_send (pub, NULL, 0, 0);
    assert (rc == 0);

    //  Pass the message downstream through the device
    rc = zmq_recv (xsub, b, sizeof (b), 0);
    assert (rc >= 0);
    rc = zmq_send (xpub, b, rc, 0);
    assert (rc >= 0);

    //  Receive the message in the subscriber
    rc = zmq_recv (sub, b, sizeof (b), 0);
    assert (rc == 0);

    //  Clean up.
    rc = zmq_close (xpub);
    assert (rc == 0);
    rc = zmq_close (xsub);
    assert (rc == 0);
    rc = zmq_close (pub);
    assert (rc == 0);
    rc = zmq_close (sub);
    assert (rc == 0);

    //  PUSH / PULL topology
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

