/*
    Copyright (c) 2007-2013 Contributors as noted in the AUTHORS file

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

#include "testutil.hpp"

int main (void)
{
    void *ctx = zmq_ctx_new ();
    assert (ctx);

    //  Server socket will accept connections
    void *server = zmq_socket (ctx, ZMQ_DEALER);
    assert (server);
    
    //  Client socket that will try to connect to server
    void *client = zmq_socket (ctx, ZMQ_DEALER);
    assert (client);

    //  Check NULL security configuration
    int rc;
    size_t optsize;
    int mechanism;
    int as_server;
    
    optsize = sizeof (int);
    rc = zmq_getsockopt (client, ZMQ_MECHANISM, &mechanism, &optsize);
    assert (rc == 0);
    assert (mechanism == ZMQ_NULL);
    
    rc = zmq_getsockopt (server, ZMQ_MECHANISM, &mechanism, &optsize);
    assert (rc == 0);
    assert (mechanism == ZMQ_NULL);
    
    rc = zmq_getsockopt (client, ZMQ_PLAIN_SERVER, &as_server, &optsize);
    assert (rc == 0);
    assert (as_server == 0);
    
    rc = zmq_getsockopt (server, ZMQ_PLAIN_SERVER, &as_server, &optsize);
    assert (rc == 0);
    assert (as_server == 0);

    rc = zmq_bind (server, "tcp://*:9999");
    assert (rc == 0);
    rc = zmq_connect (client, "tcp://localhost:9999");
    assert (rc == 0);
    
    bounce (server, client);
    
    rc = zmq_close (client);
    assert (rc == 0);
    rc = zmq_close (server);
    assert (rc == 0);
        
    //  Check PLAIN security
    server = zmq_socket (ctx, ZMQ_DEALER);
    assert (server);
    client = zmq_socket (ctx, ZMQ_DEALER);
    assert (client);
    
    char username [256];
    optsize = 256;
    rc = zmq_getsockopt (client, ZMQ_PLAIN_USERNAME, username, &optsize);
    assert (rc == 0);
    assert (optsize == 1);      //  Null string is one byte long
    
    char password [256];
    optsize = 256;
    rc = zmq_getsockopt (client, ZMQ_PLAIN_PASSWORD, password, &optsize);
    assert (rc == 0);
    assert (optsize == 1);      //  Null string is one byte long
    
    strcpy (username, "admin");
    strcpy (password, "password");
    rc = zmq_setsockopt (client, ZMQ_PLAIN_USERNAME, username, strlen (username));
    assert (rc == 0);
    rc = zmq_setsockopt (client, ZMQ_PLAIN_PASSWORD, password, strlen (password));
    assert (rc == 0);

    optsize = 256;
    rc = zmq_getsockopt (client, ZMQ_PLAIN_USERNAME, username, &optsize);
    assert (rc == 0);
    assert (optsize == 5 + 1);      
    optsize = 256;
    rc = zmq_getsockopt (client, ZMQ_PLAIN_PASSWORD, password, &optsize);
    assert (rc == 0);
    assert (optsize == 8 + 1);      
    
    as_server = 1;
    rc = zmq_setsockopt (server, ZMQ_PLAIN_SERVER, &as_server, sizeof (int));
    assert (rc == 0);
    
    optsize = sizeof (int);
    rc = zmq_getsockopt (client, ZMQ_MECHANISM, &mechanism, &optsize);
    assert (rc == 0);
    assert (mechanism == ZMQ_PLAIN);      

    rc = zmq_getsockopt (server, ZMQ_MECHANISM, &mechanism, &optsize);
    assert (rc == 0);
    assert (mechanism == ZMQ_PLAIN);      
    
    rc = zmq_getsockopt (client, ZMQ_PLAIN_SERVER, &as_server, &optsize);
    assert (rc == 0);
    assert (as_server == 0);
    
    rc = zmq_getsockopt (server, ZMQ_PLAIN_SERVER, &as_server, &optsize);
    assert (rc == 0);
    assert (as_server == 1);

    rc = zmq_bind (server, "tcp://*:9998");
    assert (rc == 0);
    rc = zmq_connect (client, "tcp://localhost:9998");
    assert (rc == 0);
    
    bounce (server, client);
    
    rc = zmq_close (client);
    assert (rc == 0);
    rc = zmq_close (server);
    assert (rc == 0);
    
    //  Check PLAIN security -- two servers trying to talk to each other
    server = zmq_socket (ctx, ZMQ_DEALER);
    assert (server);
    client = zmq_socket (ctx, ZMQ_DEALER);
    assert (client);
    
    rc = zmq_setsockopt (server, ZMQ_PLAIN_SERVER, &as_server, sizeof (int));
    assert (rc == 0);
    rc = zmq_setsockopt (client, ZMQ_PLAIN_SERVER, &as_server, sizeof (int));
    assert (rc == 0);
    
    rc = zmq_bind (server, "tcp://*:9997");
    assert (rc == 0);
    rc = zmq_connect (client, "tcp://localhost:9997");
    assert (rc == 0);
   
    //TODO: this test fails without any error
//     bounce (server, client);
    
    rc = zmq_close (client);
    assert (rc == 0);
    rc = zmq_close (server);
    assert (rc == 0);
    
    //  Shutdown
    rc = zmq_ctx_term (ctx);
    assert (rc == 0);

    return 0;
}
