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

#ifndef __ZMQ_PLAIN_MECHANISM_HPP_INCLUDED__
#define __ZMQ_PLAIN_MECHANISM_HPP_INCLUDED__

#include "mechanism.hpp"
#include "options.hpp"

namespace zmq
{

    class msg_t;

    class plain_mechanism_t : public mechanism_t
    {
    public:

        plain_mechanism_t (const options_t &options_);
        virtual ~plain_mechanism_t ();

        // mechanism implementation
        virtual int next_handshake_message (msg_t *msg_);
        virtual int process_handshake_message (msg_t *msg_);
        virtual bool is_handshake_complete () const;

    private:

        enum state_t {
            sending_hello,
            waiting_for_hello,
            sending_welcome,
            waiting_for_welcome,
            sending_initiate,
            waiting_for_initiate,
            sending_ready,
            waiting_for_ready,
            ready
        };

        state_t state;

        int hello_command (msg_t *msg_) const;
        int welcome_command (msg_t *msg_) const;
        int initiate_command (msg_t *msg_) const;
        int ready_command (msg_t *msg_) const;

        int process_hello_command (msg_t *msg_);
        int process_welcome_command (msg_t *msg);
        int process_ready_command (msg_t *msg_);
        int process_initiate_command (msg_t *msg_);

        int parse_property_list (const unsigned char *ptr, size_t length);
    };

}

#endif
