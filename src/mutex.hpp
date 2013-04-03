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

#ifndef __ZMQ_MUTEX_HPP_INCLUDED__
#define __ZMQ_MUTEX_HPP_INCLUDED__

#include "platform.hpp"
#include "err.hpp"

//  Mutex class encapsulates OS mutex in a platform-independent way.

#ifdef ZMQ_HAVE_WINDOWS

#include "windows.hpp"

#define MUTEX_TYPE CRITICAL_SECTION
#define MUTEX_SETUP(x) InitializeCriticalSection(&(x))
#define MUTEX_CLEANUP(x) DeleteCriticalSection(&(x))
#define MUTEX_LOCK(x) EnterCriticalSection(&(x))
#define MUTEX_UNLOCK(x) LeaveCriticalSection(&(x))
#define THREAD_ID GetCurrentThreadId()

#else

#include <pthread.h>

#define MUTEX_TYPE pthread_mutex_t
#define MUTEX_SETUP(x) pthread_mutex_init(&(x), NULL)
#define MUTEX_CLEANUP(x) pthread_mutex_destroy(&(x))
#define MUTEX_LOCK(x) pthread_mutex_lock(&(x))
#define MUTEX_UNLOCK(x) pthread_mutex_unlock(&(x))
#define THREAD_ID pthread_self()

#endif

namespace zmq
{

    class mutex_t
    {
    public:
        inline mutex_t ()
        {
            MUTEX_SETUP (mutex);
        }

        inline ~mutex_t ()
        {
            MUTEX_CLEANUP (mutex);
        }

        inline void lock ()
        {
            MUTEX_LOCK (mutex);
        }

        inline void unlock ()
        {
            MUTEX_UNLOCK (mutex);
        }

    private:

        MUTEX_TYPE mutex;

        //  Disable copy construction and assignment.
        mutex_t (const mutex_t&);
        void operator = (const mutex_t&);
    };

}

#endif
