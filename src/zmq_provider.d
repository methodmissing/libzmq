provider zmq {
    /* Custom user probe */
    probe trace__start(char *msg, void *obj);
    probe trace__done(char *msg, void *obj);
};

#pragma D attributes Stable/Stable/Common	provider zmq provider
#pragma D attributes Stable/Stable/Common	provider zmq module
#pragma D attributes Stable/Stable/Common	provider zmq function
#pragma D attributes Stable/Stable/Common	provider zmq name
#pragma D attributes Stable/Stable/Common	provider zmq args