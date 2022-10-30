#ifndef BUS_H
#define BUS_H

#ifndef BUS_PRIVATE
#define BUS_PRIVATE __attribute__((deprecated))
#endif

#include <stdio.h>
#include "types.h"
#include "list.h"
#include "strmap.h"

typedef enum _bus_type bus_type_t;
typedef struct _bus bus_t;
typedef struct _bus_topic bus_topic_t;
typedef struct _bus_connection bus_connection_t;
struct _bus_topic {
    list_iterator_t it BUS_PRIVATE;
    const char *name;
    bool (*read)(bus_t *bus, bus_connection_t *connection, bus_topic_t *topic, strmap_t *options, FILE *in);
};

struct _bus {
    bool is_init BUS_PRIVATE;
    list_t topics BUS_PRIVATE;
    evlp_t *evlp BUS_PRIVATE;
    char *me BUS_PRIVATE;
    char *to BUS_PRIVATE;
    char *port BUS_PRIVATE;
    evlp_handler_t timerfd_handler BUS_PRIVATE;
    evlp_handler_t mcast_handler BUS_PRIVATE;
    evlp_handler_t server_handler BUS_PRIVATE;
    int timerfd BUS_PRIVATE;
    int mcast BUS_PRIVATE;
    int server BUS_PRIVATE;
    list_t connections BUS_PRIVATE;
    bool wait4connect BUS_PRIVATE;
};


/** Initialize a Bus instance between me and to. */
void bus_initialize(bus_t *bus, evlp_t *evlp, const char *me, const char *to);

/** Cleanup Bus instance */
void bus_cleanup(bus_t *bus);

/** Register a read handler on the specified bus and topic */
void bus_register_topic(bus_t *bus, bus_topic_t *topic);

/** Bus listen for TCP connections on the specified hostname and port */
bool bus_tcp_listen(bus_t *bus, const char *hostname, const char *port);

/** Bus establish TCP connection with the specified hostname and port */
bool bus_tcp_connect(bus_t *bus, const char *hostname, const char *port);

/** Bus try to discover a TCP connection through multicast and then connect to it */
bool bus_tcp_autoconnect(bus_t *bus);

/** Bus add ipc socket to connections */
bool bus_ipc_socket(bus_t *bus, int ipc);

/** Bus listen for IPC connections on the specified socket server */
bool bus_ipc_listen(bus_t *bus, int server);

/** Bus wait for at least one connection */
bool bus_wait4connect(bus_t *bus);

/** Return first connection from Bus */
bus_connection_t *bus_first_connection(bus_t *bus);

/** Return next connection */
bus_connection_t *bus_connection_next(bus_connection_t *current);

/**
 * Write request on bus connection.
 * Data is optional and retrieving data len is let
 * to user-implementation.
 * The request has the following format.
 *
 * > REQUEST:$TOPIC\n
 * > $KEY0:$VALUE0\n
 * > $KEY1:$VALUE1\n
 * > \n
 * > $DATA
 *
 */
bool bus_connection_write_request(bus_connection_t *connection, const char *topic, strmap_t *options);

FILE *bus_connection_reader(bus_connection_t *connection);
FILE *bus_connection_writer(bus_connection_t *connection);

/**
 * Write a reply on bus connection.
 * The reply is an optional message
 * or is let to user-implementation.
 *
 * < REQUEST:REPLY\n
 * < $KEY2:$VALUE2\n
 * < $KEY3:$VALUE3\n
 * < \n
 * < $DATA
 */
bool bus_connection_write_reply(bus_connection_t *connection, strmap_t *options);

/**
 * Read reply sent with bus_write_request()
 */
bool bus_connection_read_reply(bus_connection_t *connection, strmap_t *options);

bool bus_connection_readline(bus_connection_t *connection, char *line, size_t size);
bool bus_connection_printf(bus_connection_t *connection, char *fmt, ...);
bool bus_connection_flush(bus_connection_t *connection);
void bus_connection_close(bus_connection_t *connection);

#endif
