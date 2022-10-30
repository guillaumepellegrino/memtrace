#define BUS_PRIVATE
#define _GNU_SOURCE
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/sendfile.h>
#include <sys/epoll.h>
#include <sys/timerfd.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <stdarg.h>
#include "bus.h"
#include "evlp.h"
#include "net.h"
#include "log.h"

#define BUS_DEFAULT_MCASTADDR "224.0.0.251"
#define BUS_DEFAULT_BINDADDR "::0"
#define BUS_DEFAULT_PORT "3002"

static const struct itimerspec MCAST_ITIMER = {
    .it_interval.tv_sec = 60,
    .it_value.tv_nsec = 1,
};

enum _bus_type {
    bus_type_undefined = 0,
    bus_type_unix,
    bus_type_tcp_client,
    bus_type_tcp_server,
};

struct _bus_connection {
    list_iterator_t it;
    FILE *in;
    FILE *out;
    evlp_handler_t read_handler;
};

typedef struct {
    char msgtype[32]; /** message type: ["announce", "query" ] */
    char service[32]; /** service name: ["memtrace", "memtrace-server" ] */
    char from[INET6_ADDRSTRLEN] /** source ip address from packet sender */;
    char port[8]; /** service port */
    struct sockaddr_in sockaddr;
    socklen_t sockaddrlen;
} mcast_msg_t;

static bool bus_is_server(bus_t *bus) {
    return bus->server >= 0;
}

bus_t *bus_from_connection(bus_connection_t *connection) {
    bus_t *bus = NULL;
    list_t *list = NULL;

    if (connection) {
        if ((list = connection->it.list)) {
            bus = container_of(list, bus_t, connections);
        }
    }

    return bus;
}

bus_connection_t *bus_first_connection(bus_t *bus) {
    bus_connection_t *connection = NULL;
    list_iterator_t *it = NULL;

    if (bus) {
        if ((it = list_first(&bus->connections))) {
            connection = container_of(it, bus_connection_t, it);
        }
    }

    return connection;
}

bus_connection_t *bus_connection_next(bus_connection_t *current) {
    bus_connection_t *connection = NULL;
    list_iterator_t *it = NULL;

    if (current) {
        if ((it = list_iterator_next(&current->it))) {
            connection = container_of(it, bus_connection_t, it);
        }
    }

    return connection;
}

void bus_connection_close(bus_connection_t *connection) {
    if (connection) {
        list_iterator_take(&connection->it);
        if (connection->in) {
            fclose(connection->in);
        }
        if (connection->out) {
            fclose(connection->out);
        }
        free(connection);
    }
}

/** Read bus connection request from socket */
static void bus_connection_read_handler(evlp_handler_t *self, int events) {
    char line[4096];
    bus_connection_t *connection = container_of(self, bus_connection_t, read_handler);
    bus_t *bus = bus_from_connection(connection);
    bool rt = false;
    const char *sep = ":\n\r\t";
    const char *key = NULL;
    const char *value = NULL;
    strmap_t options = {0};
    const char *req = NULL;
    list_iterator_t *it = NULL;

    while (true) {
        if (!fgets(line, sizeof(line), connection->in)) {
            CONSOLE("Client connection to %s closed", bus->to);
            goto error;
        }

        key = strtok(line, sep);
        value = strtok(NULL, sep);
        if (!key) {
            break;
        }

        strmap_add(&options, key, value?value:"");
    }
    if (!(req = strmap_get(&options, "REQUEST"))) {
        TRACE_ERROR("Read buffer is not a bus request");
        goto error;
    }

    list_for_each(it, &bus->topics) {
        bus_topic_t *topic = container_of(it, bus_topic_t, it);
        if (!strcmp(topic->name, req)) {
            if (topic->read) {
                if (!topic->read(bus, connection, topic, &options, connection->in)) {
                    TRACE_ERROR("Failed to handle request '%s'", req);
                    goto error;
                }
            }
            rt = true;
            break;
        }
    }
    when_true(ferror(connection->in), error);
    when_true(feof(connection->in), error);
    rt = true;

error:
    if (!rt) {
        bus_connection_close(connection);
    }
    strmap_cleanup(&options);
}

bool bus_add_connection(bus_t *bus, int s) {
    bool rt = false;
    bus_connection_t *connection = NULL;

    when_null(bus, error);
    when_true(s < 0, error);
    when_null(connection = calloc(1, sizeof(bus_connection_t)), error);
    when_null(connection->in = fdopen(s, "w+"), error);
    when_null(connection->out = fdopen(dup(s), "w+"), error);
    connection->read_handler.fn = bus_connection_read_handler;
    when_true(!evlp_add_handler(bus->evlp, &connection->read_handler, s, EPOLLIN), error);
    list_append(&bus->connections, &connection->it);
    if (bus->wait4connect) {
        evlp_stop(bus->evlp);
    }
    rt = true;

error:
    if (!rt) {
        bus_connection_close(connection);
    }
    return rt;
}

/** Announce the service on the specified port on the multicast socket */
static bool mcast_announce(int mcast, const char *me, const char *port) {
    char buff[512];
    int len = snprintf(buff, sizeof(buff),
        "msgtype: announce\n"
        "service: %s\n"
        "port: %s\n",
        me, port);

    if (mcast_send(mcast, buff, len, BUS_DEFAULT_MCASTADDR, BUS_DEFAULT_PORT) <= 0) {
        TRACE_ERROR("Failed to announce service: %m");
        return false;
    }

    return true;
}

bool ucast_announce(const char *me, const char *port, struct sockaddr_in *dst, size_t dstlen) {
    char buff[512];

    int s = -1;
    int len = snprintf(buff, sizeof(buff),
        "msgtype: announce\n"
        "service: %s\n"
        "port: %s\n",
        me, port);
    if ((s = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        TRACE_ERROR("Failed to create UDP socket: %m");
        return false;
    }
    if (sendto(s, buff, len, 0, (struct sockaddr *) dst, dstlen) <= 0) {
        TRACE_ERROR("Failed to announce service: %m");
    }
    close(s);

    return true;
}

/** Query the specified service on the multicast socket */
static bool mcast_query(int mcast, const char *tgt) {
    char buff[512];
    int len = snprintf(buff, sizeof(buff),
        "msgtype: query\n"
        "service: %s\n",
        tgt);

    if (mcast_send(mcast, buff, len, BUS_DEFAULT_MCASTADDR, BUS_DEFAULT_PORT) <= 0) {
        TRACE_ERROR("Failed to announce service: %m");
        return false;
    }

    return true;
}

/** handle timer expiration: announce the service through multicast */
static void bus_timerfd_handler(evlp_handler_t *self, int events) {
    bus_t *bus = container_of(self, bus_t, timerfd_handler);
    uint64_t value = 0;

    if (read(bus->timerfd, &value, sizeof(value)) < 0) {
        TRACE_ERROR("read timer error: %m");
        sleep(1);
        return;
    }

    if (bus_is_server(bus)) {
        mcast_announce(bus->mcast, bus->me, bus->port);
    }
    else {
        mcast_query(bus->mcast, bus->to);
    }
}

/** Read a message from the multicast socket */
static bool bus_mcast_read(int mcast, mcast_msg_t *msg) {
    char buff[512];
    ssize_t len;
    const char *sep = ":\n\r\t ";
    const char *key = NULL;
    const char *value = NULL;

    memset(msg, 0, sizeof(*msg));

    msg->sockaddrlen = sizeof(msg->sockaddr);
    if ((len = recvfrom(mcast, buff, sizeof(buff), 0, &msg->sockaddr, &msg->sockaddrlen)) <= 0) {
        TRACE_ERROR("Failed to read multicast message: %m");
        return false;
    }
    inet_ntop(AF_INET, &msg->sockaddr.sin_addr, msg->from, msg->sockaddrlen);

    key = strtok(buff, sep);
    value = strtok(NULL, sep);

    while (key && value) {
        if (!strcmp(key, "msgtype")) {
            snprintf(msg->msgtype, sizeof(msg->msgtype), "%s", value);
        }
        if (!strcmp(key, "service")) {
            snprintf(msg->service, sizeof(msg->service), "%s", value);
        }
        if (!strcmp(key, "port")) {
            snprintf(msg->port, sizeof(msg->port), "%s", value);
        }
        key = strtok(NULL, sep);
        value = strtok(NULL, sep);
    }

    return true;
}

static void bus_mcast_handle_query(bus_t *bus, mcast_msg_t *query) {
    if (!strcmp(query->service, bus->me)) {
        // We are being queried.
        // Let's tell who we are.
        CONSOLE("Multicast query received. Announce me");
        //ucast_announce(bus->me, bus->port, &query->sockaddr, query->sockaddrlen);
        mcast_announce(bus->mcast, bus->me, bus->port);
    }
}

static void bus_mcast_handle_announce(bus_t *bus, mcast_msg_t *announce) {
    if (!strcmp(announce->service, bus->to)) {
        // We have find the device we were looking for
        // Let's connect
        CONSOLE("%s announced on %s:%s",
            announce->service, announce->from, announce->port);
        if (!bus_add_connection(bus, tcp_connect(announce->from, announce->port))) {
            TRACE_ERROR("Failed to connect");
            return;
        }
        CONSOLE("Client connected to %s:%s", announce->from, announce->port);
        // we can stop mcast query timer
        if (bus->timerfd >= 0) {
            close(bus->timerfd);
            bus->timerfd = -1;
        }
        if (bus->mcast >= 0) {
            close(bus->mcast);
            bus->mcast = -1;
        }
        if (bus->wait4connect) {
            evlp_stop(bus->evlp);
        }
    }
}

static void bus_mcast_handler(evlp_handler_t *self, int events) {
    mcast_msg_t msg = {0};
    bus_t *bus = container_of(self, bus_t, mcast_handler);

    if (!bus_mcast_read(bus->mcast, &msg)) {
        TRACE_ERROR("Failed to read mcast message");
        return;
    }
    //CONSOLE("mcast.msg={type:%s, service:%s, port:%s}", msg.msgtype, msg.service, msg.port);

    if (bus_is_server(bus)) {
        if (!strcmp(msg.msgtype, "query")) {
            bus_mcast_handle_query(bus, &msg);
        }
    }
    else {
        if (!strcmp(msg.msgtype, "announce")) {
            bus_mcast_handle_announce(bus, &msg);
        }
    }
}

static void bus_server_handler(evlp_handler_t *self, int events) {
    bus_t *bus = container_of(self, bus_t, server_handler);
    int client = -1;

    if ((client = accept(bus->server, NULL, NULL)) == -1) {
        TRACE_ERROR("Failed to accept: %m");
    }
    if (!bus_add_connection(bus, client)) {
        TRACE_WARNING("Failed to add connection");
    }
    CONSOLE("Client accepted");
}

void bus_initialize(bus_t *bus, evlp_t *evlp, const char *me, const char *to) {
    assert(bus);
    assert(evlp);
    assert(me);
    assert(to);

    memset(bus, 0, sizeof(bus_t));
    bus->evlp = evlp;
    bus->me = strdup(me);
    bus->to = strdup(to);
    bus->timerfd_handler.fn = bus_timerfd_handler;
    bus->mcast_handler.fn = bus_mcast_handler;
    bus->server_handler.fn = bus_server_handler;
    bus->timerfd = -1;
    bus->mcast = -1;
    bus->server = -1;

    assert((bus->timerfd = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC)) >= 0);
    assert(evlp_add_handler(bus->evlp, &bus->timerfd_handler, bus->timerfd, EPOLLIN));
}

void bus_cleanup(bus_t *bus) {
    bus_connection_t *connection = NULL;
    if (bus) {
        while ((connection = bus_first_connection(bus))) {
            bus_connection_close(connection);
        }
        free(bus->me);
    }
}

void bus_register_topic(bus_t *bus, bus_topic_t *topic) {
    assert(bus);
    assert(topic);

    list_append(&bus->topics, &topic->it);
}

bool bus_tcp_listen(bus_t *bus, const char *hostname, const char *port) {
    bool rt = false;

    when_null(bus, error);
    when_null(hostname, error);
    when_null(port, error);
    when_true(bus->mcast >= 0, error);

    if ((bus->mcast = mcast_listen(BUS_DEFAULT_MCASTADDR, BUS_DEFAULT_PORT)) < 0) {
        TRACE_WARNING("Failed to create UDP multicast listening socket");
    }
    evlp_add_handler(bus->evlp, &bus->mcast_handler, bus->mcast, EPOLLIN);

    free(bus->port);
    bus->port = strdup(port);
    when_true((bus->server = tcp_listen(hostname, port)) < 0, error);
    evlp_add_handler(bus->evlp, &bus->server_handler, bus->server, EPOLLIN);
    timerfd_settime(bus->timerfd, 0, &MCAST_ITIMER, NULL);
    rt = true;


error:
    return rt;
}

bool bus_tcp_connect(bus_t *bus, const char *hostname, const char *port) {
    bool rt = false;

    when_null(bus, error);
    when_null(hostname, error);
    when_null(port, error);
    rt = bus_add_connection(bus, tcp_connect(hostname, port));

error:
    return rt;
}

bool bus_tcp_autoconnect(bus_t *bus) {
    bool rt = false;

    when_null(bus, error);
    when_true(bus->mcast >= 0, error);
    when_true((bus->mcast = mcast_listen(BUS_DEFAULT_MCASTADDR, BUS_DEFAULT_PORT)) < 0, error);
    when_true(!evlp_add_handler(bus->evlp, &bus->mcast_handler, bus->mcast, EPOLLIN), error);
    when_true(timerfd_settime(bus->timerfd, 0, &MCAST_ITIMER, NULL) != 0, error);
    rt = true;

error:
    return rt;
}

bool bus_ipc_socket(bus_t *bus, int ipc) {
    bool rt = false;

    when_null(bus, error);
    when_true(ipc < 0, error);
    rt = bus_add_connection(bus, ipc);

error:
    return rt;
}

bool bus_ipc_listen(bus_t *bus, int server) {
    bool rt = false;

    when_null(bus, error);
    when_true(server < 0, error);
    bus->server = server;
    rt = evlp_add_handler(bus->evlp, &bus->server_handler, bus->server, EPOLLIN);

error:
    return rt;

}

bool bus_wait4connect(bus_t *bus) {
    assert(bus);
    if (!bus->connections.first) {
        bus->wait4connect = true;
        evlp_main(bus->evlp);
        bus->wait4connect = false;
    }
    return bus->connections.first;
}

bool bus_connection_write_request(bus_connection_t *connection, const char *topic, strmap_t *options) {
    strmap_iterator_t *it = NULL;
    bool rt = false;

    when_null(connection, error);
    when_null(topic, error);

    fprintf(connection->out, "REQUEST:%s\n", topic);
    strmap_for_each(it, options) {
        fprintf(connection->out, "%s:%s\n", strmap_iterator_key(it), strmap_iterator_value(it));
    }
    fprintf(connection->out, "\n");
    fflush(connection->out);
    when_true(ferror(connection->out), error);
    rt = true;

error:
    return rt;
}

bool bus_connection_write_reply(bus_connection_t *connection, strmap_t *options) {
    return bus_connection_write_request(connection, "REPLY", options);
}

bool bus_connection_read_reply(bus_connection_t *connection, strmap_t *options) {
    char line[4096];
    const char *sep = ":\n\r\t";
    const char *key = NULL;
    const char *value = NULL;
    const char *option = NULL;
    bool rt = false;

    when_null(connection, error);

    if (options) {
        strmap_cleanup(options);
    }

    while (fgets(line, sizeof(line), connection->in)) {
        key = strtok(line, sep);
        value = strtok(NULL, sep);
        if (!key) {
            break;
        }

        if (options) {
            strmap_add(options, key, value?value:"");
        }
    }

    when_null((option = strmap_get(options, "REQUEST")), error);
    when_true(strcmp(option, "REPLY") != 0, error);

    rt = true;

error:
    return rt;
}

bool bus_connection_readline(bus_connection_t *connection, char *line, size_t size) {
    bool rt = false;

    when_null(connection, error);
    rt = fgets(line, size, connection->in);

error:
    return rt;
}

bool bus_connection_printf(bus_connection_t *connection, char *fmt, ...) {
    bool rt = false;
    va_list ap;

    when_null(connection, error);
    when_null(fmt, error);

    va_start(ap, fmt);
    rt = vfprintf(connection->out, fmt, ap) > 0;
    va_end(ap);

error:
    return rt;
}

bool bus_connection_flush(bus_connection_t *connection) {
    bool rt = false;

    when_null(connection, error);
    when_true(fflush(connection->out) == 0, error);

error:
    return rt;
}

FILE *bus_connection_reader(bus_connection_t *connection) {
    return connection ? connection->in : NULL;
}

FILE *bus_connection_writer(bus_connection_t *connection) {
    return connection ? connection->out : NULL;
}
