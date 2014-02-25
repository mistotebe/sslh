/*
   sslh-libevent: versatile server

# Copyright (C) 2007-2010  Yves Rutschle
# Copyright (C) 2013-2014  Ondřej Kuzník
#
# This program is free software; you can redistribute it
# and/or modify it under the terms of the GNU General Public
# License as published by the Free Software Foundation; either
# version 2 of the License, or (at your option) any later
# version.
#
# This program is distributed in the hope that it will be
# useful, but WITHOUT ANY WARRANTY; without even the implied
# warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
# PURPOSE.  See the GNU General Public License for more
# details.
#
# The full text for the General Public License is here:
# http://www.gnu.org/licenses/gpl.html

*/
/* The idea is as follows:
 * - Each listen socket is an evconnlistener, start_listen_sockets does not
 *   make them nonblocking, so we do
 * - Each time a new connection is received, create a bufferevent for it,
 *   setting the read_cb to probe and event_cb to the connection events
 *   (connection closed), plus a timeout event to trigger the timeout probe
 * - When a probe matches, we set up a nonblocking connect to the target, when
 *   that finishes, a new bufferevent is set up and the pending data is
 *   copied, callbacks and watermarks are updated to the shovel machinery, if
 *   the connection failed, clean up
 * - Once a connection is closed, we free its bufferevent and wait for the
 *   associated one to drain before closing it (if data is still present on a
 *   freed bufferevent, libevent does not wait to drain it, that data is lost)
 */

#define __LINUX__

#include "common.h"
#include "probe.h"
#include <event2/event.h>
#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/listener.h>
#include <event2/util.h>

const char* server_type = "sslh-libevent";
ssize_t buffer_size = 20 * 1024;

#define connection connection_libevent
struct connection {
    struct event_base *base;
    struct bufferevent *client_bev, *server_bev;
    struct proto *proto;
    struct event *timeout;
};

void connection_free(struct connection *cnx)
{
    if (cnx->client_bev) bufferevent_free(cnx->client_bev);
    if (cnx->server_bev) bufferevent_free(cnx->server_bev);
    if (cnx->timeout) event_free(cnx->timeout);
    free(cnx);
}

struct timeval timeout;

void shutdown_cb(struct bufferevent *bev, void *ctx)
{
    /* All data has been written, we can finally close it */
    struct connection *cnx = ctx;

    connection_free(cnx);
}

void event_cb(struct bufferevent *bev, short flags, void *ctx)
{
    /* there is no event we can handle specially, just close the bufferevent
     * and schedule the closure of the other end. That should take care even of
     * the bufferevent's endpoint calling shutdown() */
    struct connection *cnx = ctx;
    struct bufferevent *other;

    if (bev == cnx->client_bev) {
        other = cnx->server_bev;
        cnx->client_bev = NULL;
    } else {
        other = cnx->client_bev;
        cnx->server_bev = NULL;
    }
    bufferevent_free(bev);

    if (!other) {
        connection_free(cnx);
        return;
    }

    bufferevent_disable(other, EV_READ);
    bufferevent_enable(other, EV_WRITE);
    bufferevent_setwatermark(other, EV_WRITE, 0, 0);
    bufferevent_setcb(other, NULL, shutdown_cb, event_cb, cnx);
}

/*
 * The read callback is only ever invoked in one of these scenarios:
 * - at the very beginning for a faster bootstrap
 * - we have filled the incoming buffer, move the data to the other queue if
 *   it's not full yet
 * - otherwise, both buffers had been completely drained, move whatever came in
 *   to output and since it can now react again, reset watermark to default
 *
 * This way, the maximum amount of data buffered will never exceed
 * 3*buffer_size (except after the probes have finished):
 * - current bufferevent input which is capped at buffer_size by the
 *   watermarks
 * - buffer_size unread in this bufferevent we let accumulate afterwards
 * - buffer_size already in evbuffer_get_length(output)
 */
void read_cb(struct bufferevent *source, void *ctx)
{
    struct connection *cnx = ctx;
    struct bufferevent *sink;
    struct evbuffer *input, *output;

    sink = (source == cnx->client_bev) ? cnx->server_bev : cnx->client_bev;
    input = bufferevent_get_input(source);
    output = bufferevent_get_output(sink);

    if (evbuffer_get_length(output) < buffer_size)
        bufferevent_write_buffer(sink, input);

    bufferevent_setwatermark(source, EV_READ, buffer_size, buffer_size);
}

void write_cb(struct bufferevent *sink, void *ctx)
{
    struct connection *cnx = ctx;
    struct bufferevent *source;
    struct evbuffer *input, *output;

    source = (sink == cnx->client_bev) ? cnx->server_bev : cnx->client_bev;
    input = bufferevent_get_input(source);
    output = bufferevent_get_output(sink);

    bufferevent_write_buffer(sink, input);

    /* We are dry, wake up when there's anything to read */
    if (evbuffer_get_length(output) == 0)
        bufferevent_setwatermark(source, EV_READ, 0, buffer_size);
}

void connect_cb(struct bufferevent *bev, short flags, void *ctx)
{
    struct connection *cnx = ctx;

    if (flags != BEV_EVENT_CONNECTED) {
        bufferevent_free(bev);
        cnx->server_bev = NULL;

        connection_free(cnx);
        return;
    }

    bufferevent_setcb(cnx->server_bev, read_cb, write_cb, event_cb, cnx);
    bufferevent_setwatermark(cnx->server_bev, EV_READ, buffer_size, buffer_size);
    bufferevent_setwatermark(cnx->server_bev, EV_WRITE, buffer_size/2, buffer_size/2);
    bufferevent_enable(cnx->server_bev, EV_READ|EV_WRITE);

    bufferevent_setcb(cnx->client_bev, read_cb, write_cb, event_cb, cnx);
    bufferevent_setwatermark(cnx->client_bev, EV_READ, buffer_size, buffer_size);
    bufferevent_setwatermark(cnx->client_bev, EV_WRITE, buffer_size/2, buffer_size/2);
    bufferevent_enable(cnx->client_bev, EV_READ|EV_WRITE);

    /* Send the first round of data */
    write_cb(cnx->server_bev, cnx);
}

int activate_proto(struct proto *p, struct connection *cnx)
{
    if (check_access_rights(bufferevent_getfd(cnx->client_bev), p->service))
        return -1;

    bufferevent_disable(cnx->client_bev, EV_READ);
    cnx->server_bev = bufferevent_socket_new(cnx->base, -1,
            BEV_OPT_CLOSE_ON_FREE);
    if (!cnx->server_bev)
        return -1;

    /*FIXME only one connection attempt for now, need to keep the host:port
     * string and defer it to libevent (solves stale DNS entries as well) */
    if (bufferevent_socket_connect(cnx->server_bev, p->saddr->ai_addr,
            p->saddr->ai_addrlen))
        return -1;

    printf("Activating protocol %s\n", p->description);
    bufferevent_setcb(cnx->server_bev, NULL, NULL, connect_cb, cnx);
    return 0;
}

void probe_cb(struct bufferevent *bev, void *ctx)
{
    struct connection *cnx = ctx;
    struct evbuffer *input;
    struct proto *p;
    unsigned char *buf;
    ssize_t len;
    int res;

    input = bufferevent_get_input(bev);
    len = evbuffer_get_length(input);
    buf = evbuffer_pullup(input, -1);

    for (p = cnx->proto; p; p = p->next) {
        if (!p->probe)
            continue;

        res = p->probe((char *)buf, len, p);
        if (res != PROBE_NEXT)
            break;
    }
    cnx->proto = p;

    if (res == PROBE_AGAIN)
        return;

    if (!p)
        p = cnx->proto = get_first_protocol();

    /* assert(cnx->timeout); */
    event_free(cnx->timeout);
    cnx->timeout = NULL;

    if (activate_proto(p, cnx))
        connection_free(cnx);
}

void timeout_cb(evutil_socket_t fd, short flags, void *ctx)
{
    struct connection *cnx = ctx;
    /* assert(!cnx->server_bev); */

    event_free(cnx->timeout);
    cnx->timeout = NULL;

    if (activate_proto(timeout_protocol(), cnx))
        connection_free(cnx);
}

void accept_cb(struct evconnlistener *listener, evutil_socket_t fd,
               struct sockaddr *sockaddr, int socklen, void *ctx)
{
    struct event_base *base = ctx;
    struct bufferevent *bev;
    struct connection *cnx;

    bev = bufferevent_socket_new(base, fd, BEV_OPT_CLOSE_ON_FREE);
    if (!bev) {
        perror("bufferevent_socket_new");
        close(fd);
        return;
    }

    cnx = calloc(1, sizeof(struct connection));
    if (!cnx) {
        perror("calloc");
        bufferevent_free(bev);
        return;
    }

    cnx->base = base;
    cnx->client_bev = bev;
    cnx->proto = get_first_protocol();

    cnx->timeout = evtimer_new(base, timeout_cb, cnx);
    if (!cnx->timeout || evtimer_add(cnx->timeout, &timeout)) {
        perror("evtimer");
        connection_free(cnx);
        return;
    }

    bufferevent_setcb(bev, probe_cb, NULL, event_cb, cnx);
    bufferevent_enable(bev, EV_READ);
}

void main_loop(int listen_sockets[], int num_addr_listen)
{
    struct event_base *base;
    struct evconnlistener *listener;
    int i;

    base = event_base_new();
    if (!base) {
        perror("event_base_new");
        exit(1);
    }

    timeout.tv_sec = probing_timeout;
    timeout.tv_usec = 0;

    for (i = 0; i < num_addr_listen; i++) {
        evutil_make_socket_nonblocking(listen_sockets[i]);
        listener = evconnlistener_new(base, accept_cb, base, LEV_OPT_CLOSE_ON_FREE, 0, listen_sockets[i]);
        if (!listener) {
            perror("evconnlistener_new");
            exit(1);
        }
    }

    event_base_dispatch(base);
}

void start_shoveler(int listen_socket) {
    fprintf(stderr, "inetd mode is not supported in libevent mode\n");
    exit(1);
}

/* The actual main is in sslh-main.c: it's the same for all versions of
 * the server
 */
