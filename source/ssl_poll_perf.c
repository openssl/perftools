/*
 *  Copyright 2024-2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License").  You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://www.openssl.org/source/license.html
 */

/*
 * Tool reports SSL_poll(3ossl) performance for HTTP/1.0 over QUIC.
 * It spawns two threads:
 *     - server thread
 *     - client thread.
 * clients and server talk over loopback socket (use option -p to specify
 * UDP server port number).  Both client and server use SSL_poll(3ossl) to
 * multiplex QUIC connections and streams. Option -c specifies number
 * of connections client opens. Each connection opens bidirectional (option -b
 * specifies number of bidirectional streams) and unidirectional streams
 * (option -u) to transfer data between client and server.
 * Option -w specifies size of payload sent by client, option -w
 * defines the size payload sent by server.
 */
#include <string.h>
#include <stdio.h>
#include <assert.h>
#include <ctype.h>
#include <sys/types.h>
#include <time.h>
#include <stdlib.h>

/* Include the appropriate header file for SOCK_STREAM */
#ifdef _WIN32 /* Windows */
# include <winsock2.h>
#else /* Linux/Unix */
# include <err.h>
# include <sys/socket.h>
# include <sys/select.h>
# include <netinet/in.h>
# include <unistd.h>
# include <poll.h>
# include <libgen.h>
#endif

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/quic.h>
#include "perflib/perflib.h"
#include "perflib/list.h"

#ifndef _WIN32
# include <unistd.h>
#else
# include <windows.h>
# include "perflib/basename.h"
# include "perflib/err.h"
# include "perflib/getopt.h"
#endif /* _WIN32 */

/*
 * The code here is based on QUIC poll server found in demos/quic/poll-server
 * in OpenSSL source code repository. Here we take the demo one step further
 * and implement also non-blocking client which talks to server to measure
 * performance.
 *
 * Server accepts QUIC connections. It then accepts bi-directional
 * stream from client and reads request. By default it sends
 * 12345 bytes back as HTTP/1.0 response to any GET request.
 * If GET request comes with URL for example as follows:
 *     /foo/bar/file_65535.txt
 * then the server sends 64kB of data in HTTP/1.0 response.
 */

#ifdef DEBUG
# define DPRINTF fprintf
# define DPRINTFC fprintf
# define DPRINTFS fprintf
#else
# define DPRINTF(...) (void)(0)
# define DPRINTFC(...) (void)(0)
# define DPRINTFS(...) (void)(0)
#endif

/*
 * format string so we can print SSL_poll() events in more informative
 * way. To print events one does this:
 *   int events = SSL_POLL_EVENT_F | SSL_POLL_EVENT_R;
 *   printf("%s We got events: " POLL_FMT "\n", __func__, POLL_PRINTA(events));
 */
#define POLL_FMT "%s%s%s%s%s%s%s%s%s%s%s%s%s"
#define POLL_PRINTA(_revents_) \
    (_revents_) & SSL_POLL_EVENT_F ? "SSL_POLL_EVENT_F " : "", \
    (_revents_) & SSL_POLL_EVENT_EL ? "SSL_POLL_EVENT_EL " : "", \
    (_revents_) & SSL_POLL_EVENT_EC ? "SSL_POLL_EVENT_EC " : "", \
    (_revents_) & SSL_POLL_EVENT_ECD ? "SSL_POLL_EVENT_ECD " : "", \
    (_revents_) & SSL_POLL_EVENT_ER ? "SSL_POLL_EVENT_ER " : "", \
    (_revents_) & SSL_POLL_EVENT_EW ? "SSL_POLL_EVENT_EW " : "", \
    (_revents_) & SSL_POLL_EVENT_R ? "SSL_POLL_EVENT_R " : "", \
    (_revents_) & SSL_POLL_EVENT_W ? "SSL_POLL_EVENT_W " : "", \
    (_revents_) & SSL_POLL_EVENT_IC ? "SSL_POLL_EVENT_IC " : "", \
    (_revents_) & SSL_POLL_EVENT_ISB ? "SSL_POLL_EVENT_ISB " : "", \
    (_revents_) & SSL_POLL_EVENT_ISU ? "SSL_POLL_EVENT_ISU " : "", \
    (_revents_) & SSL_POLL_EVENT_OSB ? "SSL_POLL_EVENT_OSB " : "", \
    (_revents_) & SSL_POLL_EVENT_OSU ? "SSL_POLL_EVENT_OSU " : ""

/*
 * every poll_event structure has members enumerated here in poll_event_base
 * The poll events are kept in list which is managed by poll_manager instance.
 * However SSL_poll(9ossl) expects an array of SSL_POLL_ITEM structures. Therefore
 * the poll manager needs to construct array of poll_event structures from list.
 * We get two copies of poll_event structures:
 *    - one copy is held in list (original)
 *    - one copy is held in array (copy for SSL_poll())
 * We use pe_self member to easily reach from SSL_poll() copy instance back to
 * original managed by poll manager and used by our application.
 * There are four callbacks:
 *    - pe_cb_in() - triggered when inbound data/stream/connection is coming
 *    - pe_cb_out() - triggered when outbound data/stream/connection is coming
 *    - pe_cb_error() - triggered when polled object enters an error state
 *    - pe_cb_ondestroy() - this a destructor, application destroy pe_appdata
 * The remaining members are rather self explanatory.
 */
#define poll_event_base \
    SSL_POLL_ITEM pe_poll_item; \
    OSSL_LIST_MEMBER(pe, struct poll_event);\
    uint64_t pe_want_events; \
    uint64_t pe_want_mask; \
    struct poll_manager *pe_my_pm; \
    unsigned char pe_type; \
    struct poll_event *pe_self; \
    int(*pe_cb_in)(struct poll_event *); \
    int(*pe_cb_out)(struct poll_event *); \
    int(*pe_cb_error)(struct poll_event *); \
    void(*pe_cb_ondestroy)(struct poll_event *)

struct poll_event {
    poll_event_base;
};

struct poll_event_listener {
    poll_event_base;
};

/*
 * The poll_event is associated with SSL object which can be one of those:
 *    - QUIC uni-directional (simplex) streams
 *    - QUIC bi-directional (duplex) streams
 *    - QUIC connection
 *    - QUIC listener
 * bi-directional streams are easy to handle: we create them, then we read
 * request from client and write reply back. Then stream gets destroyed.  This
 * request-reply handling is more tricky with uni-directional streams.  We need
 * a pair of streams: server reads a request from one stream and then must
 * create a stream for reply. For echo-reply server we need to pass data we
 * read from input stream to output stream. The poll_stream_context here is to
 * do it for us. The echo-reply server handling with simplex (unidirectional)
 * streams goes as follows:
 *    - we read data from input stream and parse request
 *    - then we request poll manager to create an outbound stream,
 *      at this point we also create a response (rr_buffer).
 *      the response buffer is added to connection.
 *    - connection keeps list of responses to be dispatched because
 *      client may establish more streams to send more requests
 *    - once outbound stream is created, poll manager moves response
 *      connection to outbound stream.
 *
 * The function return values here follow unix convention, where
 * 0 indicates success, -1 indicates failure.
 */

/*
 * poll stream context holds context to process request
 * on server when uni-directional streams are used.
 */
struct poll_stream_context {
    OSSL_LIST_MEMBER(pscx, struct poll_stream_context);
    void *pscx;
    void(*pscx_cb_ondestroy)(void *);
};

DEFINE_LIST_OF(pe, struct poll_event);

DEFINE_LIST_OF(pscx, struct poll_stream_context);

/*
 * It facilitates transfer of app data from one stream to the other.
 * There are two lists:
 *    - pec_stream_cx for bi-directioanl streams
 *    - pec_unistream_cx for uni-direcitonal (simplex) streams.
 *
 * Then there are two counters:
 *    - pec_want_stream bumped up when application requests duplex stream,
 *      bumped down when stream is created
 *    - pec_want_unistream bumped up when application requests simplex stream.
 *      bumped down when stream is created
 *
 * the pec_cs member holds rx, tx counters so we can collect stats.
 */
struct poll_event_connection {
    poll_event_base;
    OSSL_LIST(pscx) pec_stream_cx;
    OSSL_LIST(pscx) pec_unistream_cx;
    uint64_t pec_want_stream;
    uint64_t pec_want_unistream;
    struct client_stats *pec_cs;
};

/*
 * We always allocate more slots than we need. If POLL_GROW slots get
 * depleted then we allocate POLL_GROW more for the next one.
 * Downsizing is similar. This is very naive and leads to oscillations
 * (where we may end up freeing and reallocating poll event set) we need to
 * figure out better strategy.
 */
#define POLL_GROW 20
#define POLL_DOWNSIZ 20

/*
 * Members in poll manager deserve some explanation:
 *    - pm_head, holds a list of poll_event structures (connections and
 *      streams)
 *    - pm_event_count number of events to montior in SSL_poll(3ossl)
 *    - pm_poll_set array of events to poll on
 *    - pm_poll_set_sz number of slots (space) available in pm_poll_set
 *    - pm_need_rebuild whenever list of events to monitor in a list changes
 *      poll mamnager must rebuild pm_poll_set
 *    - pm_continue a flag indicates whether event loop should continue to
 *      run or if it should be terminated (pm_continue == 0)
 *    - pm_wconn_in() callback fires when there is a new connection
 *    - pm qconn
 */
struct poll_manager {
    OSSL_LIST(pe) pm_head;
    unsigned int pm_event_count;
    struct poll_event *pm_poll_set;
    unsigned int pm_poll_set_sz;
    int pm_need_rebuild;
    int pm_continue;
    const char *pm_name;
};

#define SSL_POLL_ERROR (SSL_POLL_EVENT_F | SSL_POLL_EVENT_EL | \
                        SSL_POLL_EVENT_EC | SSL_POLL_EVENT_ECD | \
                        SSL_POLL_EVENT_ER | SSL_POLL_EVENT_EW)

#define SSL_POLL_IN (SSL_POLL_EVENT_R | SSL_POLL_EVENT_IC | \
                     SSL_POLL_EVENT_ISB | SSL_POLL_EVENT_ISU)

#define SSL_POLL_OUT (SSL_POLL_EVENT_W | SSL_POLL_EVENT_OSB | \
                      SSL_POLL_EVENT_OSU)

/*
 * bi-directional stream at server. The instances are
 * always named as pesb
 */
struct poll_event_sbstream {
    poll_event_base;
    struct poll_event_connection *pesb_pec;
    struct rr_buffer *pesb_rb;
    char *pesb_wpos;
    unsigned int pesb_wpos_sz;
    int pesb_got_request;
    char pesb_reqbuf[8192];
};

/*
 * uni-directional streams at server. The instances are
 * always named pesu
 */
struct poll_event_sustream {
    poll_event_base;
    struct poll_event_connection *pesu_pec;
    struct rr_buffer *pesu_rb;
    char *pesu_wpos;
    unsigned int pesu_wpos_sz;
    int pesu_got_request;
    char pesu_reqbuf[8192];
};

/*
 * bi-directional streams at client. The instances are
 * always named pecs
 */
struct poll_event_cstream {
    poll_event_base;
    struct poll_event_connection *pecs_pec;
    struct rr_buffer *pecs_rb;
    struct stream_stats *pecs_ss;
};

/*
 * uni-directional streams at client. The instances are
 * always named pecsu
 */
struct poll_event_custream {
    poll_event_base;
    struct poll_event_connection *pecsu_pec;
    struct rr_buffer *pecsu_rb;
    struct stream_stats *pecsu_ss;
};

/*
 * This holds context for client. It holds counters to
 * measure statistics.
 */
struct client_context {
    struct stream_stats *ccx_ss;
    struct rr_buffer *ccx_rb;
};

/*
 * request/response buffer (a.k.a. rr_buffer)
 */
enum rb_type {
    RB_TYPE_NONE,
    RB_TYPE_TEXT_SIMPLE,
    RB_TYPE_TEXT_FULL
} ;
#define rr_buffer_base \
    enum rb_type rb_type; \
    unsigned int rb_rpos; \
    void (*rb_advrpos_cb)(struct rr_buffer *, unsigned int);\
    unsigned int (*rb_read_cb)(struct rr_buffer *, char *, \
                               unsigned int); \
    int (*rb_eof_cb)(struct rr_buffer *); \
    void (*rb_ondestroy_cb)(struct rr_buffer *)

/*
 * request/response buffer makes no difference,
 * creating alias here so the code reads better.
 */
#define request_buffer rr_buffer
struct rr_buffer {
    rr_buffer_base;
};

struct rr_txt_full {
    rr_buffer_base;
    char rtf_headers[1024];
    char *rtf_pattern;
    unsigned int rtf_pattern_len;
    unsigned int rtf_hdr_len;
    unsigned int rtf_len; /* headers + data */
};

#define request_txt_full rr_txt_full

static void destroy_pe(struct poll_event *);
static int pe_return_error(struct poll_event *);
static void pe_return_void(struct poll_event *);

static const char *hostname = "localhost";
static const char *portstr = "8000";
static SSL_CTX *server_ctx;
static int stop_server = 0;

/* 100 MB cap on stream size */
#define STREAM_SZ_CAP (100 * 1024 * 1024)
/*
 * This holds parsed arguments from command line.
 */
static struct client_config {
    const char *cc_portstr;
    unsigned int cc_clients;
    unsigned int cc_bstreams;
    unsigned int cc_ustreams;
    unsigned int cc_rep_sz;
    unsigned int cc_req_sz;
    int cc_shuffle;
} client_config;

#define STREAM_COUNT (client_config.cc_ustreams + client_config.cc_bstreams)

enum {
    SS_UNISTREAM,
    SS_BIDISTREAM
};

#define SS_TYPE_TO_SFLAG(_t_) (((_t_) == SS_UNISTREAM) ? \
                               SSL_STREAM_FLAG_UNI : 0)
#define SS_TYPE_TO_POLLEV(_t_) (((_t_) == SS_UNISTREAM) ? \
                                SSL_POLL_EVENT_OSU : SSL_POLL_EVENT_OSB)

/*
 * client calculates stats for every stream (pair of streams in case
 * of unidirectional streams).
 */
struct stream_stats {
    size_t ss_req_sz;
    size_t ss_body_sz;
    size_t ss_rx;
    size_t ss_tx;
    char ss_type;
    OSSL_LIST_MEMBER(ss, struct stream_stats);
};

DEFINE_LIST_OF(ss, struct stream_stats);

/*
 * Here we manage statistics and also tasks which we still need to perform and
 * tasks which are done.
 */
struct client_stats {
    size_t cs_rx;
    size_t cs_tx;
    OSSL_LIST(ss) cs_todo;
    OSSL_LIST(ss) cs_done;
};

static int terse = 0;

#ifdef _WIN32
# define strncasecmp(_a_, _b_, _c_) _strnicmp((_a_), (_b_), (_c_))

# define ctime_r(_t_, _b_) ctime_s((_b_), sizeof((_b_)), (_t_))

#endif

enum pe_types {
    PE_NONE,
    PE_LISTENER,
    PE_CONNECTION_CLIENT,
    PE_CONNECTION_SERVER,
    PE_SSTREAM,
    PE_SUSTREAM,
    PE_CSTREAM,
    PE_CUSTREAM,
    PE_INVALID
};

static struct rr_txt_full *
rb_to_txt_full(struct rr_buffer *rb)
{
    if (rb == NULL || rb->rb_type != RB_TYPE_TEXT_FULL)
        return NULL;

    return (struct rr_txt_full *)rb;
}

static void
rb_advrpos_cb(struct rr_buffer *rb, unsigned int rpos)
{
    /* we assume base rr_buffer is unlimited */
    rb->rb_rpos += rpos;
}

static void
rb_ondestroy_cb(struct rr_buffer *rb)
{
    OPENSSL_free(rb);
}

static unsigned int
rb_null_read_cb(struct rr_buffer *rb, char *buf, unsigned int buf_sz)
{
    return 0;
}

static int
rb_eof_cb(struct rr_buffer *rb)
{
    return 1;
}

static void
rb_init(struct rr_buffer *rb)
{
    rb->rb_type = RB_TYPE_NONE;
    rb->rb_advrpos_cb = rb_advrpos_cb;
    rb->rb_read_cb = rb_null_read_cb;
    rb->rb_eof_cb = rb_eof_cb;
    rb->rb_ondestroy_cb = rb_ondestroy_cb;
    rb->rb_rpos = 0;
}

static void
rb_advrpos(struct rr_buffer *rb, unsigned int rpos)
{
    if (rb != NULL)
        rb->rb_advrpos_cb(rb, rpos);
}

static unsigned int
rb_read(struct rr_buffer *rb, char *buf, unsigned int buf_sz)
{
    if (rb != NULL)
        return rb->rb_read_cb(rb, buf, buf_sz);
    else
        return 0;
}

static unsigned int
rb_eof(struct rr_buffer *rb)
{
    if (rb != NULL)
        return rb->rb_eof_cb(rb);
    else
        return 1;
}

static void
rb_destroy(struct rr_buffer *rb)
{
    if (rb != NULL)
        rb->rb_ondestroy_cb(rb);
}

static int
rb_txt_full_eof_cb(struct rr_buffer *rb)
{
    struct rr_txt_full *rtf = rb_to_txt_full(rb);

    if (rtf == NULL)
        return 1;

    if (rb->rb_rpos >= rtf->rtf_len)
        return 1;
    else
        return 0;
}

static void
rb_txt_full_ondestroy_cb(struct rr_buffer *rb)
{
    struct rr_txt_full *rtf = rb_to_txt_full(rb);

    if (rtf != NULL) {
        OPENSSL_free(rtf->rtf_pattern);
        OPENSSL_free(rtf);
    }
}

static unsigned int
rb_txt_full_read_cb(struct rr_buffer *rb, char *buf, unsigned int buf_sz)
{
    struct rr_txt_full *rtf = rb_to_txt_full(rb);
    unsigned int i;
    unsigned int j;
    unsigned int rv = 0;

    if (rtf == NULL || rb_eof(rb))
        return 0;

    i = rb->rb_rpos;
    while (i < rtf->rtf_hdr_len && rv < buf_sz) {
        *buf++ = rtf->rtf_headers[i++];
        rv++;
    }

    j = i - rtf->rtf_hdr_len;
    while ((i < rtf->rtf_len) && (rv < buf_sz)) {
        *buf++ = rtf->rtf_pattern[j % rtf->rtf_pattern_len];
        j++;
        i++;
        rv++;
    }

    return rv;
}

static void
rb_txt_full_advrpos_cb(struct rr_buffer *rb, unsigned int sz)
{
    struct rr_txt_full *rtf = rb_to_txt_full(rb);

    if (rtf != NULL) {
        rb->rb_rpos += sz;
        if (rb->rb_rpos >= rtf->rtf_len)
            rb->rb_rpos = rtf->rtf_len;
    }
}

static struct rr_txt_full *
new_txt_full_rrbuff(const char *fill_pattern, unsigned int fsize)
{
    struct rr_txt_full *rtf;
    struct rr_buffer *rb;
    char date_str[80];
    int hlen;
    time_t t;

    rtf = OPENSSL_malloc(sizeof(struct rr_txt_full));
    if (rtf == NULL)
        return NULL;

    if ((rtf->rtf_pattern = strdup(fill_pattern)) == NULL) {
        OPENSSL_free(rtf);
        return NULL;
    }
    rtf->rtf_pattern_len = strlen(fill_pattern);

    t = time(&t);
    ctime_r(&t, date_str);
    /* TODO check headers if they confirm to HTTP/1.0 */
    hlen = snprintf(rtf->rtf_headers, sizeof(rtf->rtf_headers),
                    "HTTP/1.0 200 OK\r\n"
                    "Content-Type: text/plain\r\n"
                    "Content-Length: %u\r\n"
                    "Date: %s\r\n"
                    "\r\n", fsize, date_str);
    if (hlen >= (int)sizeof(rtf->rtf_headers)) {
        OPENSSL_free(rtf->rtf_pattern);
        OPENSSL_free(rtf);
        return NULL;
    }
    rtf->rtf_hdr_len = (unsigned int)hlen;

    rtf->rtf_len = rtf->rtf_hdr_len + fsize;

    rb = (struct rr_buffer *)rtf;
    rb_init(rb);
    rb->rb_type = RB_TYPE_TEXT_FULL;
    rb->rb_eof_cb = rb_txt_full_eof_cb;
    rb->rb_read_cb = rb_txt_full_read_cb;
    rb->rb_ondestroy_cb = rb_txt_full_ondestroy_cb;
    rb->rb_advrpos_cb = rb_txt_full_advrpos_cb;

    return rtf;
}

static struct request_txt_full *
new_txt_full_request(const char *url, const char *fill_pattern, size_t body_len)
{
    struct request_txt_full *rtf;
    struct rr_buffer *rb;
    char date_str[80];
    int hlen;
    time_t t;

    rtf = OPENSSL_zalloc(sizeof(struct request_txt_full));
    if (rtf == NULL)
        return NULL;

    if (fill_pattern != NULL) {
        if ((rtf->rtf_pattern = strdup(fill_pattern)) == NULL) {
            OPENSSL_free(rtf);
            return NULL;
        }
        rtf->rtf_pattern_len = strlen(fill_pattern);
    }

    t = time(&t);
    ctime_r(&t, date_str);
    hlen = snprintf(rtf->rtf_headers, sizeof(rtf->rtf_headers),
                    "GET %s HTTP/1.0K\r\n"
                    "Content-Type: text/plain\r\n"
                    "Content-Length: %zu\r\n"
                    "Date: %s\r\n"
                    "\r\n", url, body_len, date_str);
    if (hlen >= (int)sizeof(rtf->rtf_headers)) {
        OPENSSL_free(rtf->rtf_pattern);
        OPENSSL_free(rtf);
        return NULL;
    }
    rtf->rtf_hdr_len = (unsigned int)hlen;

    rtf->rtf_len = rtf->rtf_hdr_len + body_len;

    rb = (struct rr_buffer *)rtf;
    rb_init(rb);
    rb->rb_type = RB_TYPE_TEXT_FULL;
    rb->rb_eof_cb = rb_txt_full_eof_cb;
    rb->rb_read_cb = rb_txt_full_read_cb;
    rb->rb_ondestroy_cb = rb_txt_full_ondestroy_cb;
    rb->rb_advrpos_cb = rb_txt_full_advrpos_cb;

    return rtf;
}

static const char *
pe_type_to_name(const struct poll_event *pe)
{
    static const char *names[] = {
        "none",
        "listener",
        "client connection",
        "server connection",
        "server stream (bidi)",
        "server stream (uni)",
        "client stream (bidi)",
        "client stream (uni)",
        "invalid"
    };

    if (pe->pe_type >= PE_INVALID)
        return names[PE_INVALID];

    return names[pe->pe_type];
}

static struct poll_event_connection *
pe_to_connection(struct poll_event *pe)
{
    if ((pe == NULL) || ((pe->pe_type != PE_CONNECTION_CLIENT) &&
        (pe->pe_type != PE_CONNECTION_SERVER)))
        return NULL;

    return (struct poll_event_connection *)pe;
}

static struct poll_event_sbstream *
pe_to_sstream(struct poll_event *pe)
{
    if ((pe == NULL) || (pe->pe_type != PE_SSTREAM))
        return NULL;

    return (struct poll_event_sbstream *)pe;
}

static struct poll_event_sustream *
pe_to_sustream(struct poll_event *pe)
{
    if ((pe == NULL) || (pe->pe_type != PE_SUSTREAM))
        return NULL;

    return (struct poll_event_sustream *)pe;
}

static struct poll_event_cstream *
pe_to_cstream(struct poll_event *pe)
{
    if ((pe == NULL) || (pe->pe_type != PE_CSTREAM))
        return NULL;

    return (struct poll_event_cstream *)pe;
}

static struct poll_event_custream *
pe_to_custream(struct poll_event *pe)
{
    if ((pe == NULL) || (pe->pe_type != PE_CUSTREAM))
        return NULL;

    return (struct poll_event_custream *)pe;
}

static void
init_pe(struct poll_event *pe, SSL *ssl)
{
    pe->pe_poll_item.desc = SSL_as_poll_descriptor(ssl);
    pe->pe_cb_in = pe_return_error;
    pe->pe_cb_out = pe_return_error;
    pe->pe_cb_error = pe_return_error;
    pe->pe_cb_ondestroy = pe_return_void;
    pe->pe_self = pe;
    pe->pe_type = PE_NONE;
    pe->pe_want_mask = ~0;
}

static struct poll_event *
new_pe(SSL *ssl)
{
    struct poll_event *pe;

    if (ssl != NULL) {
        pe = OPENSSL_zalloc(sizeof(struct poll_event));
        if (pe != NULL)
            init_pe(pe, ssl);
    } else {
        pe = NULL;
    }

    return pe;
}

static struct poll_event_listener *
new_listener_pe(SSL *ssl_listener)
{
    struct poll_event *listener_pe;

    listener_pe = new_pe(ssl_listener);
    if (listener_pe != NULL) {
        listener_pe->pe_type = PE_LISTENER;
        listener_pe->pe_want_events = SSL_POLL_EVENT_IC | SSL_POLL_EVENT_EL;
    }

    return (struct poll_event_listener *)listener_pe;
}

static struct poll_event *
new_qconn_pe(SSL *ssl_qconn)
{
    struct poll_event *qconn_pe;
    struct poll_event_connection *pec;

    if (ssl_qconn != NULL) {
        qconn_pe = OPENSSL_zalloc(sizeof(struct poll_event_connection));

        if (qconn_pe != NULL) {
            init_pe(qconn_pe, ssl_qconn);
            qconn_pe->pe_type = PE_CONNECTION_CLIENT; /* assume client */
            qconn_pe->pe_want_events = SSL_POLL_EVENT_EC | SSL_POLL_EVENT_ECD;
            /*
             * SSL_POLL_EVENT_OSB (or SSL_POLL_EVENT_OSU) must be monitored
             * once there is a request for outbound stream created by app.
             */
            pec = (struct poll_event_connection *)qconn_pe;
            ossl_list_pscx_init(&pec->pec_unistream_cx);
            ossl_list_pscx_init(&pec->pec_stream_cx);
        }
    } else {
        qconn_pe = NULL;
    }

    return qconn_pe;
}

static struct poll_event_sbstream *
new_sstream_pe(SSL *ssl_qs)
{
    struct poll_event_sbstream *pesb;

    if (ssl_qs != NULL) {
        pesb = OPENSSL_zalloc(sizeof(struct poll_event_sbstream));

        if (pesb != NULL) {
            init_pe((struct poll_event *)pesb, ssl_qs);
            pesb->pesb_wpos = pesb->pesb_reqbuf;
            pesb->pesb_wpos_sz = sizeof(pesb->pesb_reqbuf) - 1;
            ((struct poll_event *)pesb)->pe_type = PE_SSTREAM;
        }
    } else {
        pesb = NULL;
    }

    return pesb;
}

static struct poll_event_sustream *
new_sustream_pe(SSL *ssl_qs)
{
    struct poll_event_sustream *pesu;

    if (ssl_qs != NULL) {
        pesu = OPENSSL_zalloc(sizeof(struct poll_event_sustream));

        if (pesu != NULL) {
            init_pe((struct poll_event *)pesu, ssl_qs);
            pesu->pesu_wpos = pesu->pesu_reqbuf;
            pesu->pesu_wpos_sz = sizeof(pesu->pesu_reqbuf) - 1;
            ((struct poll_event *)pesu)->pe_type = PE_SUSTREAM;
        }
    } else {
        pesu = NULL;
    }

    return pesu;
}

static struct poll_event_cstream *
new_cstream_pe(SSL *ssl_qs)
{
    struct poll_event_cstream *pecs;

    if (ssl_qs != NULL) {
        pecs = OPENSSL_zalloc(sizeof(struct poll_event_cstream));

        if (pecs != NULL) {
            init_pe((struct poll_event *)pecs, ssl_qs);
            ((struct poll_event *)pecs)->pe_type = PE_CSTREAM;
        }
    } else {
        pecs = NULL;
    }

    return pecs;
}

static struct poll_event_custream *
new_custream_pe(SSL *ssl_qs)
{
    struct poll_event_custream *pecsu;

    if (ssl_qs != NULL) {
        pecsu = OPENSSL_zalloc(sizeof(struct poll_event_custream));

        if (pecsu != NULL) {
            init_pe((struct poll_event *)pecsu, ssl_qs);
            ((struct poll_event *)pecsu)->pe_type = PE_CUSTREAM;
        }
    } else {
        pecsu = NULL;
    }

    return pecsu;
}

static SSL *
get_ssl_from_pe(struct poll_event *pe)
{
    SSL *ssl;

    if (pe != NULL)
        ssl = pe->pe_poll_item.desc.value.ssl;
    else
        ssl = NULL;

    return ssl;
}

static void
pe_pause_read(struct poll_event *pe)
{
    pe->pe_want_events &= ~SSL_POLL_EVENT_R;
    pe->pe_my_pm->pm_need_rebuild = 1;
}

static void
pe_resume_read(struct poll_event *pe)
{
    pe->pe_want_events |= (SSL_POLL_EVENT_R & pe->pe_want_mask);
    pe->pe_my_pm->pm_need_rebuild = 1;
}

static void
pe_pause_write(struct poll_event *pe)
{
    pe->pe_want_events &= ~SSL_POLL_EVENT_W;
    pe->pe_my_pm->pm_need_rebuild = 1;
}

static void
pe_resume_write(struct poll_event *pe)
{
    pe->pe_want_events |= (SSL_POLL_EVENT_W & pe->pe_want_mask);
    pe->pe_my_pm->pm_need_rebuild = 1;
}

/*
 * like pause, but is permanent,
 */
static void
pe_disable_read(struct poll_event *pe)
{
    pe_pause_read(pe);
    pe->pe_want_mask &= ~SSL_POLL_EVENT_R;
}

static void
pe_disable_write(struct poll_event *pe)
{
    pe_pause_write(pe);
    pe->pe_want_mask &= ~SSL_POLL_EVENT_W;
}

/*
 * handle_ssl_error() diagnoses error from SSL/QUIC stack and
 * decides if it is temporal error (in that case it returns zero)
 * or error is permanent. In case of permanent error the
 * poll event pe should be removed from poll manager and destroyed.
 */
static const char *
err_str_n(unsigned long e, char *buf, size_t buf_sz)
{
    ERR_error_string_n(e, buf, buf_sz);
    return buf;
}

static int
handle_ssl_error(struct poll_event *pe, int rc, const char *caller)
{
    SSL *ssl = get_ssl_from_pe(pe);
    int ssl_error, rv;
#ifdef DEBUG
    char err_str[120];
#endif

    /* may be we should use SSL_shutdown_ex() to signal peer what's going on */
    ssl_error = SSL_get_error(ssl, rc);
    if (rc <= 0) {
        switch (ssl_error) {
        case SSL_ERROR_SYSCALL:
        case SSL_ERROR_SSL:
            DPRINTF(stderr, "%s permanent error on %p (%s) [ %s ]\n",
                    caller, pe, pe_type_to_name(pe),
                    err_str_n(ssl_error, err_str, sizeof(err_str)));
            rv = -1;
            break;
        case SSL_ERROR_ZERO_RETURN:
        default:
            DPRINTF(stderr, "%s temporal error on %p (%s) [ %s ]\n",
                    caller, pe, pe_type_to_name(pe),
                    err_str_n(ssl_error, err_str, sizeof(err_str)));
            rv = 0; /* maybe return -1 here too */
        }
    } else if (rc == 0) {
        DPRINTF(stderr, "%s temporal error on  %p (%s) [ %s ]\n",
                caller, pe, pe_type_to_name(pe),
                err_str_n(ssl_error, err_str, sizeof(err_str)));
        rv = 0;
    } else if (rc == 1) {
        DPRINTF(stderr, "%s no error on %p (%s) [ ??? ]\n", caller, pe,
                pe_type_to_name(pe));
        rv = -1; /* complete, stop polling for event */
    } else {
        DPRINTF(stderr, "%s ?unexpected? error on %p (%s) [ %s ]\n",
                caller, pe, pe_type_to_name(pe),
                err_str_n(ssl_error, err_str, sizeof(err_str)));
        rv = -1; /* stop polling */
    }

    return rv;
}

static const char *
stream_state_str(int stream_state)
{
    const char *rv;

    switch (stream_state) {
    case SSL_STREAM_STATE_NONE:
        rv = "SSL_STREAM_STATE_NONE";
        break;
    case SSL_STREAM_STATE_OK:
        rv = "SSL_STREAM_STATE_OK";
        break;
    case SSL_STREAM_STATE_WRONG_DIR:
        rv = "SSL_STREAM_STATE_WRONG_DIR";
        break;
    case SSL_STREAM_STATE_FINISHED:
        rv = "SSL_STREAM_STATE_FINISHED";
        break;
    case SSL_STREAM_STATE_RESET_LOCAL:
        rv = "SSL_STREAM_STATE_RESET_LOCAL";
        break;
    case SSL_STREAM_STATE_RESET_REMOTE:
        rv = "SSL_STREAM_STATE_RESET_REMOTE";
        break;
    case SSL_STREAM_STATE_CONN_CLOSED:
        rv = "SSL_STREAM_STATE_CONN_CLOSED";
        break;
    default:
        rv = "???";
    }

    return rv;
}

static int
handle_read_stream_state(struct poll_event *pe)
{
    int stream_state = SSL_get_stream_read_state(get_ssl_from_pe(pe));
    int rv;

    switch (stream_state) {
    case SSL_STREAM_STATE_FINISHED:
        DPRINTF(stderr, "%s remote peer concluded the stream\n", __func__);
        pe_disable_read(pe);
        /* FALLTHRU */
    case SSL_STREAM_STATE_OK:
        rv = 0;
        break;
    default:
        DPRINTF(stderr,
                "%s error %s on stream, the %p (%s) should be destroyed\n",
                __func__, stream_state_str(stream_state), pe,
                pe_type_to_name(pe));
        rv = -1;
    }

    return rv;
}

static int
handle_write_stream_state(struct poll_event *pe)
{
    int state = SSL_get_stream_write_state(get_ssl_from_pe(pe));
    int rv;

    switch (state) {
    case SSL_STREAM_STATE_FINISHED:
        DPRINTF(stderr, "%s remote peer concluded the stream\n", __func__);
        /* FALLTHRU */
    case SSL_STREAM_STATE_OK:
        rv = 0;
        break;
    default:
        DPRINTF(stderr,
                "%s error %s on stream, the %p (%s) should be destroyed\n",
                __func__, stream_state_str(state), pe, pe_type_to_name(pe));
        rv = -1;
    }

    return rv;
}

static void
add_pe_to_pm(struct poll_manager *pm, struct poll_event *pe)
{
    if (pe->pe_my_pm == NULL) {
        ossl_list_pe_insert_head(&pm->pm_head, pe);
        pm->pm_need_rebuild = 1;
        pe->pe_my_pm = pm;
    }
}

static void
remove_pe_from_pm(struct poll_manager *pm, struct poll_event *pe)
{
    if (pe->pe_my_pm == pm) {
        ossl_list_pe_remove(&pm->pm_head, pe);
        pm->pm_need_rebuild = 1;
        pe->pe_my_pm = NULL;
    }
}

static struct poll_manager *
create_poll_manager(void)
{
    struct poll_manager *pm = NULL;

    pm = OPENSSL_zalloc(sizeof(struct poll_manager));
    if (pm == NULL)
        return NULL;

    ossl_list_pe_init(&pm->pm_head);
    pm->pm_poll_set = OPENSSL_malloc(sizeof(struct poll_event) * POLL_GROW);
    if (pm->pm_poll_set != NULL) {
        pm->pm_poll_set_sz = POLL_GROW;
        pm->pm_event_count = 0;
        pm->pm_name = "";
    } else {
        OPENSSL_free(pm);
        return NULL;
    }

    return pm;
}

static int
rebuild_poll_set(struct poll_manager *pm)
{
    struct poll_event *new_poll_set;
    struct poll_event *pe;
    size_t new_sz, new_poll_set_sz;
    size_t pe_num;
    size_t i;

    if (pm->pm_need_rebuild == 0)
        return 0;

    pe_num = ossl_list_pe_num(&pm->pm_head);
    if (pe_num > pm->pm_poll_set_sz) {
        /*
         * grow poll set by POLL_GROW
         */
        new_poll_set_sz = pm->pm_poll_set_sz;
        do {
            new_poll_set_sz += POLL_GROW;
            (void)(0); /* make check-format.pl happy */
        } while (new_poll_set_sz < pe_num);

        new_sz = sizeof(struct poll_event) * new_poll_set_sz;
        new_poll_set = (struct poll_event *)OPENSSL_realloc(pm->pm_poll_set,
                                                            new_sz);
        if (new_poll_set == NULL)
            return -1;
        pm->pm_poll_set = new_poll_set;
        pm->pm_poll_set_sz = new_poll_set_sz;

    } else if ((pe_num + POLL_DOWNSIZ) < pm->pm_poll_set_sz) {
        /*
         * shrink poll set by POLL_DOWNSIZ
         */
        new_sz = sizeof(struct poll_event) *
            (pm->pm_poll_set_sz - POLL_DOWNSIZ);
        new_poll_set = (struct poll_event *)OPENSSL_realloc(pm->pm_poll_set,
                                                            new_sz);
        if (new_poll_set == NULL)
            return -1;
        pm->pm_poll_set = new_poll_set;
        pm->pm_poll_set_sz -= POLL_DOWNSIZ;
    }

    i = 0;
    DPRINTF(stderr, "%s(%s) there %zu events to poll\n", __func__,
            pm->pm_name, ossl_list_pe_num(&pm->pm_head));
    OSSL_LIST_FOREACH(pe, pe, &pm->pm_head) {
        pe->pe_poll_item.events = pe->pe_want_events;
        pm->pm_poll_set[i++] = *pe;
        DPRINTF(stderr, "\t%p @ %s (%s) " POLL_FMT " (disabled: " POLL_FMT ")\n",
                pe,  pm->pm_name, pe_type_to_name(pe),
                POLL_PRINTA(pe->pe_poll_item.events),
                POLL_PRINTA(~pe->pe_want_mask));
    }
    pm->pm_event_count = i;
    pm->pm_need_rebuild = 0;

    return 0;
}

static void
destroy_poll_manager(struct poll_manager *pm)
{
    struct poll_event *pe, *pe_safe;

    if (pm == NULL)
        return;

    OSSL_LIST_FOREACH_DELSAFE(pe, pe_safe, pe, &pm->pm_head) {
        destroy_pe(pe);
    }

    OPENSSL_free(pm->pm_poll_set);
    OPENSSL_free(pm);
}

static void
destroy_pe(struct poll_event *pe)
{
    SSL *ssl;

    if (pe == NULL)
        return;

    DPRINTF(stderr, "%s %p (%s)\n", __func__, pe, pe_type_to_name(pe));
    ssl = get_ssl_from_pe(pe);
    if (pe->pe_my_pm)
        remove_pe_from_pm(pe->pe_my_pm, pe);

    pe->pe_cb_ondestroy(pe);

    OPENSSL_free(pe);

    SSL_free(ssl);
}

static int
pe_return_error(struct poll_event *pe)
{
    return -1;
}

static void
pe_return_void(struct poll_event *ctx)
{
    return;
}

static int
pe_handle_listener_error(struct poll_event *pe)
{
    pe->pe_my_pm->pm_continue = 0;
    if (pe->pe_poll_item.revents & SSL_POLL_EVENT_EL)
        return -1;

    DPRINTF(stderr, "%s unexpected error on %p (%s) " POLL_FMT "\n", __func__,
            pe, pe_type_to_name(pe), POLL_PRINTA(pe->pe_poll_item.revents));

    return -1;
}

/*
 * non-blocking variant for new_stream()/accept_stream(). Creating outbound
 * stream is two step process when using non-blocking I/O.
 *    application starts polling for SSL_POLL_EVENT_OS* to check
 *    if outbound streams are available.
 *
 *    as soon as SSL_POLL_EVENT_OS comes back from SSL_poll() application
 *    should call SSL-new_stream() to create a stream object and
 *    add its poll descriptor to SSL_poll() events. The stream object
 *    should be monitored for SSL_POLL_EVENT_{W,R}
 *
 * new_stream() function below is supposed to be called by application
 * which uses SSL_poll()  to manage I/O. We expect there might be more
 * than 1 stream request.
 */
static void
request_new_stream(struct poll_event_connection *pec, uint64_t qsflag,
                   struct poll_stream_context *pscx, int accept)
{
    struct poll_event *qconn_pe = (struct poll_event *)pec;

    if (qsflag & SSL_STREAM_FLAG_UNI) {
        pec->pec_want_unistream++;
        if (accept == 0)
            qconn_pe->pe_want_events |= SSL_POLL_EVENT_OSU;
        else
            qconn_pe->pe_want_events |= SSL_POLL_EVENT_ISU;
        ossl_list_pscx_insert_tail(&pec->pec_unistream_cx, pscx);
    } else {
        pec->pec_want_stream++;
        if (accept == 0)
            qconn_pe->pe_want_events |= SSL_POLL_EVENT_OSB;
        else
            qconn_pe->pe_want_events |= SSL_POLL_EVENT_ISB;

        ossl_list_pscx_insert_tail(&pec->pec_stream_cx, pscx);
    }

    /*
     * We are changing poll events, so SSL_poll() array needs be rebuilt.
     */
    qconn_pe->pe_my_pm->pm_need_rebuild = 1;
}

static void *
get_response_from_pec(struct poll_event_connection *pec, int stype)
{
    struct poll_stream_context *pscx;
    void *rv;

    switch (stype) {
    case PE_SUSTREAM:
    case PE_CUSTREAM:
        pscx = ossl_list_pscx_head(&pec->pec_unistream_cx);
        if (pscx != NULL) {
            pec->pec_want_unistream--;
            ossl_list_pscx_remove(&pec->pec_unistream_cx, pscx);
            rv = pscx->pscx;
            OPENSSL_free(pscx);
        } else {
            rv = NULL;
        }
        break;
    case PE_SSTREAM:
    case PE_CSTREAM:
        pscx = ossl_list_pscx_head(&pec->pec_stream_cx);
        if (pscx != NULL) {
            pec->pec_want_stream--;
            ossl_list_pscx_remove(&pec->pec_stream_cx, pscx);
            rv = pscx->pscx;
            OPENSSL_free(pscx);
        } else {
            rv = NULL;
        }
        break;
    default:
        rv = NULL;
    }

    return rv;
}

static void
app_destroy_qconn(struct poll_event *pe)
{
    struct poll_event_connection *pec;
    struct poll_stream_context *pscx, *pscx_save;

    pec = pe_to_connection(pe);
    if (pec == NULL)
        return;

    OSSL_LIST_FOREACH_DELSAFE(pscx, pscx_save, pscx, &pec->pec_unistream_cx) {
        pscx->pscx_cb_ondestroy(pscx->pscx);
        OPENSSL_free(pscx);
    }

    OSSL_LIST_FOREACH_DELSAFE(pscx, pscx_save, pscx, &pec->pec_stream_cx) {
        pscx->pscx_cb_ondestroy(pscx->pscx);
        OPENSSL_free(pscx);
    }
}

static int
app_handle_qconn_error(struct poll_event *pe)
{
    int rv = -2;

    if (pe->pe_poll_item.revents & SSL_POLL_EVENT_EC) {
        /*
	 * Keep to call SSL_shutdown() to drain the connection (let all streams
	 * to finish transfer)
         */
        rv = SSL_shutdown(get_ssl_from_pe(pe));
        DPRINTF(stderr,
                "%s connection shutdown started on %p (%s), "
                "shutdown %s keep polling\n",
                __func__, pe, pe_type_to_name(pe),
                (rv == 0) ? "in progress" : (rv == 1) ? "done" : "error");
        /*
	 * override error we got in shutdown and keep connection in loop. There
	 * should be _ECD event saying connection is drained and can be
	 * destroyed.
         */
        rv = 0;
    }

    if (pe->pe_poll_item.revents & SSL_POLL_EVENT_ECD) {
        DPRINTF(stderr,
                "%s connection shutdown done on %p (%s), stop polling\n",
                __func__, pe, pe_type_to_name(pe));
        rv = -1; /* shutdown is complete stop polling let pe to be destroyed */
    }

    if (rv == -2) {
        DPRINTF(stderr, "%s unexpected event on %p (%s)" POLL_FMT "\n",
                __func__, pe, pe_type_to_name(pe),
                POLL_PRINTA(pe->pe_poll_item.revents));
        rv = -1;
    }

    return rv;
}

/*
 * HTTP/1.0 server application
 */
static void
srvapp_ondestroy_sstreamcb(struct poll_event *pe)
{
    struct poll_event_sbstream *pesb = pe_to_sstream(pe);

    rb_destroy(pesb->pesb_rb);
}

static void
srvapp_ondestroy_sustreamcb(struct poll_event *pe)
{
    struct poll_event_sustream *pesu = pe_to_sustream(pe);

    rb_destroy(pesu->pesu_rb);
}

static int
srvapp_handle_stream_error(struct poll_event *pe)
{
    int rv = 0;

    if (pe->pe_poll_item.revents & SSL_POLL_EVENT_ER) {

        if ((pe->pe_poll_item.events & SSL_POLL_EVENT_R) == 0) {
            DPRINTFS(stderr, "%s unexpected failure on reader %p (%s) "
                     POLL_FMT "\n", __func__, pe, pe_type_to_name(pe),
                     POLL_PRINTA(pe->pe_poll_item.revents));
        }

        (void) handle_read_stream_state(pe);
        rv = -1; /* tell pm to stop polling and destroy stream/event */
    } else if (pe->pe_poll_item.revents & SSL_POLL_EVENT_EW) {

        if ((pe->pe_poll_item.events & SSL_POLL_EVENT_W) == 0) {
            DPRINTFS(stderr, "%s unexpected failure on writer %p (%s) "
                     POLL_FMT "\n", __func__, pe, pe_type_to_name(pe),
                     POLL_PRINTA(pe->pe_poll_item.revents));
        }
        (void) handle_write_stream_state(pe);

        rv = -1; /* tell pm to stop polling and destroy stream/event */
    } else {
        DPRINTFS(stderr, "%s unexpected failure on writer/reader %p (%s) "
                 POLL_FMT "\n", __func__, pe, pe_type_to_name(pe),
                 POLL_PRINTA(pe->pe_poll_item.revents));
        rv = -1; /* tell pm to stop polling and destroy stream/event */
    }

    return rv;
}

/*
 * srvapp_write_common() callback notifies application the QUIC stack
 * is ready to send data. The write callback attempts to process
 * all buffers in write queue.  if write queue becomes empty, stream is
 * concluded.
 * This function implements backend common to unidirectional and
 * bidirectional streams.
 */
static int
srvapp_write_common(struct poll_event *pe, struct rr_buffer *rb)
{
    char buf[4096];
    size_t written;
    unsigned int wlen;
    int rv;

    wlen = rb_read(rb, buf, sizeof(buf));
    if (wlen == 0) {
        DPRINTFS(stderr, "%s no more data to write to %p (%s)\n", __func__,
                 pe, pe_type_to_name(pe));
        rv = SSL_stream_conclude(get_ssl_from_pe(pe), 0);
        pe_disable_write(pe);
        /*
         * we deliberately override return value of SSL_stream_conclude() here
         * to keep CI build happy. -1 means we are going to kill poll event
         * anyway.
         *
         * another option would be to return 0 and let poll manager wait
         * for confirmation of FIN packet sent on behalf of
         * SSL_stream_conclude(). At the moment it does not seem necessary.
         * More details can be found here:
         *     https://github.com/openssl/project/issues/1160
         */
        rv = -1;
    } else {
        rv = SSL_write_ex(get_ssl_from_pe(pe), buf, wlen, &written);
        if (rv == 1) {
            rb_advrpos(rb, (unsigned int)written);
            rv = 0;
        } else {
            rv = handle_ssl_error(pe, rv, __func__);
        }
    }

    return rv;
}

static int
srvapp_write_sstreamcb(struct poll_event *pe)
{
    struct poll_event_sbstream *pesb;

    pesb = pe_to_sstream(pe);
    if (pesb == NULL) {
        warnx("%s unexpected type for %p (want SSTREAM, got %s\n)\n",
              __func__, pe, pe_type_to_name(pe));
        return -1;
    }

    if (pesb->pesb_rb == NULL) {
        warnx("%s no response buffer\n", __func__);
        return -1;
    }

    return srvapp_write_common(pe, pesb->pesb_rb);
}

static int
srvapp_write_sustreamcb(struct poll_event *pe)
{
    struct poll_event_sustream *pesu;

    pesu = pe_to_sustream(pe);
    if (pesu == NULL) {
        warnx("%s unexpected type for %p (want SUTREAM, got %s\n)\n",
              __func__, pe, pe_type_to_name(pe));
        return -1;
    }

    if (pesu->pesu_rb == NULL) {
        warnx("%s no response buffer\n", __func__);
        return -1;
    }

    return srvapp_write_common(pe, pesu->pesu_rb);
}

/*
 * Function sets up a response to be sent out by server.
 * For bidirectional streams we just activate write-side
 * callback which then fires as soon as write buffers are
 * available.
 *
 * For unidirectional streams we must request a new stream
 * first to be able to send reply out.
 */
static int
srvapp_setup_response(struct poll_event *pe)
{
    struct poll_stream_context *pscx;
    struct poll_event_sustream *pesu;
    struct poll_event_sbstream *pesb;
    int rv;

    switch (pe->pe_type) {
    case PE_SUSTREAM:
        pesu = pe_to_sustream(pe);
        pscx = OPENSSL_zalloc(sizeof(struct poll_stream_context));
        if (pscx == NULL)
            return -1;
        DPRINTFS(stderr, "%s sustream setup %p [ %p ]\n", __func__, pe,
                 pesu->pesu_rb);
        pscx->pscx = pesu->pesu_rb;
        pesu->pesu_rb = NULL;
        pscx->pscx_cb_ondestroy = (void(*)(void *))rb_destroy;

        /*
         * passing accept 0 indicates we want to create outbound
         * stream (handling OS* event with SSL_new_stream()
         */
        request_new_stream(pesu->pesu_pec, SSL_STREAM_FLAG_UNI,
                           pscx, /* accept */ 0);
        rv = 0;
        break;
    case PE_SSTREAM:
        pesb = pe_to_sstream(pe);
        DPRINTFS(stderr, "%s sstream setup %p [ %p ]\n", __func__, pe,
                 pesb->pesb_rb);
        pe->pe_cb_out = srvapp_write_sstreamcb;
        pe_resume_write(pe);
        rv = 0;
        break;
    default:
        warnx("%s unexpected event type %s\n", __func__, pe_type_to_name(pe));
        rv = -1;
    }

    return rv;
}

static unsigned int
get_fsize(const char *file_name)
{
    const char *digit = file_name;
    unsigned int fsize;

    /* any number we find in filename is desired size */
    fsize = 0;

    while (*digit && !isdigit((int)*digit))
        digit++;

    while (*digit && isdigit((int)*digit)) {
        fsize = fsize * 10;
        fsize = fsize + (*digit - 0x30);
        digit++;
    }

    if (fsize == 0)
        fsize = 12345; /* ? may be random ? */

    return fsize;
}

static struct rr_buffer *
parse_request(const char *buf)
{
    const char *pos = buf;
    char file_name_buf[4096];
    char *dst = file_name_buf;
    char *end = &file_name_buf[4096];
    char *file_name;
    struct rr_buffer *rv;

    while (*pos && isspace((int)*pos))
        pos++;

    if (strncasecmp(pos, "GET", 3) != 0)
        return NULL; /* this will reset the stream */
    pos += 3;

    while (*pos && isspace((int)*pos))
        pos++;

    if (*pos != '/')
        return NULL; /* this will reset the stream */

    /* strip leading slashes */
    while (*pos == '/')
        pos++;

    while ((isalnum((int)*pos) || ispunct((int)*pos)) && (dst < end))
        *dst++ = *pos++;
    if (dst == end)
        dst--;
    *dst = '\0';
    /*
     * if request is something like 'GET / HTTP/1.0...' we assume /index.html
     * otherwise take the last component
     */
    if (file_name_buf[0] == '\0') {
        file_name = "index.html";
    } else {
        file_name = basename(file_name_buf);
        /*
         * I'm not sure what happens when file_name_buf looks for example
         * like that: /foo/bar/nothing/
         * (the basename component is missing/is empty).
         */
        if (file_name == NULL || *file_name == '\0')
            file_name = "foo";
    }

    rv = (struct rr_buffer *)new_txt_full_rrbuff(file_name,
                                                 get_fsize(file_name));

    return rv;
}

/*
 * srvapp_read_cb() callback notifies application there are data
 * waiting to be read from stream. The callback allocates
 * new linked buffer and reads data from stream to newly allocated
 * buffer. It then uses request_write() to put the buffer to write
 * queue so data can be echoed back to client.
 */
static int
srvapp_read_sstreamcb(struct poll_event *pe)
{
    struct poll_event_sbstream *pesb = pe_to_sstream(pe);
    size_t read_len;
    int rv;
    char devnull[4096];

    /*
     * if we could not parse the request in the first chunk (8k), then just
     * wrap around and continue reading data from client.
     */
    if (pesb->pesb_wpos_sz == 0) {
        pesb->pesb_wpos = pesb->pesb_reqbuf;
        pesb->pesb_wpos_sz = sizeof(pesb->pesb_reqbuf) - 1;
    }

    if (pesb->pesb_rb == NULL)
        rv = SSL_read_ex(get_ssl_from_pe(pe), pesb->pesb_wpos,
                         pesb->pesb_wpos_sz, &read_len);
    else
        rv = SSL_read_ex(get_ssl_from_pe(pe), devnull, sizeof(devnull),
                         &read_len);

    if (rv == 0) {
        pe_disable_read(pe);
        /*
         * May be it's over cautious, we should just examine stream state and
         * decide if we can continue with poll (rv == 0) or we should stop
         * polling (rv == -1).
         */
        rv = handle_ssl_error(pe, rv, __func__);
        if (rv == 0) {
            rv = handle_read_stream_state(pe);
            if (rv == 0 && pesb->pesb_rb != NULL)
                rv = srvapp_setup_response(pe);
            else
                DPRINTFS(stderr, "%s error on setup (%p) [%p]\n", __func__,
                         pe, pesb->pesb_rb);

        } else {
            DPRINTFS(stderr, "%s error on read (%p)\n", __func__, pe);
        }

        return rv;
    }
    pesb->pesb_wpos += read_len;
    pesb->pesb_wpos_sz -= read_len;

    if (pesb->pesb_rb == NULL)
        pesb->pesb_rb = parse_request(pesb->pesb_reqbuf);

    return rv;
}

/*
 * Server callback for uni-directional stream. Unlike bidirectional
 * streams, we need to open a new uni-directional stream to send
 * a reply back. As soon as function reads request it sets up
 * a response object and schedules a new stream callback which fires
 * as outbound unidirectional stream is available to send reply.
 */
static int
srvapp_read_sustreamcb(struct poll_event *pe)
{
    struct poll_event_sustream *pesu = pe_to_sustream(pe);
    size_t read_len;
    int rv;
    char devnull[4096];

    /*
     * if we could not parse the request in the first chunk (8k), then just
     * wrap around and continue reading data from client.
     */
    if (pesu->pesu_wpos_sz == 0) {
        pesu->pesu_wpos = pesu->pesu_reqbuf;
        pesu->pesu_wpos_sz = sizeof(pesu->pesu_reqbuf) - 1;
    }

    if (pesu->pesu_rb == NULL)
        rv = SSL_read_ex(get_ssl_from_pe(pe), pesu->pesu_wpos, pesu->pesu_wpos_sz,
                         &read_len);
    else
        rv = SSL_read_ex(get_ssl_from_pe(pe), devnull, sizeof(devnull),
                         &read_len);
    if (rv == 0) {
        pe_disable_read(pe);
        /*
         * May be it's over cautious, we should just examine stream state and
         * decide if we can continue with poll (rv == 0) or we should stop
         * polling (rv == -1).
         */
        rv = handle_ssl_error(pe, rv, __func__);
        if (rv == 0) {
            rv = handle_read_stream_state(pe);
            if (rv == 0 && pesu->pesu_rb != NULL)
                (void)srvapp_setup_response(pe);
            else
                DPRINTFS(stderr, "%s error on setup (%p) [%p]\n", __func__,
                         pe, pesu->pesu_rb);
        } else {
            DPRINTFS(stderr, "%s error on read (%p)\n", __func__, pe);
        }
        return -1;
    }
    pesu->pesu_wpos += read_len;
    pesu->pesu_wpos_sz -= read_len;

    if (pesu->pesu_rb == NULL)
        pesu->pesu_rb = parse_request(pesu->pesu_reqbuf);

    return rv;
}

/*
 * Callback creates new outbound unidirectional stream
 * to send reply back from server to client.
 */
static int
srvapp_new_stream_cb(struct poll_event *qconn_pe)
{
    SSL *qconn;
    SSL *qs;
    struct poll_event_connection *pec;
    struct poll_event *qs_pe = NULL;
    struct rr_buffer *rb = NULL;

    assert(qconn_pe->pe_poll_item.revents & SSL_POLL_EVENT_OS);
    pec = pe_to_connection(qconn_pe);
    assert(pec != NULL);

    qconn = get_ssl_from_pe(qconn_pe);

    if (qconn_pe->pe_poll_item.revents & SSL_POLL_EVENT_OSU) {

        if (ossl_list_pscx_is_empty(&pec->pec_unistream_cx)) {
            qconn_pe->pe_want_events &= ~ SSL_POLL_EVENT_OSU;
            return 0;
        }

        qs = SSL_new_stream(qconn, SSL_STREAM_FLAG_UNI);
        qs_pe = (struct poll_event *)new_sustream_pe(qs);
    } else {
        warnx("%s server attempted to create bidirectional stream", __func__);
        /*
         * server is supposed to open uni-directional stream to
         * send response back.
         *
         * We must not fail, because there might be other streams which belong to
         * connection
         */
        return 0;
    }

    if (qs_pe != NULL) {
        qs_pe->pe_cb_error = srvapp_handle_stream_error;
        qs_pe->pe_want_events = SSL_POLL_EVENT_EW;

        qs_pe->pe_cb_ondestroy = srvapp_ondestroy_sustreamcb;
        qs_pe->pe_cb_in = srvapp_read_sustreamcb;
        qs_pe->pe_cb_out = srvapp_write_sustreamcb;
        rb = get_response_from_pec(pec, qs_pe->pe_type);
        ((struct poll_event_sustream *)qs_pe)->pesu_rb = rb;

        if (rb == NULL) {
            /*
             * the outbound stream availability is subject of flow control.
             * if resources are available server gets stream. So server
             * may actually be able to open more stream than there are
             * requests to respond.
             *
             * This is exactly what happens here. We could open outbound
             * stream. but there is no request to send respond to. We free
             * the stream and stop polling for outbound streams.
             */
            srvapp_ondestroy_sustreamcb(qs_pe);
            SSL_free(qs);
            OPENSSL_free(qs_pe);
            qconn_pe->pe_want_events &= ~SSL_POLL_EVENT_OSU;
            qconn_pe->pe_my_pm->pm_need_rebuild = 1;
        } else {
            add_pe_to_pm(qconn_pe->pe_my_pm, qs_pe);
            pe_resume_write(qs_pe);
        }
    } else {
        warnx("%s allocation of stream failed", __func__);
        SSL_free(qs);
    }

    /*
     * We must not fail, because there might be other streams which belong to
     * connection
     */
    return 0;
}

/*
 * accept stream from remote peer. This function accepts both types
 * of streams (unidirectional and bidirectional).
 */
static int
srvapp_accept_stream_cb(struct poll_event *qconn_pe)
{
    SSL *qconn;
    SSL *qs;
    struct poll_event *qs_pe;
    struct poll_event_connection *pec = pe_to_connection(qconn_pe);
    struct poll_event_sbstream *pesb;
    struct poll_event_sustream *pesu;

    if (pec == NULL) {
        warnx("%s unexpected poll event %p (expected CONNECTION got %s)",
              __func__, qconn_pe, pe_type_to_name(qconn_pe));
        return -1;
    }
    qconn = get_ssl_from_pe(qconn_pe);

    if (qconn_pe->pe_poll_item.revents & SSL_POLL_EVENT_ISU) {
        qs = SSL_accept_stream(qconn, SSL_ACCEPT_STREAM_UNI);
        pesu = new_sustream_pe(qs);
        qs_pe = (struct poll_event *)pesu;
        if (qs_pe == NULL) {
            warnx("%s accept returned NULL (%p) [%x]", __func__,
                  qconn_pe, SSL_get_error(qconn, 0));
            SSL_free(qs);
            /*
             * keep polling on connection. Returning -1 here
             * asking poll loop to destroy it is not an option,
             * because there might be other active streams.
             */
            return 0;
        }
        pesu->pesu_pec = pec;

        qs_pe->pe_cb_in = srvapp_read_sustreamcb;
        qs_pe->pe_cb_ondestroy = srvapp_ondestroy_sustreamcb;
        qs_pe->pe_cb_error = srvapp_handle_stream_error;
        qs_pe->pe_want_events = SSL_POLL_EVENT_ER;
        add_pe_to_pm(qconn_pe->pe_my_pm, qs_pe);
        pe_disable_write(qs_pe);
        pe_resume_read(qs_pe);
    } else {
        qs = SSL_accept_stream(qconn, SSL_ACCEPT_STREAM_BIDI);
        pesb = new_sstream_pe(qs);
        qs_pe = (struct poll_event *) pesb;
        if (qs_pe == NULL) {
            /*
             * keep polling on connection. Returning -1 here
             * asking poll loop to destroy it is not an option,
             * because there might be other active streams.
             */
            warnx("%s accept returned NULL (%p) [%x]", __func__,
                  qconn_pe, SSL_get_error(qconn, 0));
            SSL_free(qs);
            return 0;
        }
        pesb->pesb_pec = pec;

        qs_pe->pe_cb_in = srvapp_read_sstreamcb;
        qs_pe->pe_cb_out = srvapp_write_sstreamcb;
        qs_pe->pe_cb_ondestroy = srvapp_ondestroy_sstreamcb;
        qs_pe->pe_cb_error = srvapp_handle_stream_error;
        qs_pe->pe_want_events = SSL_POLL_EVENT_ER;
        add_pe_to_pm(qconn_pe->pe_my_pm, qs_pe);
        pe_pause_write(qs_pe);
        pe_resume_read(qs_pe);
    }

    return 0;
}

/*
 * The server callback which accepts a new connection from client.
 */
static int
srvapp_accept_qconn(struct poll_event *listener_pe)
{
    SSL *listener;
    SSL *qconn;
    struct poll_event *qc_pe;

    listener = get_ssl_from_pe(listener_pe);
    qconn = SSL_accept_connection(listener, 0);
    if (qconn == NULL)
        return -1;
    SSL_set_default_stream_mode(qconn, SSL_DEFAULT_STREAM_MODE_NONE);

    qc_pe = new_qconn_pe(qconn);
    if (qc_pe != NULL) {
        qc_pe->pe_cb_in = srvapp_accept_stream_cb;
        qc_pe->pe_cb_out = srvapp_new_stream_cb;
        qc_pe->pe_cb_error = app_handle_qconn_error;
        qc_pe->pe_cb_ondestroy = app_destroy_qconn;
        add_pe_to_pm(listener_pe->pe_my_pm, qc_pe);
        qc_pe->pe_my_pm = listener_pe->pe_my_pm;
        qc_pe->pe_type = PE_CONNECTION_SERVER;
        qc_pe->pe_want_events |= SSL_POLL_EVENT_ISB | SSL_POLL_EVENT_ISU;
    } else {
        SSL_free(qconn);
        return -1;
    }

    return 0;
}

/*
 * Main loop for server to accept QUIC connections.
 * Echo every request back to the client.
 */
static int
run_quic_server(SSL_CTX *ctx, struct poll_manager *pm, int fd)
{
    int ok = -1;
    int e = 0;
    unsigned int i;
    SSL *listener;
    struct poll_event *pe;
    struct poll_event_listener *listener_pe = NULL;
    size_t poll_items;
    /*
     * 1sec timeout for server loop to check stopping condition periodically
     */
    struct timeval tv = { 1, 0 };

    /* Create a new QUIC listener */
    if ((listener = SSL_new_listener(ctx, 0)) == NULL)
        goto err;

    if (!SSL_set_fd(listener, fd))
        goto err;

    /*
     * Set the listener mode to non-blocking, which is inherited by
     * child objects.
     */
    if (!SSL_set_blocking_mode(listener, 0))
        goto err;

    /*
     * Begin listening. Note that is not usually needed as SSL_accept_connection
     * will implicitly start listening. It is only needed if a server wishes to
     * ensure it has started to accept incoming connections but does not wish to
     * actually call SSL_accept_connection yet.
     */
    if (!SSL_listen(listener))
        goto err;

    listener_pe = new_listener_pe(listener);
    if (listener_pe == NULL)
        goto err;
    listener = NULL; /* listener_pe took ownership */

    pe = (struct poll_event *)listener_pe;
    pe->pe_cb_in = srvapp_accept_qconn;
    pe->pe_cb_error = pe_handle_listener_error;

    add_pe_to_pm(pm, pe);
    listener_pe = NULL; /* listener is owned by pm now */

    /*
     * Begin an infinite loop of listening for connections. We will only
     * exit this loop if we encounter an error or are told to stop.
     */
    pm->pm_continue = 1;
    while (stop_server == 0 && pm->pm_continue) {
        rebuild_poll_set(pm);
        ok = SSL_poll((SSL_POLL_ITEM *)pm->pm_poll_set, pm->pm_event_count,
                      sizeof(struct poll_event), &tv, 0, &poll_items);

        if (ok == 0 && poll_items == 0)
            break;

        for (i = 0; i < pm->pm_event_count; i++) {
            e = 0;
            pe = &pm->pm_poll_set[i];
            if (pe->pe_poll_item.revents == 0)
                continue;
            DPRINTFS(stderr, "%s %s (%p) " POLL_FMT "\n", __func__,
                     pe_type_to_name(pe->pe_self), pe->pe_self,
                     POLL_PRINTA(pe->pe_poll_item.revents));
            pe->pe_self->pe_poll_item.revents = pe->pe_poll_item.revents;
            pe = pe->pe_self;
            if (pe->pe_poll_item.revents & SSL_POLL_ERROR)
                e = pe->pe_cb_error(pe);
            else if (pe->pe_poll_item.revents & SSL_POLL_IN)
                e = pe->pe_cb_in(pe);
            else if (pe->pe_poll_item.revents & SSL_POLL_OUT)
                e = pe->pe_cb_out(pe);
            if (e == -1)
                destroy_pe(pe);
        }
    }

    DPRINTFS(stderr, "%s stop_server: %d, pm_continue: %d\n", __func__,
             stop_server, pm->pm_continue);

    ok = EXIT_SUCCESS;
err:
    SSL_free(listener);
    destroy_pe((struct poll_event *)listener_pe);
    return ok;
}

/*
 * ALPN strings for TLS handshake. Only 'http/1.0' and 'hq-interop'
 * are accepted.
 */
static const unsigned char alpn_ossltest[] = {
    8,  'h', 't', 't', 'p', '/', '1', '.', '0',
};

/*
 * This callback validates and negotiates the desired ALPN on the server side.
 */
static int
select_alpn(SSL *ssl, const unsigned char **out, unsigned char *out_len,
            const unsigned char *in, unsigned int in_len, void *arg)
{
    if (SSL_select_next_proto((unsigned char **)out, out_len, alpn_ossltest,
                              sizeof(alpn_ossltest), in,
                              in_len) == OPENSSL_NPN_NEGOTIATED)
        return SSL_TLSEXT_ERR_OK;
    return SSL_TLSEXT_ERR_ALERT_FATAL;
}

/* Create SSL_CTX. for server */
static SSL_CTX *
create_srv_ctx(const char *cert_path, const char *key_path)
{
    SSL_CTX *ctx;

    ctx = SSL_CTX_new(OSSL_QUIC_server_method());
    if (ctx == NULL)
        goto err;

    if (SSL_CTX_use_certificate_chain_file(ctx, cert_path) <= 0) {
        DPRINTFS(stderr, "couldn't load certificate file: %s\n", cert_path);
        goto err;
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, key_path, SSL_FILETYPE_PEM) <= 0) {
        DPRINTFS(stderr, "couldn't load key file: %s\n", key_path);
        goto err;
    }

    /* Setup ALPN negotiation callback to decide which ALPN is accepted. */
    SSL_CTX_set_alpn_select_cb(ctx, select_alpn, NULL);

    return ctx;

err:
    SSL_CTX_free(ctx);
    return NULL;
}

/* Create UDP socket on the given port. */
static int
create_srv_socket(uint16_t port)
{
    int fd;
    struct sockaddr_in sa = {0};

    /* Retrieve the file descriptor for a new UDP socket */
    if ((fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
        DPRINTFS(stderr, "cannot create socket");
        return -1;
    }

    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);

    /* Bind to the new UDP socket on localhost */
    if (bind(fd, (const struct sockaddr *)&sa, sizeof(sa)) < 0) {
        DPRINTFS(stderr, "cannot bind to %u\n", port);
        BIO_closesocket(fd);
        return -1;
    }

    /* Set port to nonblocking mode */
    if (BIO_socket_nbio(fd, 1) <= 0) {
        DPRINTFS(stderr, "Unable to set port to nonblocking mode");
        BIO_closesocket(fd);
        return -1;
    }

    return fd;
}

static void
server_thread(size_t port)
{
    struct poll_manager *pm;
    int fd;

    /* Create and bind a UDP socket. */
    if ((fd = create_srv_socket((uint16_t)port)) < 0) {
        ERR_print_errors_fp(stderr);
        errx(1, "Failed to create server socket");
    }

    pm = create_poll_manager();
    if (pm == NULL) {
        ERR_print_errors_fp(stderr);
        errx(1, "Failed to create poll manager for server");
    }
    pm->pm_name = "server";

    /* QUIC server connection acceptance loop. */
    if (run_quic_server(server_ctx, pm, fd) < 0) {
        destroy_poll_manager(pm);
        BIO_closesocket(fd);
        ERR_print_errors_fp(stderr);
        errx(1, "Error in QUIC server loop");
    }

    destroy_poll_manager(pm);
    /* Free resources. */
    BIO_closesocket(fd);
}

/*
 * client application
 */
static int
clntapp_handle_stream_error(struct poll_event *pe)
{
    int rv = 0;

    if (pe->pe_poll_item.revents & SSL_POLL_EVENT_ER) {

        if ((pe->pe_poll_item.events & SSL_POLL_EVENT_R) == 0) {
            DPRINTFC(stderr, "%s unexpected failure on reader %p (%s) "
                     POLL_FMT "\n", __func__, pe, pe_type_to_name(pe),
                     POLL_PRINTA(pe->pe_poll_item.revents));
        }

        (void) handle_read_stream_state(pe);
        rv = -1; /* tell pm to stop polling and destroy stream/event */
    } else if (pe->pe_poll_item.revents & SSL_POLL_EVENT_EW) {

        if ((pe->pe_poll_item.events & SSL_POLL_EVENT_W) == 0) {
            DPRINTFC(stderr, "%s unexpected failure on writer %p (%s) "
                     POLL_FMT "\n", __func__, pe, pe_type_to_name(pe),
                     POLL_PRINTA(pe->pe_poll_item.revents));
        }
        (void) handle_write_stream_state(pe);

        rv = -1; /* tell pm to stop polling and destroy stream/event */
    } else {
        DPRINTFC(stderr, "%s unexpected failure on writer/reader %p (%s) "
                 POLL_FMT "\n", __func__, pe, pe_type_to_name(pe),
                 POLL_PRINTA(pe->pe_poll_item.revents));
        rv = -1; /* tell pm to stop polling and destroy stream/event */
    }

    return rv;
}

/*
 * function creates a request object for client. The request buffer
 * is object has a file-like semantics, so it keeps a position
 * where next byte needs to be read from.
 */
static void *
clntapp_create_request(size_t arg_sz, size_t payload_sz)
{
    struct request_txt_full *rtf;
    char request[80];

    snprintf(request, sizeof(request), "/foo/%zu", arg_sz);

    rtf = new_txt_full_request(request,
                               (payload_sz > 0) ? "foo" : NULL, payload_sz);

    return rtf;
}

static void
clntapp_ondestroy_ccxcb(void *ccx_arg)
{
    struct client_context *ccx = ccx_arg;

    if (ccx != NULL) {
        rb_destroy(ccx->ccx_rb);
        OPENSSL_free(ccx);
    }
}

/*
 * As soon as client sends its request out, it must prepare its read side to
 * read reply for server.  Bidirectional streams are straightforward, the
 * client just starts receiving a read notifications when reply from server
 * is available. Unidirectional streams are more complicated as client
 * needs to accept a stream first to start reading a reply from server.
 * The function here sets up an accept callback to create inbound stream
 * for server reply.
 */
static int
clntapp_setup_response(struct poll_event *pe)
{
    struct poll_stream_context *pscx;
    struct client_context *ccx;
    struct poll_event_custream *pecsu = pe_to_custream(pe);
    int rv;

    if (pecsu != NULL) {
        pscx = OPENSSL_zalloc(sizeof(struct poll_stream_context));
        if (pscx == NULL) {
            warnx("%s cannot allocate memory for poll stream context", __func__);
            return -1;
        }

        ccx = OPENSSL_malloc(sizeof(struct client_context));
        if (ccx == NULL) {
            OPENSSL_free(pscx);
            warnx("%s cannot allocate memory for client context", __func__);
            return -1;
        }

        ccx->ccx_rb = pecsu->pecsu_rb;
        pecsu->pecsu_rb = NULL;
        ccx->ccx_ss = pecsu->pecsu_ss;
        pecsu->pecsu_ss = NULL;

        pscx->pscx = ccx;
        pscx->pscx_cb_ondestroy = clntapp_ondestroy_ccxcb;

        /*
         * passing accept 1 indicates we want to accept inbound
         * stream (handling IS* event with SSL_accept_stream()
         */
        request_new_stream(pecsu->pecsu_pec, SSL_STREAM_FLAG_UNI,
                           pscx, /* accept */ 1);
        rv = 0;
    } else if (pe_to_cstream(pe) != NULL) {
        pe_resume_read(pe);
        rv = 0;
    } else {
        rv = -1;
    }

    return rv;
}

/*
 * clntapp_write_common() sets up a handling of response from server once all
 * data are written from client. This is common code for client write callbacks
 * for bidirectional and unidirectional stream.
 */
static int
clntapp_write_common(struct poll_event *pe, struct request_buffer *rb,
                     struct stream_stats *ss)
{
    char buf[4096];
    size_t written;
    unsigned int wlen;
    int rv;

    wlen = rb_read(rb, buf, sizeof(buf));
    if (wlen == 0) {
        DPRINTFC(stderr, "%s no more data to write to %p (%s)\n", __func__,
                 pe, pe_type_to_name(pe));
        rv = SSL_stream_conclude(get_ssl_from_pe(pe), 0);
        if (rv == 0) {
            DPRINTFC(stderr, "%s Wow, stream conclude failed %p (%s)\n",
                     __func__, pe, pe_type_to_name(pe));
            return -1;
        }
        pe_disable_write(pe);

        rv = clntapp_setup_response(pe);
        if (rv == -1)
            DPRINTFC(stderr, "%s clntapp_setup_response() failed\n", __func__);

        /*
         * tell polling loop to remove poll event for
         * unidirectional stream as it is done.
         */
        if (pe->pe_type == PE_CUSTREAM)
            rv = -1;
    } else {
        rv = SSL_write_ex(get_ssl_from_pe(pe), buf, wlen, &written);
        if (rv == 1) {
            ss->ss_tx += written;
            rb_advrpos(rb, (unsigned int)written);
            rv = 0;
        } else {
            rv = handle_ssl_error(pe, rv, __func__);
        }
    }

    return rv;
}

static int
clntapp_write_cstreamcb(struct poll_event *pe)
{
    struct poll_event_cstream *pecs = pe_to_cstream(pe);

    if (pecs == NULL) {
        warnx("%s unexpected event for %p (want CSTREAM got %s)",
              __func__, pe, pe_type_to_name(pe));
        return -1;
    }

    return clntapp_write_common(pe, pecs->pecs_rb, pecs->pecs_ss);
}

static int
clntapp_write_custreamcb(struct poll_event *pe)
{
    struct request_buffer *rb;
    struct poll_event_custream *pecsu = pecsu = pe_to_custream(pe);

    if (pecsu == NULL) {
        warnx("%s unexpected event for %p (want CSTREAM got %s)",
              __func__, pe, pe_type_to_name(pe));
        return -1;
    }

    return clntapp_write_common(pe, pecsu->pecsu_rb, pecsu->pecsu_ss);
}

/*
 * Callback reads reply from server on bidirectional stream.
 */
static int
clntapp_read_cstreamcb(struct poll_event *pe)
{
    struct poll_event_cstream *pecs;
    char devnull[16384];
    size_t read_len;
    int rv;

    pecs = pe_to_cstream(pe);
    if (pecs == NULL) {
        warnx("%s unexpected event type (want CSTREAM, got %s)\n",
              __func__, pe_type_to_name(pe));
        return -1;
    }

    rv = SSL_read_ex(get_ssl_from_pe(pe), devnull, sizeof(devnull), &read_len);
    if ((rv == 0) || (read_len == 0)) {
        rv = -1; /* stream is done, tell poll manager to remove it */
        DPRINTFC(stderr, "%s received: %zu\n", __func__, pecs->pecs_ss->ss_rx);
    } else {
        rv = 0; /* keep polling */
        pecs->pecs_ss->ss_rx += read_len;
    }

    return rv;
}

/*
 * Callback reads reply from server on unidirectional stream.
 */
static int
clntapp_read_custreamcb(struct poll_event *pe)
{
    struct poll_event_custream *pecsu;
    char devnull[16384];
    size_t read_len;
    int rv;

    pecsu = pe_to_custream(pe);
    if (pecsu == NULL) {
        warnx("%s unexpected event type (want CUSTREAM, got %s)\n",
              __func__, pe_type_to_name(pe));
        return -1;
    }

    rv = SSL_read_ex(get_ssl_from_pe(pe), devnull, sizeof(devnull), &read_len);
    if ((rv == 0) || (read_len == 0)) {
        rv = -1; /* stream is done, tell poll manager to remove it */
        DPRINTFC(stderr, "%s (%p) received: %zu\n", __func__, pecsu,
                 pecsu->pecsu_ss->ss_rx);
    } else {
        rv = 0; /* keep polling */
        pecsu->pecsu_ss->ss_rx += read_len;
    }

    return rv;
}

/*
 * Function is called when stream is destroyed. As soon as all streams
 * are destroyed we call SSL_shutdown() to close connection.
 */
static void
clntapp_update_pec(struct poll_event_connection *pec, struct stream_stats *ss)
{
    int e;

    if (ss == NULL)
        return;

    /*
     * bump connection stats and close connection when done
     */
    pec->pec_cs->cs_tx += ss->ss_tx;
    pec->pec_cs->cs_rx += ss->ss_rx;
    /* ? timeestamp ? */
    ossl_list_ss_insert_head(&pec->pec_cs->cs_done, ss);
    if (ossl_list_ss_num(&pec->pec_cs->cs_done) == STREAM_COUNT) {
        e = SSL_shutdown(get_ssl_from_pe((struct poll_event *)pec));
        DPRINTFC(stderr, "%s shutdown on %p (%d)\n", __func__, pec, e);
    }
}

/*
 * Callback fires when bidirectional client stream gets destroyed.
 */
static void
clntapp_ondestroy_cstreamcb(struct poll_event *pe)
{
    struct poll_event_cstream *pecs;
    struct poll_event_connection *pec;
    struct stream_stats *ss;

    pecs = pe_to_cstream(pe);
    if (pecs == NULL) {
        warnx("%s unexpected type for %p (want CSTREAM got %s)\n",
              __func__, pecs, pe_type_to_name(pe));
        return;
    }

    rb_destroy(pecs->pecs_rb);
    pec = pecs->pecs_pec;
    ss = pecs->pecs_ss;

    clntapp_update_pec(pec, ss);
    DPRINTFC(stderr, "%s %p @ %p\n", __func__, pe, pec);
}

/*
 * Callback fires when unidirectional client stream gets destroyed.
 */
static void
clntapp_ondestroy_custreamcb(struct poll_event *pe)
{
    struct poll_event_custream *pecsu;
    struct poll_event_connection *pec;
    struct stream_stats *ss;

    pecsu = pe_to_custream(pe);
    if (pecsu == NULL) {
        warnx("%s unexpected type for %p (want CUSTREAM got %s)\n",
              __func__, pecsu, pe_type_to_name(pe));
        return;
    }

    rb_destroy(pecsu->pecsu_rb);
    pec = pecsu->pecsu_pec;
    ss = pecsu->pecsu_ss;

    clntapp_update_pec(pec, ss);
    DPRINTFC(stderr, "%s %p @ %p\n", __func__, pe, pec);
}

/*
 * This deals with the situation when client is told to connect only (-u 0 -b
 * 0). To determine the client could complete handshake successfully we ask
 * SSL_poll() to let us know when outbound stream becomes available. As soon as
 * outbound stream is available we close the connection.
 */
static int
clntapp_null_run_cb(struct poll_event *qconn_pe)
{
    struct poll_event_connection *pec;

    pec = pe_to_connection(qconn_pe);
    assert(pec != NULL);
    DPRINTFC(stderr, "%s no streams to create for connection %p\n",
             __func__, pec);
    SSL_shutdown(get_ssl_from_pe(qconn_pe));

    return 0;
}

/*
 * Callback fires when new stream is available to send request out.  The
 * callback inspects the todo list of request to be sent.  If no requests are
 * available the callback stops polling for outbound stream event availability.
 */
static int
clntapp_new_stream_cb(struct poll_event *qconn_pe)
{
    SSL *qconn;
    SSL *qs;
    struct poll_event_connection *pec;
    struct poll_event *qs_pe = NULL;
    struct poll_event_cstream *pecs;
    struct poll_event_custream *pecsu;
    struct stream_stats *ss;
    int rv = 0;
    int want_type;

    assert(qconn_pe->pe_poll_item.revents & SSL_POLL_EVENT_OS);
    pec = pe_to_connection(qconn_pe);
    assert(pec != NULL);

    if (qconn_pe->pe_poll_item.revents & SSL_POLL_EVENT_OSB)
        want_type = SS_BIDISTREAM;
    else
        want_type = SS_UNISTREAM;

    /*
     * Search a todo list for desired session type
     * (either unidirectional stream session or bidirectional stream session)
     */
    OSSL_LIST_FOREACH(ss, ss, &pec->pec_cs->cs_todo) {
        if (ss->ss_type == want_type)
            break;
    }

    if (ss == NULL) {
        /* stop polling on uni/bidi stream */
        qconn_pe->pe_want_events &= ~(SS_TYPE_TO_POLLEV(want_type));

        /* if all requests are dispatch stop polling write side completely */
        ss = ossl_list_ss_head(&pec->pec_cs->cs_todo);
        if (ss == NULL) {
            pe_pause_write(qconn_pe);
            DPRINTFC(stderr, "%s conn %p no more requests to handle\n",
                     __func__, qconn_pe);
        } else {
            qconn_pe->pe_want_events |= SS_TYPE_TO_POLLEV(ss->ss_type);
        }

        qconn_pe->pe_my_pm->pm_need_rebuild = 1;

        return 0;
    }

    ossl_list_ss_remove(&pec->pec_cs->cs_todo, ss);
    qconn = get_ssl_from_pe(qconn_pe);
    qs = SSL_new_stream(qconn, SS_TYPE_TO_SFLAG(want_type));
    if (qs == NULL) {
        warnx("%s failed to create stream (%p)", __func__, qconn_pe);
        abort();
    }

    if (want_type == SS_BIDISTREAM) {
        pecs = new_cstream_pe(qs);
        if (pecs != NULL) {
            pecs->pecs_pec = pec;
            pecs->pecs_ss = ss;
            pecs->pecs_rb = clntapp_create_request(ss->ss_req_sz,
                                                   ss->ss_body_sz);
            qs_pe = (struct poll_event *)pecs;
            qs_pe->pe_cb_ondestroy = clntapp_ondestroy_cstreamcb;
            qs_pe->pe_cb_in = clntapp_read_cstreamcb;
            qs_pe->pe_cb_out = clntapp_write_cstreamcb;
            qs_pe->pe_want_events = SSL_POLL_EVENT_ER;
            add_pe_to_pm(qconn_pe->pe_my_pm, qs_pe);
            pe_resume_read(qs_pe);
            DPRINTFC(stderr, "%s got new bidi-stream %p on %p\n",
                     __func__, qs_pe, qconn_pe);
        }
    } else {
        pecsu = new_custream_pe(qs);
        if (pecsu != NULL) {
            pecsu->pecsu_pec = pec;
            pecsu->pecsu_ss = ss;
            pecsu->pecsu_rb = clntapp_create_request(ss->ss_req_sz,
                                                     ss->ss_body_sz);
            qs_pe = (struct poll_event *)pecsu;
            qs_pe->pe_cb_out = clntapp_write_custreamcb;
            qs_pe->pe_cb_ondestroy = clntapp_ondestroy_custreamcb;
            add_pe_to_pm(qconn_pe->pe_my_pm, qs_pe);
            pe_disable_read(qs_pe);
            DPRINTFC(stderr, "%s got new uni-stream %p on %p\n",
                     __func__, qs_pe, qconn_pe);
        }
    }

    if (qs_pe != NULL) {
        qs_pe->pe_cb_error = clntapp_handle_stream_error;
        qs_pe->pe_want_events = SSL_POLL_EVENT_EW;
        pe_resume_write(qs_pe);
        DPRINTFC(stderr, "%s got %p (%s) for %p\n", __func__, qs_pe,
                 pe_type_to_name(qs_pe), qconn_pe);
    } else {
        warnx("%s failed to create poll event (%p)", __func__, qconn_pe);
        SSL_free(qs);
        rv = -1;
    }

    return rv;
}

/*
 * Callback fires to accept unidirectional stream from server
 * to read reply.
 */
static int
clntapp_accept_stream_cb(struct poll_event *qconn_pe)
{
    SSL *qconn;
    SSL *qs;
    struct poll_event *qs_pe;
    struct poll_event_connection *pec = pe_to_connection(qconn_pe);
    struct poll_event_custream *pecsu;
    struct poll_stream_context *pscx;

    qconn = get_ssl_from_pe(qconn_pe);
    if (qconn_pe->pe_poll_item.revents & SSL_POLL_EVENT_ISU) {
        qs = SSL_accept_stream(qconn, SSL_ACCEPT_STREAM_UNI);
        pecsu = new_custream_pe(qs);
        qs_pe = (struct poll_event *)pecsu;
        if (qs_pe == NULL) {
            SSL_free(qs);
            return -1;
        }
        qs_pe = (struct poll_event *)pecsu;
        qs_pe->pe_cb_error = clntapp_handle_stream_error;
        qs_pe->pe_cb_in = clntapp_read_custreamcb;
        qs_pe->pe_cb_ondestroy = clntapp_ondestroy_custreamcb;
        qs_pe->pe_want_events = SSL_POLL_EVENT_ER;

        /*
         * move context which got allocated with request
         * to response handler.
         */
        pecsu->pecsu_pec = pec;
        pscx = ossl_list_pscx_head(&pec->pec_unistream_cx);
        if (pscx == NULL) {
            warnx("%s no context for unistream client (%p)",
                   __func__, qconn_pe);
            clntapp_ondestroy_custreamcb(qs_pe);
            OPENSSL_free(qs_pe);
            SSL_free(qs);
            /*
             * keep polling on connection. returning -1 to
             * destroy it is not option as there still might be
             * other active streams
             */
            return 0;
        }
        ossl_list_pscx_remove(&pec->pec_unistream_cx, pscx);
        pecsu->pecsu_ss = ((struct client_context *)pscx->pscx)->ccx_ss;
        ((struct client_context *)pscx->pscx)->ccx_ss = NULL;
        pecsu->pecsu_rb = ((struct client_context *)pscx->pscx)->ccx_rb;
        ((struct client_context *)pscx->pscx)->ccx_rb = NULL;
        OPENSSL_free(pscx->pscx);
        OPENSSL_free(pscx);

        DPRINTFC(stderr, "%s got %p for connection %p\n",
                 __func__, qs_pe, qconn_pe);
        add_pe_to_pm(qconn_pe->pe_my_pm, qs_pe);
        pe_disable_write(qs_pe);
        pe_resume_read(qs_pe);
    } else {
        warnx("%s client can accept unidirectional streams only (%p)",
              __func__, qconn_pe);
    }

    return 0;
}

static int
run_quic_client(struct poll_manager *pm)
{
    int ok;
    int e = 0;
    size_t poll_items;
    unsigned int i;
    struct poll_event *pe;

    while (pm->pm_event_count > 0) {
        ok = SSL_poll((SSL_POLL_ITEM *)pm->pm_poll_set, pm->pm_event_count,
                      sizeof(struct poll_event), NULL, 0, &poll_items);

        if (ok == 0)
            break;

        for (i = 0; i < pm->pm_event_count; i++) {
            pe = &pm->pm_poll_set[i];
            e = 0;
            DPRINTFC(stderr, "%s %s (%p) " POLL_FMT "\n", __func__,
                     pe_type_to_name(pe), pe->pe_self,
                     POLL_PRINTA(pe->pe_poll_item.revents));
            pe->pe_self->pe_poll_item.revents = pe->pe_poll_item.revents;
            pe = pe->pe_self;
            if (pe->pe_poll_item.revents & SSL_POLL_ERROR)
                e = pe->pe_cb_error(pe);
            else if (pe->pe_poll_item.revents & SSL_POLL_IN)
                e = pe->pe_cb_in(pe);
            else if (pe->pe_poll_item.revents & SSL_POLL_OUT)
                e = pe->pe_cb_out(pe);
            if (e == -1)
                destroy_pe(pe);
        }
        rebuild_poll_set(pm);
        DPRINTFC(stderr, "%s ----------------------\n", __func__);
    }

    ok = (pm->pm_event_count == 0);

    return ok;
}

static BIO *
create_socket_bio(const char *hostname, const char *port, int family,
                  BIO_ADDR **peer_addr)
{
    int sock = -1;
    BIO_ADDRINFO *res;
    const BIO_ADDRINFO *ai = NULL;
    BIO *bio;

    if (!BIO_lookup_ex(hostname, port, BIO_LOOKUP_CLIENT, family, SOCK_DGRAM, 0,
                       &res)) {
        DPRINTFC(stderr, "%s BIO_lookp_ex failed\n", __func__);
        return NULL;
    }

    for (ai = res; ai != NULL; ai = BIO_ADDRINFO_next(ai)) {
        sock = BIO_socket(BIO_ADDRINFO_family(ai), SOCK_DGRAM, 0, 0);
        if (sock == -1)
            continue;

        if (!BIO_connect(sock, BIO_ADDRINFO_address(ai), 0)) {
            BIO_closesocket(sock);
            sock = -1;
            continue;
        }

        if (!BIO_socket_nbio(sock, 1)) {
            BIO_closesocket(sock);
            sock = -1;
            continue;
        }

        break;
    }

    if (sock != -1) {
        *peer_addr = BIO_ADDR_dup(BIO_ADDRINFO_address(ai));
        if (*peer_addr == NULL) {
            BIO_closesocket(sock);
            DPRINTFC(stderr, "%s could not allocate peer_addr\n", __func__);
            return NULL;
        }
    }

    BIO_ADDRINFO_free(res);

    if (sock == -1) {
        DPRINTFC(stderr, "%s could not connect to %s:%s\n", __func__, hostname,
                 portstr);
        return NULL;
    }

    bio = BIO_new(BIO_s_datagram());
    if (bio == NULL) {
        DPRINTFC(stderr, "%s could create bio for socket\n", __func__);
        BIO_closesocket(sock);
        return NULL;
    }

    BIO_set_fd(bio, sock, BIO_CLOSE);

    return bio;
}

static struct poll_event *
create_client_pe(SSL_CTX *ctx, struct client_stats *cs)
{
    unsigned char alpn[] = { 8, 'h', 't', 't', 'p', '/', '1', '.', '0' };
    SSL *qconn = NULL;
    BIO *bio = NULL;
    BIO_ADDR *peer_addr = NULL;
    struct poll_event *qc_pe;
    struct poll_event_connection *qc_pec;
    struct stream_stats *ss;

    qconn = SSL_new(ctx);
    if (qconn == NULL) {
        DPRINTFC(stderr, "%s SSL_new() failed\n", __func__);
        goto fail;
    }

    bio = create_socket_bio(hostname, portstr, AF_INET, &peer_addr);
    if (bio == NULL) {
        DPRINTFC(stderr, "%s no bio\n", __func__);
        goto fail;
    }
    SSL_set_bio(qconn, bio, bio);
    bio = NULL;

    if (SSL_set_tlsext_host_name(qconn, hostname) == 0) {
        DPRINTFC(stderr, "%s SSL_set_tlsext_host_name() failed\n", __func__);
        goto fail;
    }

    if (SSL_set1_host(qconn, hostname) == 0) {
        DPRINTFC(stderr, "%s SSL_set1_host() failed\n", __func__);
        goto fail;
    }

    /* SSL_set_alpn_protos returns 0 for success! */
    if (SSL_set_alpn_protos(qconn, alpn, sizeof(alpn)) != 0) {
        DPRINTFC(stderr, "%s SSL_set_alpn_protos() failed\n", __func__);
        goto fail;
    }

    /* Set the IP address of the remote peer */
    if (SSL_set1_initial_peer_addr(qconn, peer_addr) == 0) {
        DPRINTFC(stderr, "%s SSL_set1_initial_peer_addr() failed\n", __func__);
        goto fail;
    }

    if (SSL_set_blocking_mode(qconn, 0) == 0) {
        DPRINTFC(stderr, "%s SSL_set_blocking_mode() failed\n", __func__);
        goto fail;
    }

    qc_pe = new_qconn_pe(qconn);
    if (qc_pe == NULL) {
        DPRINTFC(stderr, "%s new_qconn_pe() failed\n", __func__);
        goto fail;
    }

    qc_pe->pe_cb_in = clntapp_accept_stream_cb;
    qc_pe->pe_cb_out = clntapp_new_stream_cb;
    qc_pe->pe_cb_error = app_handle_qconn_error;
    qc_pe->pe_cb_ondestroy = app_destroy_qconn;

    qc_pec = pe_to_connection(qc_pe);
    qc_pec->pec_cs = cs;

    /*
     * client wants to send request, it needs to create outbound stream.
     */
    if ((ss = ossl_list_ss_head(&cs->cs_todo)) != NULL) {
        switch (ss->ss_type) {
        case SS_UNISTREAM:
            qc_pe->pe_want_events |= SSL_POLL_EVENT_OSU;
            break;
        case SS_BIDISTREAM:
            qc_pe->pe_want_events |= SSL_POLL_EVENT_OSB;
            break;
        default:
            warnx("No streams for connection\n");
        }
    }

    /*
     * Force new stream event so we can detect client connects
     * to server. The clntapp_new_stream_cb callback then detects there
     * is nothing to do and initiates connection shutdown.
     */
    if ((qc_pe->pe_want_events & (SSL_POLL_EVENT_OS)) == 0) {
        qc_pe->pe_want_events |= SSL_POLL_EVENT_OSB;
        qc_pe->pe_cb_out = clntapp_null_run_cb;
    }

    return qc_pe;

fail:
    SSL_free(qconn);
    BIO_free(bio);
    BIO_ADDR_free(peer_addr);

    return NULL;
}

static struct stream_stats *
create_stream_stats(unsigned int req_sz, unsigned int body_sz, char type)
{
    struct stream_stats *ss;

    ss = OPENSSL_zalloc(sizeof(struct stream_stats));
    if (ss != NULL) {
        ss->ss_req_sz = req_sz;
        ss->ss_body_sz = body_sz;
        ss->ss_type = type;
        ss->ss_rx = 0;
        ss->ss_tx = 0;
    }

    return ss;
}

static void
destroy_test_scenario(struct client_stats cs[])
{
    unsigned int i;
    struct stream_stats *ss;

    OPENSSL_assert(cs != NULL);

    for (i = 0; i < client_config.cc_clients; i++) {
        while ((ss = ossl_list_ss_head(&cs[i].cs_todo)) != NULL) {
            ossl_list_ss_remove(&cs[i].cs_todo, ss);
            OPENSSL_free(ss);
        }

        while ((ss = ossl_list_ss_head(&cs[i].cs_done)) != NULL) {
            ossl_list_ss_remove(&cs[i].cs_done, ss);
            OPENSSL_free(ss);
        }
    }

    OPENSSL_free(cs);
}

/*
 * creates a scenario for performance test. The scenario is array
 * of connections. Each connection has list of streams to perform.
 * The streams are moved from todo list to done list as they are
 * being processed.
 */
static struct client_stats *
create_test_scenario(void)
{
    struct client_stats *cs;
    struct stream_stats *ss;
    unsigned int arg_sz, body_sz;
    unsigned int i, j;

    cs = OPENSSL_zalloc(sizeof(struct client_stats) *
                        client_config.cc_clients);

    if (cs != NULL) {
        for (i = 0; i < client_config.cc_clients; i++) {
            ossl_list_ss_init(&cs[i].cs_todo);
            ossl_list_ss_init(&cs[i].cs_done);

            arg_sz = client_config.cc_rep_sz;
            body_sz = client_config.cc_req_sz;
            for (j = 0; j < client_config.cc_ustreams; j++) {
                ss = create_stream_stats(arg_sz, body_sz, SS_UNISTREAM);
                if (ss == NULL) {
                    destroy_test_scenario(cs);
                    return NULL;
                }
                ossl_list_ss_insert_tail(&cs[i].cs_todo, ss);
            }

            arg_sz = client_config.cc_rep_sz;
            body_sz = client_config.cc_req_sz;
            for (j = 0; j < client_config.cc_bstreams; j++) {
                ss = create_stream_stats(arg_sz, body_sz, SS_BIDISTREAM);
                if (ss == NULL) {
                    destroy_test_scenario(cs);
                    return NULL;
                }
                ossl_list_ss_insert_tail(&cs[i].cs_todo, ss);
            }
        }
    }

    return cs;
}

static int
client_thread(void)
{
    SSL_CTX *ctx;
    struct poll_manager *pm;
    struct poll_event *pec;
    int rv;
    struct client_stats *cs;
    unsigned int i;
    size_t rx, tx;
    OSSL_TIME start, end;
    float duration;

    cs = create_test_scenario();
    if (cs == NULL)
        errx(1, "%s can not create test scenario (malloc)\n", __func__);

    ctx = SSL_CTX_new(OSSL_QUIC_client_method());
    if (ctx == NULL)
        errx(1, "%s SSL_CTX_new() failed", __func__);

    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

    pm = create_poll_manager();
    if (pm == NULL) {
        ERR_print_errors_fp(stderr);
        errx(1, "Failed to create poll manager for server");
    }
    pm->pm_name = "client";

    start = ossl_time_now();
    for (i = 0; i < client_config.cc_clients; i++) {
        pec = create_client_pe(ctx, &cs[i]);
        if (pec == NULL) {
            ERR_print_errors_fp(stderr);
            errx(1, "Failed to create connection");
        }

        add_pe_to_pm(pm, pec);
        SSL_set_default_stream_mode(get_ssl_from_pe(pec),
                                    SSL_DEFAULT_STREAM_MODE_NONE);
        SSL_connect(get_ssl_from_pe(pec));
    }

    rebuild_poll_set(pm);
    rv = run_quic_client(pm);

    destroy_poll_manager(pm);
    SSL_CTX_free(ctx);
    end = ossl_time_now();
    duration = ossl_time2ticks(ossl_time_subtract(end, start)) / (double)OSSL_TIME_MS;
    rx = 0;
    tx = 0;
    for (i = 0; i < client_config.cc_clients; i++) {
        rx += cs[i].cs_rx;
        tx += cs[i].cs_tx;
    }
    if (terse) {
        printf("%.04lf\n", ((double)(rx + tx)) / duration);
    } else {
        printf("%s\n\ttx: %zu\n\trx: %zu\nin %.4f secs\n", __func__, tx, rx,
               duration / OSSL_TIME_US);
    }

    destroy_test_scenario(cs);

    return rv;
}

static void usage(const char *progname)
{
    fprintf(stderr, "%s -p portnum -c connections -b bidi_stream_count "
            "-u uni_stream_count -s base_size [-V]"
            "path/to/cert path/to/certkey\n"
            "\t-p port number to use (<1, 65535>), default 8000\n"
            "\t-c number of connections to establish, default 10\n"
            "\t-b number of bidirectional streams to use, default 10\n"
            "\t-u number of unidirectional streams to use, default 10\n"
            "\t-s data size to request, default 64\n"
            "\t-w request body size, default 64\n"
            "\t-V print version information and exit\n"
            "program creates server and client thread.\n"
            "client establishes `c` connections to server\n"
            "Each connection carries `b` `and `u` streams to request data\n"
            "from server. Initial size to download is `s` bytes. The second\n"
            "stream then carries `s` * 2, third `s` * 3, etc.\n"
            "Request body increases using the same pattern starting with\n"
            "`w` size.\n", progname);
    exit(EXIT_FAILURE);
}

/* Minimal QUIC HTTP/1.0 server. */
int
main(int argc, char *argv[])
{
    int res = EXIT_FAILURE;
    int ch;
    unsigned long port;
    thread_t srv_thrd;
    struct thread_arg_st targ = {
        server_thread,
        0
    };
    int ccount = 0;
    const char *ccountstr = "10";
    const char *bstreamstr = "10";
    const char *ustreamstr = "10";
    const char *rep_sizestr = "64";
    const char *req_sizestr = "64";

#ifdef _WIN32
    progname = argv[0];
#endif
    while ((ch = getopt(argc, argv, "p:c:b:u:s:w:tV")) != -1) {
        switch (ch) {
        case 'p':
            portstr = optarg;
            break;
        case 'c':
            ccountstr = optarg;
            break;
        case 'b':
            bstreamstr = optarg;
            break;
        case 'u':
            ustreamstr = optarg;
            break;
        case 's':
            rep_sizestr = optarg;
            break;
        case 'w':
            req_sizestr = optarg;
            break;
        case 't':
            terse = 1;
            break;
        case 'V':
            perflib_print_version(basename(argv[0]));
            return EXIT_SUCCESS;
        default:
            usage(argv[0]);
        }
    }

    if ((argv[optind] == NULL) || (argv[optind + 1] == NULL))
        usage(argv[0]);

    /* Create SSL_CTX that supports QUIC. */
    if ((server_ctx = create_srv_ctx(argv[optind], argv[optind + 1])) == NULL) {
        ERR_print_errors_fp(stderr);
        errx(res, "Failed to create context");
    }

    /* Parse port number from command line arguments. */
    port = strtoul(portstr, NULL, 0);
    if (port == 0 || port > UINT16_MAX)
        errx(res, "Failed to parse port number");
    targ.num = port;
    client_config.cc_portstr = portstr;

    client_config.cc_clients = strtoul(ccountstr, NULL, 0);
    if (client_config.cc_clients == 0 || client_config.cc_clients > 100)
        errx(res, "number of clients must be in [1, 100]");

    client_config.cc_bstreams = strtoul(bstreamstr, NULL, 0);
    if (client_config.cc_bstreams > 1000)
        errx(res, "number of bidi streams must be in <0, 1000>");

    client_config.cc_ustreams = strtoul(ustreamstr, NULL, 0);
    if (client_config.cc_ustreams > 1000)
        errx(res, "number of uni streams must be in <0, 1000>");

    client_config.cc_rep_sz = strtoul(rep_sizestr, NULL, 0);
    if (client_config.cc_rep_sz == 0 || client_config.cc_rep_sz > STREAM_SZ_CAP)
        errx(res, "data size to request outside of range <1, %u>",
             STREAM_SZ_CAP);

    client_config.cc_req_sz = strtoul(req_sizestr, NULL, 0);
    if (client_config.cc_rep_sz > STREAM_SZ_CAP)
        errx(res, "request payload  size is outside of range <0, %u>",
             STREAM_SZ_CAP);

    if (perflib_run_thread(&srv_thrd, &targ) != 0) {
        /* success do the client job */
        client_thread();
        stop_server = 1;
        perflib_wait_for_thread(srv_thrd);
        res = EXIT_SUCCESS;
    }

    SSL_CTX_free(server_ctx);
    server_ctx = NULL;

    return res;
}
