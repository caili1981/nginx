
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_CONNECTION_H_INCLUDED_
#define _NGX_CONNECTION_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


typedef struct ngx_listening_s  ngx_listening_t;

struct ngx_listening_s {
    ngx_socket_t        fd;

    struct sockaddr    *sockaddr;
    socklen_t           socklen;    /* size of sockaddr */
    size_t              addr_text_max_len;
    ngx_str_t           addr_text;

    int                 type;

    /* 
     * 配置 backlog=number
     * tcp backlog queue size 
     */
    int                 backlog;
    /* 
     * 配置 rcvbuf=size
     * tcp rcv/snd buffer size 
     */
    int                 rcvbuf;
    int                 sndbuf;
#if (NGX_HAVE_KEEPALIVE_TUNABLE)
    /*
     * 配置： so_keepalive=on|off|[keepidle]:[keepintvl]:[keepcnt]
     */
    int                 keepidle;
    int                 keepintvl;
    int                 keepcnt;
#endif

    /* handler of accepted connection */
    /*
     * - http   ngx_http_init_connection 
     * - mail   ngx_mail_init_connection
     * - stream ngx_stream_init_connection
     */
    ngx_connection_handler_pt   handler;

    void               *servers;  /* array of ngx_http_in_addr_t, for example */

    ngx_log_t           log;
    ngx_log_t          *logp;

    size_t              pool_size;
    /* should be here because of the AcceptEx() preread */
    size_t              post_accept_buffer_size;
    /* should be here because of the deferred accept */
    ngx_msec_t          post_accept_timeout;

    ngx_listening_t    *previous;
    ngx_connection_t   *connection;

    ngx_rbtree_t        rbtree;
    ngx_rbtree_node_t   sentinel;

    ngx_uint_t          worker;

    unsigned            open:1;
    unsigned            remain:1;
    unsigned            ignore:1;

    unsigned            bound:1;       /* already bound */
    unsigned            inherited:1;   /* inherited from previous process */
    unsigned            nonblocking_accept:1;
    unsigned            listen:1;
    unsigned            nonblocking:1;
    unsigned            shared:1;    /* shared between threads or processes */
    unsigned            addr_ntop:1;
    unsigned            wildcard:1;

#if (NGX_HAVE_INET6)
    unsigned            ipv6only:1;
#endif
    unsigned            reuseport:1;
    unsigned            add_reuseport:1;
    unsigned            keepalive:2;

    unsigned            deferred_accept:1;
    unsigned            delete_deferred:1;
    unsigned            add_deferred:1;
#if (NGX_HAVE_DEFERRED_ACCEPT && defined SO_ACCEPTFILTER)
    char               *accept_filter;
#endif
#if (NGX_HAVE_SETFIB)
    int                 setfib;
#endif

#if (NGX_HAVE_TCP_FASTOPEN)
    int                 fastopen;
#endif

};


typedef enum {
    NGX_ERROR_ALERT = 0,
    NGX_ERROR_ERR,
    NGX_ERROR_INFO,
    NGX_ERROR_IGNORE_ECONNRESET,
    NGX_ERROR_IGNORE_EINVAL
} ngx_connection_log_error_e;


typedef enum {
    NGX_TCP_NODELAY_UNSET = 0,
    NGX_TCP_NODELAY_SET,
    NGX_TCP_NODELAY_DISABLED
} ngx_connection_tcp_nodelay_e;


typedef enum {
    NGX_TCP_NOPUSH_UNSET = 0,
    NGX_TCP_NOPUSH_SET,
    NGX_TCP_NOPUSH_DISABLED
} ngx_connection_tcp_nopush_e;


#define NGX_LOWLEVEL_BUFFERED  0x0f
#define NGX_SSL_BUFFERED       0x01
#define NGX_HTTP_V2_BUFFERED   0x02

/*
 * 一个connection代表一个连接, 每个连接都有自己的read/write event.
 * 1. 普通连接, 一个connection就够.
 * 2. upstream, 和客户端一个连接，和upstream->peer一个连接.
 *    在upstream时，会创建一个新的连接(ngx_get_connection), 并将连接加入到event队列中.
 *    upstream如果有响应时（如：连接成功)，会调用此upstream的处理回调函数ngx_http_upstream_handler
 *    然后内部继续调用upstream的write_event_handler(ngx_http_upstream_send_request_handler)
 * 3. subrequest, 和客户端一个连接，和每个sub-upstream一个连接.
 * 4. 事件的恢复顺序(upstream举例).
 *        ngx_http_upstream_connect/ngx_event_connect_peer/ngx_get_connection 将读写事件加入到事件列表中.
 *        ngx_epoll_process_events  ===> 有可读或者可写的事件时
 *            rev/wev->handler(ngx_http_upstream_handler)
 *               ngx_http_upstream_handler
 *                 ev->data(request)->upstream->write_event_handler/read_event_handler
 */
struct ngx_connection_s {
    /*
       1.  ngx_cycle->free_connections 里用data作为next指针，连接一个free链表 
       2.  在建立好http连接之后data指向ngx_http_connection_t.
       3.  在wait request(ngx_http_create_request)之后，指向ngx_http_request_t
       4.  当有subrequest时，指向active的subrequest
     */
    void               *data;  

    /*
     * read/event event的handler在发现ngx_http_process_request之后，
     * 就变成了ngx_http_request_handler,
     * 例如在ngx_http_read_client_request_body 之后，如果发现recv无法获取信息，则
     * 将read event加入到监听队列中，它的handler就写ngx_http_request_handler,
     * 而ngx_http_request_handler会再次调用响应的read函数read_event_handler
     */
    ngx_event_t        *read;
    ngx_event_t        *write;

    ngx_socket_t        fd;

    /* 
     * 接收函数指针，不同的协议接收函数不一样 
     * 例如: ngx_unix_recv/ngx_ssl_recv/ngx_udp_recv等
     */
    ngx_recv_pt         recv;
    ngx_send_pt         send;
    /*
     * 发送和接收函数
     * 和recv/send的区别是，recv_chain底层调用readv进行多片读取，
     * 以减少系统调用次数
     */
    ngx_recv_chain_pt   recv_chain;
    ngx_send_chain_pt   send_chain;

    ngx_listening_t    *listening;

    /* 成功发送的数据, ngx_unix_send 函数在发送成功后会将sent更新 */
    off_t               sent;

    ngx_log_t          *log;

    /* pool size 默认为cscf->connection_pool_size */
    ngx_pool_t         *pool;

    /* socket 类型, SOCK_STREAM/SOCK_DGRAM */
    int                 type;

    /* peer addr, 包括 port 和 addr */
    struct sockaddr    *sockaddr;
    /* 16 字节 */
    socklen_t           socklen;
    /* 192.168.101.1 */
    ngx_str_t           addr_text;

    ngx_str_t           proxy_protocol_addr;
    in_port_t           proxy_protocol_port;

#if (NGX_SSL || NGX_COMPAT)
    /* ssl连接相关，例如SSL_ctx, 回调函数等. */
    ngx_ssl_connection_t  *ssl;
#endif

    ngx_udp_connection_t  *udp;

    /* 
     * 本地地址和端口，例如0.0.0.0和, 
     * 调用ngx_connection_local_sockaddr可以将本地地址输出成字符串
     */
    struct sockaddr    *local_sockaddr;
    socklen_t           local_socklen;

    /* 
     * ngx_connection_t在初始化时，会设置为 * client_header_buffer_size, 
     * 此结构用来存放整个 client request header (request-line header-line)
     * 因为一般的客户请求长度都小于此值, 
     * 所以一般情况下整个请求头都放在buffer里。
     */
    ngx_buf_t          *buffer;

    /*
     * 连接ngx_cycle->reusable_connections_queue
     */
    ngx_queue_t         queue;

    /* 
     * c->number: 实际上是一个seq_id, 
     * 每次新建连接时seq_id都会加1, log时，这个值会写在最前面 
     */
    ngx_atomic_uint_t   number;

    /* 
     * 使用keepalive模块时，peer connection会被复用, 
     * requests表示它被复用的次数
     */
    ngx_uint_t          requests;

    unsigned            buffered:8;

    unsigned            log_error:3;     /* ngx_connection_log_error_e */

    /* 所有连接的handler，都需要检查timedout */
    unsigned            timedout:1;
    unsigned            error:1;
    unsigned            destroyed:1;   /* 标志连接是否已经被销毁 */

    unsigned            idle:1;
    /* 连接是否可复用, 如果是可复用连接，则此连接会在reusable_connections_queue 里*/
    unsigned            reusable:1;
    /* 
     * 对于一个连接，处于reusable状态时，可以将close设置为1，以此来关闭连接
     * 因此此时的rev/wev->handler入口，需要检查close是否=1.
     */
    unsigned            close:1;
    /* 对同一个server的udp连接，连接是可以复用的 */
    unsigned            shared:1;   

    unsigned            sendfile:1;
    /* SO_SNDLOWAT */
    unsigned            sndlowat:1;
    /* TCP_NODELAY */
    unsigned            tcp_nodelay:2;   /* ngx_connection_tcp_nodelay_e */
    /* TCP_NOPUSH */
    unsigned            tcp_nopush:2;    /* ngx_connection_tcp_nopush_e */

    /* for HTTP2 */
    unsigned            need_last_buf:1;

#if (NGX_HAVE_AIO_SENDFILE || NGX_COMPAT)
    unsigned            busy_count:2;
#endif

#if (NGX_THREADS || NGX_COMPAT)
    ngx_thread_task_t  *sendfile_task;
#endif
};


#define ngx_set_connection_log(c, l)                                         \
                                                                             \
    c->log->file = l->file;                                                  \
    c->log->next = l->next;                                                  \
    c->log->writer = l->writer;                                              \
    c->log->wdata = l->wdata;                                                \
    if (!(c->log->log_level & NGX_LOG_DEBUG_CONNECTION)) {                   \
        c->log->log_level = l->log_level;                                    \
    }


ngx_listening_t *ngx_create_listening(ngx_conf_t *cf, struct sockaddr *sockaddr,
    socklen_t socklen);
ngx_int_t ngx_clone_listening(ngx_cycle_t *cycle, ngx_listening_t *ls);
ngx_int_t ngx_set_inherited_sockets(ngx_cycle_t *cycle);
ngx_int_t ngx_open_listening_sockets(ngx_cycle_t *cycle);
void ngx_configure_listening_sockets(ngx_cycle_t *cycle);
void ngx_close_listening_sockets(ngx_cycle_t *cycle);
void ngx_close_connection(ngx_connection_t *c);
void ngx_close_idle_connections(ngx_cycle_t *cycle);
ngx_int_t ngx_connection_local_sockaddr(ngx_connection_t *c, ngx_str_t *s,
    ngx_uint_t port);
ngx_int_t ngx_tcp_nodelay(ngx_connection_t *c);
ngx_int_t ngx_connection_error(ngx_connection_t *c, ngx_err_t err, char *text);

ngx_connection_t *ngx_get_connection(ngx_socket_t s, ngx_log_t *log);
void ngx_free_connection(ngx_connection_t *c);

void ngx_reusable_connection(ngx_connection_t *c, ngx_uint_t reusable);

#endif /* _NGX_CONNECTION_H_INCLUDED_ */
