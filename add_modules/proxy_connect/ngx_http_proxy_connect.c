
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#define NGX_HTTP_CONNECT             0x0300

typedef struct {
    ngx_http_upstream_conf_t       upstream;
    ngx_int_t                      index;
    ngx_hash_t                     ports;
    ngx_array_t                   *block_ports;
    ngx_array_t                   *proxy_lengths;
    ngx_array_t                   *proxy_values;
} ngx_http_proxy_connect_loc_conf_t;

typedef struct {
    ngx_http_request_t        *request;
    ngx_buf_t                 *client_hello;
} ngx_http_proxy_connect_ctx_t;


static ngx_int_t ngx_http_proxy_connect_create_request(ngx_http_request_t *r);
static ngx_int_t ngx_http_proxy_connect_reinit_request(ngx_http_request_t *r);
static ngx_int_t ngx_http_proxy_connect_process_header(ngx_http_request_t *r);
static void ngx_http_proxy_connect_abort_request(ngx_http_request_t *r);
static void ngx_http_proxy_connect_finalize_request(ngx_http_request_t *r,
    ngx_int_t rc);

static void *ngx_http_proxy_connect_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_proxy_connect_merge_loc_conf(ngx_conf_t *cf,
    void *parent, void *child);

static char *ngx_http_proxy_connect_pass(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);


static ngx_conf_bitmask_t  ngx_http_proxy_connect_next_upstream_masks[] = {
    { ngx_string("error"), NGX_HTTP_UPSTREAM_FT_ERROR },
    { ngx_string("timeout"), NGX_HTTP_UPSTREAM_FT_TIMEOUT },
    { ngx_string("invalid_response"), NGX_HTTP_UPSTREAM_FT_INVALID_HEADER },
    { ngx_string("not_found"), NGX_HTTP_UPSTREAM_FT_HTTP_404 },
    { ngx_string("off"), NGX_HTTP_UPSTREAM_FT_OFF },
    { ngx_null_string, 0 }
};

ngx_str_t  ngx_http_proxy_connect_block_ports[] = {
    ngx_string("25"),
    ngx_null_string
};


static ngx_command_t  ngx_http_proxy_connect_commands[] = {

    { ngx_string("connect_pass"),
      NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_TAKE1,
      ngx_http_proxy_connect_pass,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },
    
    { ngx_string("block_ports"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_http_types_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_connect_loc_conf_t, block_ports),
      &ngx_http_proxy_connect_block_ports[0] },

    { ngx_string("proxy_connect_bind"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_upstream_bind_set_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_connect_loc_conf_t, upstream.local),
      NULL },

    { ngx_string("proxy_connect_connect_timeout"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_connect_loc_conf_t, upstream.connect_timeout),
      NULL },

    { ngx_string("proxy_connect_send_timeout"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_connect_loc_conf_t, upstream.send_timeout),
      NULL },

    { ngx_string("proxy_connect_buffer_size"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_connect_loc_conf_t, upstream.buffer_size),
      NULL },

    { ngx_string("proxy_connect_read_timeout"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_connect_loc_conf_t, upstream.read_timeout),
      NULL },

    { ngx_string("proxy_connect_next_upstream"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_conf_set_bitmask_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_proxy_connect_loc_conf_t, upstream.next_upstream),
      &ngx_http_proxy_connect_next_upstream_masks },

      ngx_null_command
};




static ngx_http_module_t  ngx_http_proxy_connect_module_ctx = {
    NULL,                                  /* preconfiguration */
    NULL,                                  /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_proxy_connect_create_loc_conf,    /* create location configuration */
    ngx_http_proxy_connect_merge_loc_conf      /* merge location configuration */
};


ngx_module_t  ngx_http_proxy_connect_module = {
    NGX_MODULE_V1,
    &ngx_http_proxy_connect_module_ctx,        /* module context */
    ngx_http_proxy_connect_commands,           /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};

static ngx_str_t ngx_http_proxy_connect_success = ngx_string("HTTP/1.1 200 Connection established\r\n\r\n");
static ngx_buf_t ngx_http_proxy_connect_buf;
static ngx_chain_t  ngx_http_proxy_connect_chain = {&ngx_http_proxy_connect_buf, NULL};

static ngx_int_t
ngx_http_proxy_connect_eval(ngx_http_request_t *r, ngx_http_proxy_connect_ctx_t *ctx,
    ngx_http_proxy_connect_loc_conf_t *plcf)
{
    u_char               *p;
    ngx_url_t             url;
    ngx_http_upstream_t  *u;

    
    u = r->upstream;
    u->schema.data = (u_char*)"CONNECT";
    u->schema.len = sizeof("CONNECT") - 1;

    ngx_memzero(&url, sizeof(ngx_url_t));

    url.url.len = r->host_end - r->host_start + (r->port_start ? r->port_end - r->host_end : 0);
    url.url.data = r->host_start;
    url.default_port = 443;
    url.uri_part = 1;
    url.no_resolve = 1;

    if (ngx_parse_url(r->pool, &url) != NGX_OK) {
        if (url.err) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "%s in upstream \"%V\"", url.err, &url.url);
        }

        return NGX_ERROR;
    }

    if (url.uri.len) {
        if (url.uri.data[0] == '?') {
            p = ngx_pnalloc(r->pool, url.uri.len + 1);
            if (p == NULL) {
                return NGX_ERROR;
            }

            *p++ = '/';
            ngx_memcpy(p, url.uri.data, url.uri.len);

            url.uri.len++;
            url.uri.data = p - 1;
        }
    }

    u->resolved = ngx_pcalloc(r->pool, sizeof(ngx_http_upstream_resolved_t));
    if (u->resolved == NULL) {
        return NGX_ERROR;
    }

    if (url.addrs && url.addrs[0].sockaddr) {
        u->resolved->sockaddr = url.addrs[0].sockaddr;
        u->resolved->socklen = url.addrs[0].socklen;
        u->resolved->naddrs = 1;
        u->resolved->host = url.addrs[0].name;

    } else {
        u->resolved->host = url.host;
        u->resolved->port = (in_port_t) (url.no_port ? 443 : url.port);
        u->resolved->no_port = url.no_port;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_proxy_connect_upstream(ngx_http_request_t *r)
{
    ngx_http_upstream_t                     *u;
    ngx_http_proxy_connect_ctx_t            *ctx;
    ngx_http_proxy_connect_loc_conf_t       *mlcf;

    if (ngx_http_upstream_create(r) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    
    mlcf = ngx_http_get_module_loc_conf(r, ngx_http_proxy_connect_module);
    ctx = ngx_http_get_module_ctx(r,ngx_http_proxy_connect_module);
    if (ngx_http_proxy_connect_eval(r, ctx, mlcf) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    
    ctx->request = r;
    u = r->upstream;

    ngx_str_set(&u->schema, "proxy_connect://");
    u->output.tag = (ngx_buf_tag_t) &ngx_http_proxy_connect_module;

    mlcf = ngx_http_get_module_loc_conf(r, ngx_http_proxy_connect_module);

    u->conf = &mlcf->upstream;

    u->create_request = ngx_http_proxy_connect_create_request;
    u->reinit_request = ngx_http_proxy_connect_reinit_request;
    u->process_header = ngx_http_proxy_connect_process_header;
    u->abort_request = ngx_http_proxy_connect_abort_request;
    u->finalize_request = ngx_http_proxy_connect_finalize_request;

    u->input_filter_init = NULL;
    u->input_filter = NULL;
    u->input_filter_ctx = ctx;
    ngx_http_upstream_init(r);
    return NGX_DONE;
}


static void 
ngx_http_proxy_connect_read_hello_data(ngx_http_request_t *r)
{
    ngx_int_t                       n;
    ngx_buf_t                       *buf;
    ngx_connection_t                *c;
    ngx_http_core_srv_conf_t        *cscf;
    ngx_http_proxy_connect_ctx_t    *ctx;
    
    c = r->connection;
    
    ctx = ngx_http_get_module_ctx(r,ngx_http_proxy_connect_module);
    buf = ctx->client_hello;

    if (c->read->timedout) {
        c->timedout = 1;
        ngx_connection_error(c, NGX_ETIMEDOUT, "client timed out");
        ngx_http_finalize_request(r, NGX_HTTP_REQUEST_TIME_OUT);
        return;
    }
    
    if (c->read->ready) {
        n = c->recv(c, buf->start, 4096);
    } else {
        return;
    }
    if (n == NGX_AGAIN) {
        if (!c->read->timer_set) {
            cscf = ngx_http_get_module_srv_conf(r, ngx_http_core_module);
            ngx_add_timer(c->read, cscf->client_header_timeout);
        }
        if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
            ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }
        
        return;
    }

    if (n == 0) {
        ngx_log_error(NGX_LOG_INFO, c->log, 0,
                      "client prematurely closed connection");
    }
 
    if (n == 0 || n == NGX_ERROR) {
        c->error = 1;
        c->log->action = "reading https client hello data";

        ngx_http_finalize_request(r, NGX_HTTP_BAD_REQUEST);
        return;
    }
    if (c->read->timer_set) {
        ngx_del_timer(c->read);
    }

    buf->last = buf->pos + n;
    ngx_http_proxy_connect_upstream(r);
}

void *
ngx_http_proxy_connect_test_block_ports(ngx_http_request_t *r)
{
    size_t      len;
    ngx_uint_t  i, hash;
    ngx_hash_t *ports_hash = NULL;
    ngx_http_proxy_connect_loc_conf_t *conf;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_proxy_connect_module);
    ports_hash = &conf->ports;

    len = r->port_end - r->port_start;
    if (ports_hash->size == 0 || len == 0) {
        return NULL;
    }
    
    hash = 0;
    for (i = 0; i < len; i++) {
        hash = ngx_hash(hash, r->port_start[i]);
    }    

    return ngx_hash_find(ports_hash, hash, r->port_start, len);
}


ngx_int_t 
ngx_http_proxy_connect_handler(ngx_http_request_t *r)
{
    
    ngx_int_t                               rc;
    ngx_buf_t                               *b;
    ngx_http_proxy_connect_ctx_t            *ctx;
    if (!(r->method & (NGX_HTTP_CONNECT)) \
        || ngx_http_proxy_connect_test_block_ports(r)) 
    {
        return NGX_HTTP_NOT_ALLOWED;
    }
    ngx_http_proxy_connect_buf.pos = ngx_http_proxy_connect_success.data;
    ngx_http_proxy_connect_buf.last = ngx_http_proxy_connect_success.data \
                                        + ngx_http_proxy_connect_success.len;
    ngx_http_proxy_connect_buf.start = ngx_http_proxy_connect_success.data;
    ngx_http_proxy_connect_buf.end = ngx_http_proxy_connect_success.data \
                                        + ngx_http_proxy_connect_success.len;
    ngx_http_proxy_connect_buf.last_buf = 1;
    ngx_http_proxy_connect_buf.memory = 1;
    
    rc = ngx_http_output_filter(r, &ngx_http_proxy_connect_chain);
    if (rc != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    
    ngx_http_core_srv_conf_t *cscf = \
        ngx_http_get_module_srv_conf(r, ngx_http_core_module);
    if (!r->connection->read->timer_set) {
        cscf = ngx_http_get_module_srv_conf(r, ngx_http_core_module);
        ngx_add_timer(r->connection->read, cscf->client_header_timeout);
    }
    
    ctx = ngx_palloc(r->pool, sizeof(ngx_http_proxy_connect_ctx_t));
    if (ctx == NULL) {
        return NGX_ERROR;
    }
    ngx_http_set_ctx(r, ctx, ngx_http_proxy_connect_module);

    b = ngx_calloc_buf(r->pool);
    if (b == NULL) {
        return NGX_ERROR;
    }
    b->start = ngx_palloc(r->pool, 4096);
    if (b->start == NULL) {
        return NGX_ERROR;
    }
    b->end = b->start + 4096;
    b->pos = b->start;
    b->last = b->pos;
    b->last_buf = 1;
    b->memory = 1;

    ctx->client_hello = b;

    r->main->count ++;
    r->read_event_handler = ngx_http_proxy_connect_read_hello_data;
    ngx_http_proxy_connect_read_hello_data(r);
    return NGX_DONE;
}



static ngx_int_t
ngx_http_proxy_connect_create_request(ngx_http_request_t *r)
{
    ngx_chain_t                         *cl;
    ngx_http_proxy_connect_ctx_t        *ctx;

    ctx = ngx_http_get_module_ctx(r,ngx_http_proxy_connect_module);
    
    cl = ngx_alloc_chain_link(r->pool);
    if (cl == NULL) {
        return NGX_ERROR;
    }

    cl->buf = ctx->client_hello;
    cl->next = NULL;

    r->upstream->request_bufs = cl;

    return NGX_OK;
}


static ngx_int_t
ngx_http_proxy_connect_reinit_request(ngx_http_request_t *r)
{
    return NGX_OK;
}


static ngx_int_t
ngx_http_proxy_connect_process_header(ngx_http_request_t *r)
{
    ngx_http_upstream_t  *u = r->upstream;
    
    u->upgrade = 1;
    u->headers_in.status_n = NGX_HTTP_OK;
    u->headers_in.x_accel_redirect = NULL;
    u->headers_in.content_length_n = -1;
    u->headers_in.status_line.data = (u_char*)"200 OK";
    u->headers_in.status_line.len = sizeof("200 OK") - 1;
    return NGX_OK;
}


static void
ngx_http_proxy_connect_abort_request(ngx_http_request_t *r)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "abort http proxy_connect request");
    return;
}


static void
ngx_http_proxy_connect_finalize_request(ngx_http_request_t *r, ngx_int_t rc)
{
    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "finalize http proxy_connect request");
    return;
}


static void *
ngx_http_proxy_connect_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_proxy_connect_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_proxy_connect_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    /*
     * set by ngx_pcalloc():
     *
     *     conf->upstream.bufs.num = 0;
     *     conf->upstream.next_upstream = 0;
     *     conf->upstream.temp_path = NULL;
     *     conf->upstream.uri = { 0, NULL };
     *     conf->upstream.location = NULL;
     */

    conf->upstream.connect_timeout = NGX_CONF_UNSET_MSEC;
    conf->upstream.send_timeout = NGX_CONF_UNSET_MSEC;
    conf->upstream.read_timeout = NGX_CONF_UNSET_MSEC;

    conf->upstream.buffer_size = NGX_CONF_UNSET_SIZE;

    /* the hardcoded values */
    conf->upstream.cyclic_temp_file = 0;
    conf->upstream.buffering = 0;
    conf->upstream.ignore_client_abort = 0;
    conf->upstream.send_lowat = 0;
    conf->upstream.bufs.num = 0;
    conf->upstream.busy_buffers_size = 0;
    conf->upstream.max_temp_file_size = 0;
    conf->upstream.temp_file_write_size = 0;
    conf->upstream.intercept_errors = 1;
    conf->upstream.intercept_404 = 1;
    conf->upstream.pass_request_headers = 0;
    conf->upstream.pass_request_body = 0;

    conf->index = NGX_CONF_UNSET;

    return conf;
}


static char *
ngx_http_proxy_connect_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_proxy_connect_loc_conf_t *prev = parent;
    ngx_http_proxy_connect_loc_conf_t *conf = child;

    
    if (ngx_http_merge_types(cf, &conf->block_ports, &conf->ports,
                             &prev->block_ports, &prev->ports,
                             ngx_http_proxy_connect_block_ports)
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    ngx_conf_merge_msec_value(conf->upstream.connect_timeout,
                              prev->upstream.connect_timeout, 60000);

    ngx_conf_merge_msec_value(conf->upstream.send_timeout,
                              prev->upstream.send_timeout, 60000);

    ngx_conf_merge_msec_value(conf->upstream.read_timeout,
                              prev->upstream.read_timeout, 60000);

    ngx_conf_merge_size_value(conf->upstream.buffer_size,
                              prev->upstream.buffer_size,
                              (size_t) ngx_pagesize);

    ngx_conf_merge_bitmask_value(conf->upstream.next_upstream,
                              prev->upstream.next_upstream,
                              (NGX_CONF_BITMASK_SET
                               |NGX_HTTP_UPSTREAM_FT_ERROR
                               |NGX_HTTP_UPSTREAM_FT_TIMEOUT));

    if (conf->upstream.next_upstream & NGX_HTTP_UPSTREAM_FT_OFF) {
        conf->upstream.next_upstream = NGX_CONF_BITMASK_SET
                                       |NGX_HTTP_UPSTREAM_FT_OFF;
    }

    if (conf->upstream.upstream == NULL) {
        conf->upstream.upstream = prev->upstream.upstream;
    }

    if (conf->index == NGX_CONF_UNSET) {
        conf->index = prev->index;
    }

    return NGX_CONF_OK;
}


static char *
ngx_http_proxy_connect_pass(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
        ngx_http_proxy_connect_loc_conf_t *plcf = conf;
    
        ngx_str_t                  *value, *url;
        ngx_uint_t                  n;
        ngx_http_core_loc_conf_t   *clcf;
        ngx_http_script_compile_t   sc;
    
        if (plcf->upstream.upstream || plcf->proxy_lengths) {
            return "is duplicate";
        }
    
        clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    
        clcf->handler = ngx_http_proxy_connect_handler;
    
        value = cf->args->elts;
    
        url = &value[1];
    
        n = ngx_http_script_variables_count(url);
    
        if (n) {
    
            ngx_memzero(&sc, sizeof(ngx_http_script_compile_t));
    
            sc.cf = cf;
            sc.source = url;
            sc.lengths = &plcf->proxy_lengths;
            sc.values = &plcf->proxy_values;
            sc.variables = n;
            sc.complete_lengths = 1;
            sc.complete_values = 1;
    
            if (ngx_http_script_compile(&sc) != NGX_OK) {
                return NGX_CONF_ERROR;
            }   
        }
        return NGX_CONF_OK;
}
