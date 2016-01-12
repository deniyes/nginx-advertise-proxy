
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ctype.h>


#define NGX_HTTP_CONNECT 0x0300


static ngx_int_t ngx_http_https_continue_init(ngx_conf_t *cf);
static void *ngx_http_https_continue_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_https_continue_merge_loc_conf(ngx_conf_t *cf, void *parent,
    void *child);

typedef struct {
    ngx_flag_t                   flag;
}ngx_http_https_continue_conf_t;

typedef struct {
    ngx_uint_t                   state;
} ngx_http_https_continue_ctx_t;

static ngx_command_t  ngx_http_https_continue_commands[] = {
    ngx_null_command
};

static ngx_http_module_t  ngx_http_https_continue_module_ctx = {
    NULL,                                                  /* preconfiguration */
    ngx_http_https_continue_init,                          /* postconfiguration */

    NULL,                                                  /* create main configuration */
    NULL,                                                  /* init main configuration */

    NULL,                                                  /* create server configuration */
    NULL,                                                  /* merge server configuration */

    ngx_http_https_continue_create_loc_conf,         /* create location configuration */
    ngx_http_https_continue_merge_loc_conf           /* merge location configuration */
};


ngx_module_t  ngx_http_https_continue_module = {
    NGX_MODULE_V1,
    &ngx_http_https_continue_module_ctx,                   /* module context */
    ngx_http_https_continue_commands,                      /* module directives */
    NGX_HTTP_MODULE,                                       /* module type */
    NULL,                                                  /* init master */
    NULL,                                                  /* init module */
    NULL,                                                  /* init process */
    NULL,                                                  /* init thread */
    NULL,                                                  /* exit thread */
    NULL,                                                  /* exit process */
    NULL,                                                  /* exit master */
    NGX_MODULE_V1_PADDING
};

static ngx_http_output_header_filter_pt  ngx_http_next_header_filter;
static ngx_http_output_body_filter_pt    ngx_http_next_body_filter;

static ngx_int_t
ngx_http_https_continue_parse_line(ngx_http_request_t *r)
{
    if (ngx_memcmp(r->request_start, "CONNECT ",  8) != 0) {
        return NGX_ERROR;
    }
    u_char *p = r->request_start + 8;

    if (!isalnum(*p)) {
        return NGX_ERROR;
    }
    r->host_start = p;
    while (*p) {
        if (*p == LF || *p == CR) {
            return NGX_ERROR;
        }
        if (*p == ':' || *p == ' ') {
            break;
        }
        p ++;
    }
    r->host_end = p;

    if (*p != ':') {
        return NGX_ERROR;
    }
    p += 1;
    r->port_start = p;
        
    while (*p) {
        if (*p == ' ') {
            break;
        }
        if (*p == LF || *p == CR || !isdigit(*p)) {
            return NGX_ERROR;
        }
        p ++;
    }
    r->port_end = p;
    p += 1;

    if (ngx_memcmp(p, "HTTP/", 5) != 0 && ngx_memcmp(p, "http/", 5) != 0) {
        return NGX_ERROR;
    }
    p += 5;
    if (*p < '0' || *p > '9') {
        return NGX_ERROR;
    }
    r->http_protocol.data = p;
    r->http_major = *p - '0';

    p ++;
    if (*p != '.') {
        return NGX_ERROR;
    }
    p ++;
    if (*p < '0' || *p > '9') {
        return NGX_ERROR;
    }
    r->http_minor = *p - '0';

    r->http_version = r->http_major * 1000 + r->http_minor;
    p ++;
    if (*p != CR && *p != LF) {
        return NGX_ERROR;
    }
    
    r->request_end = p;

    r->http_protocol.len = r->request_end - r->http_protocol.data;

    r->uri.len = 16; 
    r->uri.data = ngx_pnalloc(r->pool, 16);
    r->uri_start = r->uri.data; 
    r->uri_end = r->uri.data + 16;
    ngx_memcpy(r->uri.data, "/QuickbirdTunnel", 16);
    
    r->headers_in.server.len = r->host_end - r->host_start;
    r->headers_in.server.data = r->host_start;

    r->request_line.len = r->request_end - r->request_start;
    r->request_line.data = r->request_start;
    r->request_length = r->header_in->pos - r->request_start;

    r->unparsed_uri.len = r->uri_end - r->uri_start;
    r->unparsed_uri.data = r->uri_start;
    
    r->valid_unparsed_uri = r->space_in_uri ? 0 : 1;
    
    r->method_name.len = r->method_end - r->request_start + 1;
    r->method_name.data = r->request_line.data;

    r->header_in->pos = r->header_in->last;
    return NGX_OK;
}


static ngx_int_t
ngx_http_https_continue_header_filter(ngx_http_request_t *r)
{
    ngx_http_https_continue_conf_t   *conf;

    conf = ngx_http_get_module_loc_conf(r, ngx_http_https_continue_module);
    if (conf->flag == 0) {
        return ngx_http_next_header_filter(r);
    }
    if (r->method == NGX_HTTP_CONNECT) {
        if (r->headers_out.status == 200 \
            && r->err_status == 200) {
            return NGX_OK;
        } else {
            return ngx_http_next_header_filter(r);
        }
    }
    if (ngx_memcmp(r->request_start, "CONNECT ", 8)) {
        return ngx_http_next_header_filter(r);
    }
        
    if (ngx_http_https_continue_parse_line(r) != NGX_OK) {
        return ngx_http_next_header_filter(r);
    }
    ngx_http_core_srv_conf_t *cscf = \
        ngx_http_get_module_srv_conf(r, ngx_http_core_module);
    if (!r->connection->read->timer_set) {
        ngx_add_timer(r->connection->read, cscf->client_header_timeout);
    }
       
    r->method = NGX_HTTP_CONNECT;
    r->err_status = NGX_HTTP_OK;
    r->headers_out.status = NGX_HTTP_OK;
        
    return NGX_OK; 
}

static ngx_int_t
ngx_http_https_continue_body_filter(ngx_http_request_t *r, ngx_chain_t *in) 
{
    ngx_http_https_continue_ctx_t *ctx;
    
    if (r->method != NGX_HTTP_CONNECT) {
        return ngx_http_next_body_filter(r, in);
    }
    ctx = ngx_http_get_module_ctx(r, ngx_http_https_continue_module);
    if (ctx && ctx->state == 1) {
        return ngx_http_next_body_filter(r, in);
    }

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_https_continue_ctx_t));
    if (ctx == NULL) {
        return ngx_http_next_body_filter(r, in);
    }
    ngx_http_set_ctx(r, ctx, ngx_http_https_continue_module);
    ctx->state = 1;

    r->main->count ++;
    ngx_http_handler(r);
    return NGX_DONE;
}



static void *
ngx_http_https_continue_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_https_continue_conf_t  *clcf;

    clcf = ngx_pcalloc(cf->pool, sizeof(ngx_http_https_continue_conf_t));
    if (clcf == NULL) {
        return NULL;
    }
    clcf->flag = NGX_CONF_UNSET;
    return clcf;
}


static char *
ngx_http_https_continue_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_https_continue_conf_t  *prev = parent;
    ngx_http_https_continue_conf_t  *conf = child;

    ngx_conf_merge_value(conf->flag, prev->flag, 1);
    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_https_continue_init(ngx_conf_t *cf)
{
    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_https_continue_header_filter;

    ngx_http_next_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter = ngx_http_https_continue_body_filter;
    
    return NGX_OK;
}



