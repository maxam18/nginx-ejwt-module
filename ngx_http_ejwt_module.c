/*
 * Copyright (C) 2014 Maxim Amzarakov
 *
 * Nginx Easy JWT module
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <nginx.h>

#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>

#define NGX_TNS_EJWT_VERSION            "0.0.4"

#define NGX_HTTP_EJWT_MD_LEN            256/8 /* HS256 only */

#define NGX_HTTP_EJWT_MODE_OFF          0x0000
#define NGX_HTTP_EJWT_MODE_PARSE        0x1000 
#define NGX_HTTP_EJWT_MODE_AUTH_HS256   0x0001
#define NGX_HTTP_EJWT_MODE_AUTH_HS384   0x0002
#define NGX_HTTP_EJWT_MODE_AUTH_HS512   0x0004
#define NGX_HTTP_EJWT_MODE_AUTH_HMAC    (0x01|0x02|0x04)
#define NGX_HTTP_EJWT_MODE_AUTH_RS256   0x0010
#define NGX_HTTP_EJWT_MODE_AUTH_PS256   0x0020
#define NGX_HTTP_EJWT_MODE_AUTH_PS384   0x0040
#define NGX_HTTP_EJWT_MODE_AUTH_PS512   0x0080
#define NGX_HTTP_EJWT_MODE_AUTH_RSA     (0x00F0)
#define NGX_HTTP_EJWT_MODE_AUTH_ES256   0x0100
#define NGX_HTTP_EJWT_MODE_AUTH_ES384   0x0200
#define NGX_HTTP_EJWT_MODE_AUTH_ES512   0x0400
#define NGX_HTTP_EJWT_MODE_AUTH_EC      (0x0F00)
#define NGX_HTTP_EJWT_MODE_AUTH_PUB     (0x0FF0)
#define NGX_HTTP_EJWT_MODE_AUTH_ALL     (0x0FFF)


/*
#define dd(...) fprintf( stderr, "JWT " __VA_ARGS__)
*/
#define dd(...)

/* Description
 Parameter tns_var on/off
    - set variable module on/off at location
 */

typedef struct {
    ngx_str_t                   token;
    ngx_str_t                   header;
    ngx_str_t                   payload;
    ngx_str_t                   signature;
    ngx_str_t                   var;
    ngx_str_t                   auth;
    ngx_uint_t                  exp;
    ngx_uint_t                  hash_code;
    ngx_uint_t                  alg;
} ngx_http_ejwt_ctx_t;

typedef struct {
    ngx_flag_t                  mode;
    ngx_int_t                   vindex;
    ngx_str_t                   claim;
    ngx_str_t                   var;
    ngx_str_t                   realm;
    HMAC_CTX                   *hmac_ctx;
    HMAC_CTX                   *hmac_ctx_old;
    RSA                        *rsa;
    RSA                        *rsa_old;
    ngx_http_complex_value_t   *auth;
} ngx_http_ejwt_conf_t;

typedef enum { 
    NGX_HTTP_EJWT_ERR_OK = 0, 
    NGX_HTTP_EJWT_ERR_INVALID, 
    NGX_HTTP_EJWT_ERR_EXPIRED, 
    NGX_HTTP_EJWT_ERR_FORBIDDEN 
} ngx_http_ejwt_err_t;


ngx_int_t ngx_http_ejwt_handler(ngx_http_request_t *r);

static ngx_int_t ngx_http_ejwt_init(ngx_conf_t *cf);

static ngx_int_t ngx_http_ejwt_add_variables(ngx_conf_t *cf);
static ngx_int_t ngx_http_ejwt_var_claim(ngx_http_request_t *r
        , ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_ejwt_var_auth(ngx_http_request_t *r
        , ngx_http_variable_value_t *v, uintptr_t data);

static void *ngx_http_ejwt_conf_create(ngx_conf_t *cf);
static char *ngx_http_ejwt_conf_merge(ngx_conf_t *cf
        , void *parent, void *child);
static char *ngx_http_ejwt_conf_set_mode(ngx_conf_t *cf, ngx_command_t *cmd
        , void *conf);
static char *ngx_http_ejwt_conf_set_key(ngx_conf_t *cf, ngx_command_t *cmd
        , void *conf);
static void *ngx_http_ejwt_conf_set_hmac_key(ngx_conf_t *cf
        , ngx_http_ejwt_conf_t *lcf, ngx_str_t *var, int alg);
static void *ngx_http_ejwt_conf_set_pub_key(ngx_conf_t *cf
        , ngx_http_ejwt_conf_t *lcf, ngx_str_t *var, int alg);
static char *ngx_http_ejwt_conf_set_auth(ngx_conf_t *cf, ngx_command_t *cmd
        , void *conf);

static ngx_int_t ngx_http_ejwt_auth_reply(ngx_http_request_t *r
        , ngx_str_t *realm, ngx_http_ejwt_err_t err);

static ngx_int_t ngx_http_ejwt_split_token(ngx_pool_t *pool
        , ngx_http_ejwt_ctx_t *ctx);
static ngx_int_t ngx_http_ejwt_parse_payload(ngx_http_ejwt_conf_t *conf
        , ngx_http_ejwt_ctx_t *ctx);
static ngx_int_t ngx_http_ejwt_parse_header(ngx_http_ejwt_conf_t *conf
        , ngx_http_ejwt_ctx_t *ctx);
static ngx_int_t ngx_http_ejwt_check_hmac(HMAC_CTX *main_ctx
        , ngx_http_ejwt_ctx_t *ctx);
static ngx_int_t ngx_http_ejwt_check_rsa(RSA *rsa
        , ngx_http_ejwt_ctx_t *ctx);

static ngx_str_t ngx_http_ejwt_var_claim_str = ngx_string("ejwt_claim");
static ngx_str_t ngx_http_ejwt_var_auth_str = ngx_string("ejwt_auth");

static ngx_conf_enum_t  ngx_http_ejwt_mode_set[] = {
    { ngx_string("off"),     NGX_HTTP_EJWT_MODE_OFF },
    { ngx_string("parse"),   NGX_HTTP_EJWT_MODE_PARSE },
    { ngx_string("hs256"),   NGX_HTTP_EJWT_MODE_AUTH_HS256 },
    { ngx_string("rs256"),   NGX_HTTP_EJWT_MODE_AUTH_RS256 },
    { ngx_string("hmac"),    NGX_HTTP_EJWT_MODE_AUTH_HMAC },
    { ngx_string("pub"),     NGX_HTTP_EJWT_MODE_AUTH_PUB },
    { ngx_string("all"),     NGX_HTTP_EJWT_MODE_AUTH_ALL },
    { ngx_null_string, 0 }
};


static ngx_command_t ngx_http_ejwt_commands[] = {
    {   ngx_string("easy_jwt"),
        NGX_HTTP_LOC_CONF|NGX_CONF_TAKE12,
        ngx_http_ejwt_conf_set_mode,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_ejwt_conf_t, mode),
        ngx_http_ejwt_mode_set },
    { ngx_string("easy_jwt_realm"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_ejwt_conf_t, realm),
        NULL },
    { ngx_string("easy_jwt_key"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE23,
        ngx_http_ejwt_conf_set_key,
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        NULL },
    { ngx_string("easy_jwt_claim"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_ejwt_conf_t, var),
        NULL },
    { ngx_string("easy_jwt_auth"),
        NGX_HTTP_LOC_CONF|NGX_CONF_TAKE2,
        ngx_http_ejwt_conf_set_auth,
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        NULL },
    
    ngx_null_command
};


static ngx_http_module_t ngx_http_ejwt_ctx = {
    ngx_http_ejwt_add_variables,            /* preconfiguration */
    ngx_http_ejwt_init,                     /* postconfiguration */
    NULL,                                   /* create main configuration */
    NULL,                                   /* init main configuration */
    NULL,                                   /* create server configuration */
    NULL,                                   /* merge server configuration */
    ngx_http_ejwt_conf_create,              /* create location configration */
    ngx_http_ejwt_conf_merge                /* merge location configration */
};


ngx_module_t ngx_http_ejwt_module = {
    NGX_MODULE_V1,
    &ngx_http_ejwt_ctx,                     /* module context */
    ngx_http_ejwt_commands,                 /* module directives */
    NGX_HTTP_MODULE,                        /* module type */
    NULL,                                   /* init master */
    NULL,                                   /* init module */
    NULL,                                   /* init process */
    NULL,                                   /* init thread */
    NULL,                                   /* exit thread */
    NULL,                                   /* exit process */
    NULL,                                   /* exit master */
    NGX_MODULE_V1_PADDING
};


ngx_int_t ngx_http_ejwt_handler(ngx_http_request_t *r)
{
    ngx_http_variable_value_t   *value;
    ngx_http_ejwt_conf_t        *lcf;
    ngx_http_ejwt_ctx_t         *ctx;
    ngx_str_t                    token, str;
    int                          err;

    lcf = ngx_http_get_module_loc_conf(r, ngx_http_ejwt_module);
    if( lcf->mode == NGX_HTTP_EJWT_MODE_OFF 
            || r->method == NGX_HTTP_OPTIONS )
        return NGX_DECLINED;

    token.len = 0;
    if( r->headers_in.authorization != NULL )
    {
        token = r->headers_in.authorization->value;

        if( token.len > sizeof("Bearer ") && 
                ngx_strncmp(token.data+1, "earer ", sizeof("earer ") -1) 
            == 0 )
        {
            token.len  -= sizeof("Bearer ") - 1;
            token.data += sizeof("Bearer ") - 1;
        } else {
            token.len = 0;
        }
    } else if( lcf->vindex != NGX_CONF_UNSET )
    {
        value =  ngx_http_get_indexed_variable(r, lcf->vindex);
        if( value == NULL )
            return NGX_ERROR;

        token.data = value->data;
        token.len  = value->len;
    } 
    
    if( token.len == 0 ) {
        return ngx_http_ejwt_auth_reply(r, &lcf->realm, 0);
    }

    ctx = ngx_pcalloc(r->pool, sizeof(*ctx));
    if( ctx == NULL )
        return NGX_HTTP_INTERNAL_SERVER_ERROR;

    dd("Token: '%.*s'\n", (int)token.len, token.data);

    ctx->token = token;
    if( ngx_http_ejwt_split_token(r->pool, ctx) != NGX_OK ) {
        ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0
                , "Cannot decode token");
        return NGX_HTTP_BAD_REQUEST;
    }

    dd("Token decoded.\n"
        "  token:   '%.*s'\n"
        "  header:  '%.*s'\n"
        "  payload: '%.*s'\n"
        "  signlen   %zu\n"
        "  expired   %lu\n"
        , (int)ctx->token.len, ctx->token.data
        , (int)ctx->header.len, ctx->header.data
        , (int)ctx->payload.len, ctx->payload.data
        , ctx->signature.len, ctx->exp);

    if( ngx_http_ejwt_parse_payload(lcf, ctx) != NGX_OK ) {
        ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0
                , "Cannot parse token payload");
        return NGX_HTTP_BAD_REQUEST;
    }

    ngx_http_set_ctx(r, ctx, ngx_http_ejwt_module);

    if( lcf->mode == NGX_HTTP_EJWT_MODE_PARSE )
        return NGX_OK;

    if( ctx->exp && (time_t)ctx->exp < ngx_time() )
        return ngx_http_ejwt_auth_reply(r, &lcf->realm
                , NGX_HTTP_EJWT_ERR_EXPIRED);
    
    if( !ctx->signature.len ) {
        return ngx_http_ejwt_auth_reply(r, &lcf->realm
                , NGX_HTTP_EJWT_ERR_INVALID);
    }

    if( lcf->mode == NGX_HTTP_EJWT_MODE_AUTH_ALL 
            && (lcf->hmac_ctx && lcf->rsa) )
    {
        if( ngx_http_ejwt_parse_header(lcf, ctx) != NGX_OK ) {
            ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0
                    , "Cannot parse alg from token '%V'", ctx->token);
            return NGX_HTTP_BAD_REQUEST;
        }
    } else 
        ctx->alg = lcf->mode;

    if( ctx->alg & NGX_HTTP_EJWT_MODE_AUTH_HMAC )
    {
        err = ngx_http_ejwt_check_hmac(lcf->hmac_ctx, ctx);
        if( err != NGX_OK && lcf->hmac_ctx_old != NGX_CONF_UNSET_PTR )
        {
            err = ngx_http_ejwt_check_hmac(lcf->hmac_ctx_old, ctx);
        }

    } else if( ctx->alg & NGX_HTTP_EJWT_MODE_AUTH_PUB )
    {
        err = ngx_http_ejwt_check_rsa(lcf->rsa, ctx);
        if( err != NGX_OK && lcf->rsa_old != NGX_CONF_UNSET_PTR )
        {
            err = ngx_http_ejwt_check_rsa(lcf->rsa_old, ctx);
        }
    } else
        err = NGX_ERROR;
    
    if( err != NGX_OK )
        return ngx_http_ejwt_auth_reply(r, &lcf->realm
                , NGX_HTTP_EJWT_ERR_INVALID);

    if( lcf->auth != NGX_CONF_UNSET_PTR )
    {
        if( ctx->auth.len == 0 ) 
            return NGX_HTTP_FORBIDDEN;
        
        if( ngx_http_complex_value(r, lcf->auth, &str) != NGX_OK )
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        
        if( !(ctx->auth.len == str.len 
                && ngx_strncmp(ctx->auth.data, str.data, str.len) == 0) )
            return NGX_HTTP_FORBIDDEN;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_ejwt_split_token(ngx_pool_t *pool, ngx_http_ejwt_ctx_t *ctx)
{
    size_t       len;
    int          i;
    u_char      *p, *buf;
    ngx_str_t    part[3] = {{0,0}, {0,0}, {0,0}}, enc;

    p   = part[0].data = ctx->token.data;
    len = ctx->token.len;
    i   = 0;
    while( len-- )
        if( *p++ == '.' )
        {
            part[i].len = p - part[i].data - 1;
            if( ++i == 3 )
                return NGX_ERROR;

            part[i].data = p;
        }
    part[i].len = p - part[i].data;

    if( part[2].len ) {
        ctx->token.len -= part[2].len + 1;
    }

    buf = ngx_palloc(pool, ctx->token.len);
    if( !buf )
        return NGX_ERROR;

    while( i >= 0 )
    {
        enc = part[i];
        part[i].data = buf;

        if( ngx_decode_base64url(&part[i], &enc) != NGX_OK )
            return NGX_ERROR;

        buf += part[i--].len;
    }

    ctx->header    = part[0];
    ctx->payload   = part[1];
    ctx->signature = part[2];

    return NGX_OK;
}


static ngx_int_t
ngx_http_ejwt_parse_payload(ngx_http_ejwt_conf_t *conf, ngx_http_ejwt_ctx_t *ctx)
{
    u_char     *p, *e, *v, *k, ch;
    u_int32_t   vlen, klen, nval, dig;
    static enum { LS_BEGIN, LS_LVL, LS_TVAL, LS_NVAL, LS_KEYST, LS_KEY } lstate;

    lstate = LS_BEGIN;

    dig = vlen = klen = nval = 0;
    v = e = k = 0;

    if( conf->var.len && conf->var.data[0] == '*' ) {
            ctx->var = ctx->payload;
    }

    p = ctx->payload.data + ctx->payload.len;
    while( p > ctx->payload.data )  
    {
        ch = *p--;
        switch( lstate )
        {
            case LS_BEGIN:
                if( ch == '}' )
                    lstate = LS_LVL;
            break;
            case LS_LVL:
                if( ch == '"' ) {
                    lstate = LS_TVAL;
                    e = p;
                    dig = 0;
                } else if( ch >= 0x30 && ch <= 0x39 ) {
                    lstate = LS_NVAL;
                    e = p;
                    nval = (ch - '0');
                    dig = 10;
                }
            break;
            case LS_TVAL:
                if( ch == '"' && *p != '\\' ) {
                    v      = p + 2;
                    vlen   = e - p - 1;
                    lstate = LS_KEYST;
                }
            break;
            case LS_NVAL:
                if( ch >= 0x30 && ch <= 0x39 ) {
                    nval += (ch - '0') * dig;
                    dig *= 10;
                } else {
                    v      = p + 2;
                    vlen   = e - p - 1;
                    lstate = LS_KEYST;
                }
            break;
            case LS_KEYST:
                if( ch == '"' ) {
                    e = p;
                    lstate = LS_KEY;
                }
            break;
            case LS_KEY:
                if( ch == '"' && *p != '\\' ) {
                    k      = p + 2;
                    klen   = e - p - 1;
                    lstate = LS_LVL;

                    if( !ctx->exp && dig && klen == 3 ) {
                        if( k[0] == 'e' && k[1] == 'x' && k[2] == 'p' )
                            ctx->exp = nval;
                    }

                    if( !ctx->var.len && conf->var.len == klen ) {
                        if( !ngx_strncmp(conf->var.data, k, klen) ) {
                            ctx->var.len  = vlen;
                            ctx->var.data = v;
                        }
                    }

                    if( !ctx->auth.len && conf->claim.len == klen ) {
                        if( !ngx_strncmp(conf->claim.data, k, klen) ) {
                            ctx->auth.len  = vlen;
                            ctx->auth.data = v;
                        }
                    }

                    if( ctx->exp && ctx->var.len && ctx->auth.len  )
                        p = ctx->payload.data;
                }
            break;
        }
    }
    
    if( lstate != LS_LVL ) 
        return NGX_ERROR;


    return NGX_OK;
}


static ngx_int_t
ngx_http_ejwt_parse_header(ngx_http_ejwt_conf_t *conf, ngx_http_ejwt_ctx_t *ctx)
{
    u_char     *p, *e, *v, *k, ch;
    u_int32_t   vlen, klen;
    static enum { LS_BEGIN, LS_LVL, LS_VAL, LS_KEYST, LS_KEY } lstate;

    lstate = LS_BEGIN;

    vlen = klen = 0;
    v = e = k = 0;

    ctx->alg = NGX_HTTP_EJWT_MODE_OFF;

    p = ctx->header.data + ctx->header.len;
    while( p > ctx->header.data )  
    {
        ch = *p--;
        switch( lstate )
        {
            case LS_BEGIN:
                if( ch == '}' )
                    lstate = LS_LVL;
            break;
            case LS_LVL:
                if( ch == '"' ) {
                    lstate = LS_VAL;
                    e = p;
                }
            break;
            case LS_VAL:
                if( ch == '"' && *p != '\\' ) {
                    v      = p + 2;
                    vlen   = e - p - 1;
                    lstate = LS_KEYST;
                }
            break;
            case LS_KEYST:
                if( ch == '"' ) {
                    e = p;
                    lstate = LS_KEY;
                }
            break;
            case LS_KEY:
                if( ch == '"' && *p != '\\' ) {
                    lstate = LS_LVL;
                    klen   = e - p - 1;

                    if( klen != 3 && vlen != 5 )
                        break;

                    k = p + 2;
                    if( k[0] == 'a' && k[1] == 'l' && k[2] == 'g' )
                    {
                        if( (v[1] == 's' || v[1] == 'S') 
                                && v[2] == '2' && v[3] == '5' && v[4] == '6' )
                        {
                            if( *v == 'h' || *v == 'H' )
                                ctx->alg = NGX_HTTP_EJWT_MODE_AUTH_HS256;
                            else if( *v == 'r' || *v == 'R' )
                                ctx->alg = NGX_HTTP_EJWT_MODE_AUTH_RS256;
                        }
                        p = ctx->header.data;
                    }
                }
            break;
        }
    }

    if( lstate != LS_LVL ) 
        return NGX_ERROR;

    return NGX_OK;
}


static ngx_int_t
ngx_http_ejwt_check_hmac(HMAC_CTX *main_ctx, ngx_http_ejwt_ctx_t *ctx)
{
    HMAC_CTX    *hs_ctx;
    u_char       md[NGX_HTTP_EJWT_MD_LEN];

/* mem of HMAC_CTX size is unknown cannot allocate from the pool */
    hs_ctx = HMAC_CTX_new();
    if( !hs_ctx )
        return NGX_ERROR;

    if( !HMAC_CTX_copy(hs_ctx, main_ctx) )
        goto hmac_fail;

    if( !HMAC_Init_ex(hs_ctx, NULL, 0, NULL, NULL) )
        return NGX_ERROR;
    
    if( !HMAC_Update(hs_ctx, ctx->token.data, ctx->token.len) )
        return NGX_ERROR;

    if( !HMAC_Final(hs_ctx, md, NULL) )
        return NGX_ERROR;

    HMAC_CTX_free(hs_ctx);

    return ngx_memcmp(ctx->signature.data, md, NGX_HTTP_EJWT_MD_LEN) == 0 ?
            NGX_OK : NGX_ERROR;

hmac_fail:
    HMAC_CTX_free(hs_ctx);
    return NGX_ERROR;
}


static ngx_int_t
ngx_http_ejwt_check_rsa(RSA *rsa, ngx_http_ejwt_ctx_t *ctx)
{
    int          err;
    u_char       hash[256/8 + 1];

    SHA256(ctx->token.data, ctx->token.len, hash);

    err = RSA_verify(NID_sha256, hash, 32
            , ctx->signature.data, ctx->signature.len, rsa);

    return err == 1 ? NGX_OK : NGX_ERROR;
}


static ngx_int_t
ngx_http_ejwt_auth_reply(ngx_http_request_t *r, ngx_str_t *realm, ngx_http_ejwt_err_t err)
{
    size_t              len;
    u_char             *val, *p;
    static ngx_str_t    errors[] = {
        ngx_string(""),
        ngx_string("invalid signature"),
        ngx_string("token expired"),
        ngx_string("access forbidden")
    };

    if( realm->len == NGX_CONF_UNSET_SIZE )
        return NGX_HTTP_UNAUTHORIZED;

    r->headers_out.www_authenticate = ngx_list_push(&r->headers_out.headers);
    if( r->headers_out.www_authenticate == NULL ) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    len = sizeof("Bearer") - 1;

    if( realm->len ) {
        len += sizeof(" realm=\"\"") - 1 + realm->len;
    }

    if( err ) {
        len += sizeof(" error=\"invalid_token\", error_description=\"\"") - 1 
                + errors[err].len;
        if( realm->len )
            len += sizeof(",") - 1;
    }

    val = ngx_pcalloc(r->pool, len);
    if( val == NULL ) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    p = ngx_cpymem(val, "Bearer", sizeof("Bearer") - 1);

    if( realm->len ) {
        p  = ngx_cpymem(p, " realm=\"", sizeof(" realm=\"") - 1);
        p  = ngx_cpymem(p, realm->data, realm->len);
    }

    if( err ) {
        if( realm->len ) {
            *p++ = '"';
            *p++ = ',';
        }
        p = ngx_cpymem(p, " error=\"invalid_token\", error_description=\"", 
                sizeof(" error=\"invalid_token\", error_description=\"") - 1);
        p = ngx_cpymem(p, errors[err].data, errors[err].len);
    }
    *p = '"';

    r->headers_out.www_authenticate->hash = 1;
    ngx_str_set(&r->headers_out.www_authenticate->key, "WWW-Authenticate");
    r->headers_out.www_authenticate->value.data = val;
    r->headers_out.www_authenticate->value.len  = len;

    return NGX_HTTP_UNAUTHORIZED;
}


static ngx_int_t
ngx_http_ejwt_var_claim(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_ejwt_ctx_t     *ctx;

    v->not_found = 1;

    ctx = ngx_http_get_module_ctx(r, ngx_http_ejwt_module);

    if( ctx == NULL )
        return NGX_OK;

    if( ctx->var.len == 0 )
         return NGX_OK;

    v->len = ctx->var.len;

    v->data = ngx_palloc(r->pool, v->len);
    if( v->data == NULL )
        return NGX_ERROR;

    ngx_memcpy(v->data, ctx->var.data, ctx->var.len);

    v->valid        = 1;
    v->no_cacheable = 0;
    v->not_found    = 0;

    return NGX_OK;
}


static ngx_int_t
ngx_http_ejwt_var_auth(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_ejwt_ctx_t     *ctx;

    v->not_found = 1;

    ctx = ngx_http_get_module_ctx(r, ngx_http_ejwt_module);

    if( ctx == NULL )
        return NGX_OK;

    if( ctx->auth.len == 0 )
         return NGX_OK;

    v->len = ctx->auth.len;

    v->data = ngx_palloc(r->pool, v->len);
    if( v->data == NULL )
        return NGX_ERROR;

    ngx_memcpy(v->data, ctx->auth.data, ctx->auth.len);

    v->valid        = 1;
    v->no_cacheable = 0;
    v->not_found    = 0;

    return NGX_OK;
}


static ngx_int_t
ngx_http_ejwt_add_variables(ngx_conf_t *cf)
{
    ngx_http_variable_t     *var;

    var = ngx_http_add_variable(cf, &ngx_http_ejwt_var_claim_str
                                  , NGX_HTTP_VAR_NOHASH);
    if (var == NULL)
         return NGX_ERROR;
    var->get_handler = ngx_http_ejwt_var_claim;

    var = ngx_http_add_variable(cf, &ngx_http_ejwt_var_auth_str
                                  , NGX_HTTP_VAR_NOHASH);
    if (var == NULL)
         return NGX_ERROR;
    var->get_handler = ngx_http_ejwt_var_auth;

    return NGX_OK;
}


static ngx_int_t 
ngx_http_ejwt_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt         *hpt;
    ngx_http_core_main_conf_t   *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    hpt = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);

    if( hpt == NULL )
        return NGX_ERROR;

    *hpt = ngx_http_ejwt_handler;

    return NGX_OK;
}


static char *
ngx_http_ejwt_conf_set_mode(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t                          *arg;
    ngx_http_ejwt_conf_t               *lcf;
    ngx_conf_enum_t                    *e;
    
    arg = cf->args->elts;
    lcf = conf;

    lcf->mode = NGX_CONF_UNSET;

    arg++;
    e = ngx_http_ejwt_mode_set;
    for(; e->name.len; e++ )
        if( arg->len == e->name.len 
            && ngx_strncasecmp(arg->data,  e->name.data, arg->len ) == 0 )
        {
            lcf->mode = e->value;
            break;
        }

    if( lcf->mode == NGX_CONF_UNSET )
        return "Invalid mode";
    

    if( cf->args->nelts < 3 )
        return NGX_CONF_OK;
    
    arg++;
    if( *arg->data == '$' )
    {
        arg->data++;
        arg->len--;
    }

    lcf->vindex = ngx_http_get_variable_index(cf, arg);
    if( lcf->vindex == NGX_ERROR )
        return "Unknown variable name";

    return NGX_CONF_OK;
}


static char *
ngx_http_ejwt_conf_set_key(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t                          *values;
    ngx_http_ejwt_conf_t               *lcf;

    values = cf->args->elts;
    lcf    = conf;

    if( values[1].len != 5 )
        return "Invalid signature algorithm name";

    if( ngx_strncasecmp(values[1].data, (u_char *)"hs256", 5) == 0 )
    {
        if( !(lcf->hmac_ctx = 
                    ngx_http_ejwt_conf_set_hmac_key(cf, lcf, &values[2]
                            , NGX_HTTP_EJWT_MODE_AUTH_HS256))  ) {
            return "Invalid key";
        }

        if( cf->args->nelts > 3 )
        {
            if( !(lcf->hmac_ctx_old = 
                        ngx_http_ejwt_conf_set_hmac_key(cf, lcf, &values[3]
                                , NGX_HTTP_EJWT_MODE_AUTH_HS256)) ) {
                return "Invalid old key";
            }
        }
    } else if( ngx_strncasecmp(values[1].data, (u_char *)"rs256", 5) == 0 )
    {
        if( !(lcf->rsa = 
                ngx_http_ejwt_conf_set_pub_key(cf, lcf, &values[2]
                        , NGX_HTTP_EJWT_MODE_AUTH_RS256)) ) {
            return "Invalid key";
        }

        if( cf->args->nelts > 3 )
        {
            if( !(lcf->rsa_old = 
                        ngx_http_ejwt_conf_set_pub_key(cf, lcf, &values[3]
                                , NGX_HTTP_EJWT_MODE_AUTH_RS256)) ) {
                return "Invalid old key";
            }
        }
    } else
        return "HS256 and RS256 only supported";

    return NGX_CONF_OK;
}


static void *
ngx_http_ejwt_conf_set_hmac_key(ngx_conf_t *cf, ngx_http_ejwt_conf_t *lcf, ngx_str_t *var, int alg)
{
    HMAC_CTX        *hmac_ctx;
    const EVP_MD    *evp_md;

    evp_md = EVP_sha256();

    if( !(hmac_ctx = HMAC_CTX_new()) )
        return NULL;

    if( HMAC_Init_ex(hmac_ctx, var->data, var->len, evp_md, 0) == 0 )
        return NULL;

    return hmac_ctx;
}

static void *
ngx_http_ejwt_conf_set_pub_key(ngx_conf_t *cf, ngx_http_ejwt_conf_t *lcf, ngx_str_t *var, int alg)
{
    RSA    *rsa;
    FILE   *fp;

    rsa = RSA_new();
    if( !rsa )
        return NULL;

    if( ngx_conf_full_name(cf->cycle, var, 1) != NGX_OK )
        return NULL;

    fp = fopen((char *)var->data, "r");
    if( !fp ) {
        perror((char *)var->data);
        return NULL;
    }

    rsa = PEM_read_RSA_PUBKEY(fp, &rsa, NULL, NULL);

    fclose(fp);

    return rsa;
}


static char *
ngx_http_ejwt_conf_set_auth(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_compile_complex_value_t   ccv;
    ngx_http_ejwt_conf_t              *lcf;
    ngx_str_t                         *var;

    var = cf->args->elts;
    lcf = conf;

    var++;
    lcf->claim = *var;

    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

    var++;
    ccv.cf = cf;
    ccv.value = var;
    ccv.complex_value = ngx_pcalloc(cf->pool, sizeof(*ccv.complex_value));
    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
        return NGX_CONF_ERROR;
    }

    lcf->auth = ccv.complex_value;

    return NGX_CONF_OK;
}


static char *
ngx_http_ejwt_conf_merge(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_ejwt_conf_t *prev = parent;
    ngx_http_ejwt_conf_t *conf = child;

    ngx_conf_merge_value(conf->mode, prev->mode, NGX_HTTP_EJWT_MODE_OFF);
    ngx_conf_merge_value(conf->vindex, prev->vindex, NGX_CONF_UNSET);
    ngx_conf_merge_str_value(conf->claim, prev->claim, "");
    ngx_conf_merge_str_value(conf->var, prev->var, "");
    ngx_conf_merge_ptr_value(conf->auth, prev->auth
            , NGX_CONF_UNSET_PTR);
    ngx_conf_merge_ptr_value(conf->hmac_ctx, prev->hmac_ctx
            , NGX_CONF_UNSET_PTR);
    ngx_conf_merge_ptr_value(conf->hmac_ctx_old, prev->hmac_ctx_old
            , NGX_CONF_UNSET_PTR);
    ngx_conf_merge_ptr_value(conf->rsa, prev->rsa
            , NGX_CONF_UNSET_PTR);
    ngx_conf_merge_ptr_value(conf->rsa_old, prev->rsa_old
            , NGX_CONF_UNSET_PTR);

    if( conf->realm.data == NULL )
    {
        if( prev->realm.data )
            conf->realm = prev->realm;
        else 
            conf->realm.len = NGX_CONF_UNSET_SIZE;
    }

    if( conf->mode & NGX_HTTP_EJWT_MODE_AUTH_HMAC 
            && conf->hmac_ctx == NGX_CONF_UNSET_PTR )
        return "Hash code is not set";

    if( conf->mode & NGX_HTTP_EJWT_MODE_AUTH_PUB 
            && conf->rsa == NGX_CONF_UNSET_PTR )
        return "RSA public key is not set";
        
    return NGX_CONF_OK;
}


static void *ngx_http_ejwt_conf_create(ngx_conf_t *cf)
{
    ngx_http_ejwt_conf_t *conf;

    if( (conf = ngx_pcalloc(cf->pool, sizeof(*conf))) == NULL )
        return NGX_CONF_ERROR;

    conf->mode          = NGX_CONF_UNSET;
    conf->vindex        = NGX_CONF_UNSET;
    conf->auth          = NGX_CONF_UNSET_PTR;
    conf->hmac_ctx      = NGX_CONF_UNSET_PTR;
    conf->hmac_ctx_old  = NGX_CONF_UNSET_PTR;
    conf->rsa           = NGX_CONF_UNSET_PTR;
    conf->rsa_old       = NGX_CONF_UNSET_PTR;

    return conf;
}
