/*
 * ngx_http_find_cache_module.c
 *
 *  Created on: Jan 2, 2014
 *      Author: root
 */
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_md5.h>
#include <ngx_crc32.h>
#include <ngx_palloc.h>

typedef struct {
	ngx_int_t find_cache;

} ngx_http_find_cache_loc_conf_t;

static ngx_int_t ngx_http_find_cache_init(ngx_conf_t *cf);

static void *ngx_http_find_cache_create_loc_conf(ngx_conf_t *cf);

static char *ngx_http_find_cache(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static ngx_command_t ngx_http_find_cache_commands[] = { {
//定义配置指令的名称
		ngx_string("find_cache"),
		//NGX_HTTP_LOC_CONF(范围location) NGX_CONF_FLAG(配置指令可以接受的值是”on”或者”off”，最终会被转成bool值)
		NGX_HTTP_LOC_CONF | NGX_CONF_FLAG, ngx_http_find_cache,
		//存入loc_conf
		NGX_HTTP_LOC_CONF_OFFSET,
		//offsetof(指定该配置项值的精确存放位置，一般指定为某一个结构体变量的字段偏移)
		offsetof(ngx_http_find_cache_loc_conf_t, find_cache), NULL },
		ngx_null_command };

//一般情况下，我们自定义的模块，大多数是挂载在NGX_HTTP_CONTENT_PHASE阶段的。挂载的动作一般是在模块上下文调用的postconfiguration函数中。
static ngx_http_module_t ngx_http_find_cache_module_ctx = { NULL, /* preconfiguration */
ngx_http_find_cache_init, /* postconfiguration (在创建和读取该模块的配置信息之后被调用)*/

NULL, /* create main configuration */
NULL, /* init main configuration */

NULL, /* create server configuration */
NULL, /* merge server configuration */

ngx_http_find_cache_create_loc_conf, /* create location configuration */
NULL /* merge location configuration */
};

ngx_module_t ngx_http_find_cache_module = { NGX_MODULE_V1,
		&ngx_http_find_cache_module_ctx, /* module context */
		ngx_http_find_cache_commands, /* module directives */
		NGX_HTTP_MODULE, /* module type */
		NULL, /* init master */
		NULL, /* init module */
		NULL, /* init process */
		NULL, /* init thread */
		NULL, /* exit thread */
		NULL, /* exit process */
		NULL, /* exit master */
		NGX_MODULE_V1_PADDING };

typedef struct {
	ngx_str_t key_start;
	ngx_str_t schema;
	ngx_str_t host_header;
	ngx_str_t port;
	ngx_str_t uri;
} ngx_http_proxy_vars_t;

typedef struct {
	ngx_http_upstream_conf_t upstream;

	ngx_array_t *flushes;
	ngx_array_t *body_set_len;
	ngx_array_t *body_set;
	ngx_array_t *headers_set_len;
	ngx_array_t *headers_set;
	ngx_hash_t headers_set_hash;

	ngx_array_t *headers_source;
# if defined(nginx_version) && (nginx_version < 8040)
	ngx_array_t *headers_names;
# endif /* nginx_version < 8040 */

	ngx_array_t *proxy_lengths;
	ngx_array_t *proxy_values;

	ngx_array_t *redirects;
# if defined(nginx_version) && (nginx_version >= 1001015)
	ngx_array_t *cookie_domains;
	ngx_array_t *cookie_paths;
# endif /* nginx_version >= 1001015 */

	ngx_str_t body_source;

	ngx_str_t method;
	ngx_str_t location;
	ngx_str_t url;

	ngx_http_complex_value_t cache_key;

	ngx_http_proxy_vars_t vars;

	ngx_flag_t redirect;

# if defined(nginx_version) && (nginx_version >= 1001004)
	ngx_uint_t http_version;
# endif /* nginx_version >= 1001004 */

	ngx_uint_t headers_hash_max_size;
	ngx_uint_t headers_hash_bucket_size;
} ngx_http_proxy_loc_conf_t;
extern ngx_module_t ngx_http_proxy_module;

#define NGX_HTTP_CACHE_KEY_LEN       16

static ngx_int_t ngx_http_find_cache_handler(ngx_http_request_t *r) {

	ngx_int_t rc;
	ngx_buf_t *b;
	ngx_chain_t out;

	u_char ngx_cache_node_t_string[2048] = { '\0' };
	ngx_uint_t content_length = 0;

	//get URL param key
	ngx_str_t key;
	ngx_http_arg(r, (u_char *) "key", sizeof("key")-1, &key);
	if (key.len > 0) {

		u_char* datas;
		datas=(u_char* )malloc((key.len+1)*sizeof(u_char));
		memset(datas,0,sizeof(u_char)*(key.len+1));
		ngx_sprintf(datas,"%V", &key);

		//char * ngx_key;
		//ngx_key=(char *)malloc(strlen(ngx_key_string));
		//ngx_key=ngx_key_string;

		//key is md5
		ngx_md5_t md5;
		u_char md5_buf[NGX_HTTP_CACHE_KEY_LEN];
		ngx_md5_init(&md5);
		ngx_md5_update(&md5, datas, key.len);
		ngx_md5_final(md5_buf, &md5);

		//get ngx_http_file_cache_t
		ngx_http_proxy_loc_conf_t *plcf;
		plcf = ngx_http_get_module_loc_conf(r, ngx_http_proxy_module);
		ngx_http_file_cache_t *cache = plcf->upstream.cache->data;

		//get ngx_http_file_cache_node_t
		ngx_rbtree_key_t node_key;
		ngx_rbtree_node_t *node, *sentinel;
		ngx_http_file_cache_node_t *fcn = NULL;

		ngx_memcpy((u_char * ) &node_key, md5_buf, sizeof(ngx_rbtree_key_t));
		node = cache->sh->rbtree.root;
		sentinel = cache->sh->rbtree.sentinel;

		while (node != sentinel) {
			if (node_key < node->key) {
				node = node->left;
				continue;
			}

			if (node_key > node->key) {
				node = node->right;
				continue;
			}

			/* node_key == node->key */

			fcn = (ngx_http_file_cache_node_t *) node;

			rc = ngx_memcmp(&md5_buf[sizeof(ngx_rbtree_key_t)], fcn->key,
					NGX_HTTP_CACHE_KEY_LEN - sizeof(ngx_rbtree_key_t));

			if (rc == 0) {
				break;
			}

			node = (rc < 0) ? node->left : node->right;
		}
		if (fcn != NULL ) {
			//ngx_cache_node_t_string
			ngx_sprintf(ngx_cache_node_t_string,
					"%Nbody_start:%d %Ncount:%d %Ndeleting:%d %Nerror:%d %Nexists:%d %Nexists:%T %Nfs_size:%O %Nkey:%s",
					fcn->body_start, fcn->count, fcn->deleting, fcn->error,
					fcn->exists, fcn->expire, fcn->fs_size, &fcn->key);
//			ngx_sprintf(ngx_cache_node_t_string,"count:%d", fcn->count);
//			ngx_sprintf(ngx_cache_node_t_string,"deleting:%d", fcn->deleting);
//			ngx_sprintf(ngx_cache_node_t_string,"\n error:%d", fcn->error);
//			ngx_sprintf(ngx_cache_node_t_string,"\n exists:%d", fcn->exists);
//
//			ngx_sprintf(ngx_cache_node_t_string,"\n exists:%T",fcn->expire);
//			ngx_sprintf(ngx_cache_node_t_string,"\n fs_size:%O", fcn->fs_size);
//			ngx_sprintf(ngx_cache_node_t_string, "\n key:%s", fcn->key);

		} else {
			ngx_sprintf(ngx_cache_node_t_string, "not found!");
		}
	}

	content_length = ngx_strlen(ngx_cache_node_t_string);

	/* we response to 'GET' and 'HEAD' requests only */
	if (!(r->method & (NGX_HTTP_GET | NGX_HTTP_HEAD))) {
		return NGX_HTTP_NOT_ALLOWED;
	}

	/* discard request body, since we don't need it here */
	rc = ngx_http_discard_request_body(r);

	if (rc != NGX_OK) {
		return rc;
	}

	/* set the 'Content-type' header */
	/*
	 r->headers_out.content_type_len = sizeof("text/html") - 1;
	 r->headers_out.content_type.len = sizeof("text/html") - 1;
	 r->headers_out.content_type.data = (u_char *)"text/html";*/
	ngx_str_set(&r->headers_out.content_type, "text/html");

	/* send the header only, if the request type is http 'HEAD' */
	if (r->method == NGX_HTTP_HEAD) {
		r->headers_out.status = NGX_HTTP_OK;
		r->headers_out.content_length_n = content_length;

		return ngx_http_send_header(r);
	}

	/* allocate a buffer for your response body */
	b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
	if (b == NULL ) {
		return NGX_HTTP_INTERNAL_SERVER_ERROR;
	}

	/* attach this buffer to the buffer chain */
	out.buf = b;
	out.next = NULL;

	/* adjust the pointers of the buffer */
	b->pos = ngx_cache_node_t_string;
	b->last = ngx_cache_node_t_string + content_length;
	b->memory = 1; /* this buffer is in memory */
	b->last_buf = 1; /* this is the last buffer in the buffer chain */

	/* set the status line */
	r->headers_out.status = NGX_HTTP_OK;
	r->headers_out.content_length_n = content_length;

	/* send the headers of your response */
	rc = ngx_http_send_header(r);

	if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
		return rc;
	}

	/* send the buffer chain of your response */
	return ngx_http_output_filter(r, &out);
}

static void *ngx_http_find_cache_create_loc_conf(ngx_conf_t *cf) {
	ngx_http_find_cache_loc_conf_t* local_conf = NULL;
	local_conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_find_cache_loc_conf_t));
	if (local_conf == NULL ) {
		return NULL ;
	}

	local_conf->find_cache = NGX_CONF_UNSET;

	return local_conf;
}

static char *ngx_http_find_cache(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
	ngx_http_core_loc_conf_t *clcf;

	//	/* set handler */
	clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module) ;

	clcf->handler = ngx_http_find_cache_handler;

	return NGX_CONF_OK ;
}

static ngx_int_t ngx_http_find_cache_init(ngx_conf_t *cf) {
	ngx_http_handler_pt *h;
	ngx_http_core_main_conf_t *cmcf;

	cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module) ;

	h = ngx_array_push(&cmcf->phases[NGX_HTTP_CONTENT_PHASE].handlers);
	if (h == NULL ) {
		return NGX_ERROR;
	}

	*h = ngx_http_find_cache_handler;

	return NGX_OK;
}
