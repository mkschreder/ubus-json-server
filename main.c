
#include "json_socket.h"
#include <libubox/blobmsg.h>
#include <libubox/blobmsg_json.h>
#include <libubus.h>

static struct blob_buf buf = {0}; 

enum {
	UBUS_MSG_METHOD_CALL = 1, 
	UBUS_MSG_METHOD_RETURN, 
	UBUS_MSG_ERROR, 
	UBUS_MSG_SIGNAL
}; 

struct json_request {
	struct list_head list; 
	uint32_t peer; 
	uint32_t serial; 
	int status; 
	bool response_sent; 
	struct json_socket *sock; 
	struct ubus_request *req; 
}; 

struct json_request *json_request_new(struct json_socket *sock, uint32_t src_peer, uint32_t serial){
	struct json_request *self = calloc(1, sizeof(struct json_request)); 
	self->req = calloc(1, sizeof(struct ubus_request)); 
	self->req->priv = self; 
	self->sock = sock; 
	self->peer = src_peer; 
	self->serial = serial; 
	return self; 
}

void json_request_delete(struct json_request **self){
	free(*self); 
	*self = NULL; 
}

static void _on_json_connected(struct json_socket *sock, uint32_t id){
	printf("proxy: client connected! %08x\n", id); 
}

static void receive_list_result(struct ubus_context *ctx, struct ubus_object_data *obj, void *priv){
	struct blob_buf *buf = (struct blob_buf*)priv; 
    struct blob_attr *cur;
    int rem;

	void *arr = blobmsg_open_table(buf, obj->path); 
    //printf("'%s' @%08x\n", obj->path, obj->id);

    if (obj->signature){
		blob_for_each_attr(cur, obj->signature, rem) { 
			struct blob_attr *param; 
			int rem2; 
			void *params = blobmsg_open_array(buf, blobmsg_name(cur)); 
			blobmsg_for_each_attr(param, cur, rem2){
				void *p = blobmsg_open_array(buf, NULL); 
				blobmsg_add_u32(buf, NULL, 1); 
				blobmsg_add_string(buf, NULL, blobmsg_name(param)); 
				blobmsg_add_string(buf, NULL, "s"); 
				blobmsg_close_array(buf, p); 
			}
			blobmsg_close_array(buf, params); 
		}
	}
	blobmsg_close_table(buf, arr); 
}

static void _server_send_error(struct json_socket *sock, uint32_t peer, int code, uint32_t serial, const char *msg){
	static const char *errors[] = {
		"UBUS_STATUS_OK",                     
		"UBUS_STATUS_INVALID_COMMAND",        
		"UBUS_STATUS_INVALID_ARGUMENT",       
		"UBUS_STATUS_METHOD_NOT_FOUND",       
		"UBUS_STATUS_NOT_FOUND",              
		"UBUS_STATUS_NO_DATA",                
		"UBUS_STATUS_PERMISSION_DENIED",      
		"UBUS_STATUS_TIMEOUT",                
		"UBUS_STATUS_NOT_SUPPORTED",          
		"UBUS_STATUS_UNKNOWN_ERROR",
		"UBUS_STATUS_CONNECTION_FAILED",
	}; 

	blob_buf_init(&buf, 0); 
	blobmsg_buf_init(&buf); 
	void *obj = blobmsg_open_table(&buf, NULL); 
	blobmsg_add_string(&buf, "jsonrpc", "2.0"); 
	blobmsg_add_u32(&buf, "id", serial); 
	void *arr = blobmsg_open_array(&buf, "result"); 
	void *data = blobmsg_open_table(&buf, NULL); 
	blobmsg_add_u32(&buf, "code", code);
	if(code >= 0 && code < __UBUS_STATUS_LAST)
		blobmsg_add_string(&buf, "error", errors[code]); 
	blobmsg_add_string(&buf, "message", msg); 	
	blobmsg_close_table(&buf, data); 
	blobmsg_close_array(&buf, arr); 	
	blobmsg_close_table(&buf, obj); 

	json_socket_send(sock, peer, UBUS_MSG_ERROR, serial, buf.head); 
}

static void _on_call_completed(struct ubus_request *req, int ret){
	printf("request complete: %d\n", ret); 
	struct json_request *jr = (struct json_request*)req->priv; 
	jr->status = ret; 
	if(ret != 0){
		_server_send_error(jr->sock, jr->peer, ret, jr->serial, "Method call failed!"); 
		jr->response_sent = true; 
	}
}

static void _on_call_result_data(struct ubus_request *req, int type, struct blob_attr *msg){
	printf("got response\n"); 
	struct json_request *jr = (struct json_request*)req->priv; 
	blob_buf_init(&buf, 0); 
	blobmsg_buf_init(&buf); 
	void *obj = blobmsg_open_table(&buf, NULL); 
	blobmsg_add_string(&buf, "jsonrpc", "2.0"); 
	blobmsg_add_u32(&buf, "id", jr->serial); 
	void *arr = blobmsg_open_array(&buf, "result"); 
	void *data = blobmsg_open_table(&buf, NULL); 
	struct blob_attr *cur; int rem; 
	//void *foo = blobmsg_open_table(&buf, NULL); 
	blobmsg_for_each_attr(cur, msg, rem){ 
		blobmsg_add_blob(&buf, cur); 
	}
	blobmsg_close_table(&buf, data); 
	blobmsg_close_array(&buf, arr); 	
	blobmsg_close_table(&buf, obj); 
	// send the response
	json_socket_send(jr->sock, jr->peer, UBUS_MSG_METHOD_RETURN, jr->serial, buf.head); 
	jr->response_sent = true; 
}

void _on_json_message(struct json_socket *self, uint32_t peer, uint8_t type, uint32_t serial, struct blob_attr *msg){
	//printf("got message from peer %08x\n", peer); 
	struct ubus_context *ctx = (struct ubus_context*)json_socket_get_userdata(self); 	

	enum {
		RPC_JSONRPC,
		RPC_ID,
		RPC_METHOD,
		RPC_PARAMS,
		__RPC_MAX,
	};

	static const struct blobmsg_policy rpc_policy[__RPC_MAX] = {
		[RPC_JSONRPC] = { .name = "jsonrpc", .type = BLOBMSG_TYPE_STRING },
		[RPC_METHOD] = { .name = "method", .type = BLOBMSG_TYPE_STRING },
		[RPC_PARAMS] = { .name = "params", .type = BLOBMSG_TYPE_ARRAY },
		[RPC_ID] = { .name = "id", .type = BLOBMSG_TYPE_INT32 },
	};

	const struct blobmsg_policy data_policy[] = {
		{ .type = BLOBMSG_TYPE_STRING },
		{ .type = BLOBMSG_TYPE_STRING },
		{ .type = BLOBMSG_TYPE_TABLE },
	};
	struct blob_attr *tb[__RPC_MAX];
	struct blob_attr *tb2[4];
	struct blob_attr *cur;

	blobmsg_parse(rpc_policy, __RPC_MAX, tb, blobmsg_data(msg), blobmsg_len(msg));
	
	//printf("got json message\n"); 
	cur = tb[RPC_JSONRPC];
	if (!cur || strcmp(blobmsg_data(cur), "2.0") != 0){
		_server_send_error(self, peer, UBUS_STATUS_INVALID_ARGUMENT, serial, "invalid rpc version!\n"); 
		return;
	}

	if (!tb[RPC_METHOD]){
		_server_send_error(self, peer, UBUS_STATUS_INVALID_ARGUMENT, serial, "method unspecified!\n"); 
		return;
	}
	const char *rpc_method = blobmsg_data(tb[RPC_METHOD]); 

	cur = tb[RPC_PARAMS];
	if (!cur){
		_server_send_error(self, peer, UBUS_STATUS_INVALID_ARGUMENT, serial, "params unspecified!\n"); 
		return;
	}

	if(tb[RPC_ID])
		serial = blobmsg_get_u32(tb[RPC_ID]); 

	blobmsg_parse_array(data_policy, ARRAY_SIZE(data_policy), tb2,
			    blobmsg_data(tb[RPC_PARAMS]), blobmsg_len(tb[RPC_PARAMS]));

	if(strcmp(rpc_method, "list") == 0){
		printf("proxy: list request from %08x\n", peer); 
		if (!tb2[0]){
			_server_send_error(self, peer, UBUS_STATUS_INVALID_ARGUMENT, serial, "object unspecified in params!\n"); 
			return; 
		}

		blob_buf_init(&buf, 0); 
		blobmsg_buf_init(&buf); 
		void *obj = blobmsg_open_table(&buf, NULL); 
		blobmsg_add_string(&buf, "jsonrpc", "2.0"); 
		blobmsg_add_u32(&buf, "id", serial); 
		void *arr = blobmsg_open_array(&buf, "result"); 
		void *data = blobmsg_open_table(&buf, NULL); 
		char *search = "*"; 
		if(tb2[0]) search = blobmsg_data(tb2[0]); 
		ubus_lookup(ctx, search, receive_list_result, &buf);
		blobmsg_close_table(&buf, data); 
		blobmsg_close_array(&buf, arr); 	
		blobmsg_close_table(&buf, obj); 
		json_socket_send(self, peer, UBUS_MSG_METHOD_RETURN, serial, buf.head); 
	} else if(strcmp(rpc_method, "call") == 0){
		if (!tb2[0]){
			_server_send_error(self, peer, UBUS_STATUS_INVALID_ARGUMENT, serial, "object unspecified in params!\n"); 
			return; 
		}

		const char *object = blobmsg_data(tb2[0]);

		if (!tb2[1]){
			_server_send_error(self, peer, UBUS_STATUS_INVALID_ARGUMENT, serial, "method unspecified in params!\n"); 
			return; 
		}
		
		const char *method = blobmsg_data(tb2[1]);
				
		if(!tb2[2]){
			_server_send_error(self, peer, UBUS_STATUS_INVALID_ARGUMENT, serial, "params unspecified in params!\n"); 
			return; 
		}

		uint32_t id = 0; 
		if(ubus_lookup_id(ctx, object, &id) < 0 || !id) {
			_server_send_error(self, peer, UBUS_STATUS_NOT_FOUND, serial, "object not found!\n");
			return;
		}

		char *json = blobmsg_format_json(tb2[2], false); 
		printf("proxy: call from %08x, object=%s, method=%s params=%s\n", peer, object, method, json);  
		free(json); 

		struct json_request *jr = json_request_new(self, peer, serial);  

		blob_buf_init(&buf, 0); 
		struct blob_attr *cur; int rem; 
		//void *foo = blobmsg_open_table(&buf, NULL); 
		blobmsg_for_each_attr(cur, tb2[2], rem){ 
			blobmsg_add_blob(&buf, cur); 
			//blobmsg_add_blob(&buf, blobmsg_data(tb2[2])); 

		}
		//blobmsg_close_table(&buf, foo); 

		int rc = ubus_invoke_async(ctx, id, method, buf.head, jr->req);
		if(rc){
			printf("could not make call! %d\n", rc); 
		}
		// NOTE: this is incredibly retarded! Holy fuck! Why is invoke sync INITIALIZING the request? What idiot wrote original ubus libraries???
		jr->req->priv = jr; 
		jr->req->data_cb = _on_call_result_data; 
		jr->req->complete_cb = _on_call_completed; 
		ubus_complete_request(ctx, jr->req, 5000); 
		// pretty ugly but just makes sure we at least send an empty response when ubus returns ok but no data. 
		if(!jr->response_sent){
			blob_buf_init(&buf, 0); 
			blobmsg_buf_init(&buf); 
			void *obj = blobmsg_open_table(&buf, NULL); 
			blobmsg_add_string(&buf, "jsonrpc", "2.0"); 
			blobmsg_add_u32(&buf, "id", jr->serial); 
			void *arr = blobmsg_open_array(&buf, "result"); 
			void *data = blobmsg_open_table(&buf, NULL); 
			blobmsg_close_table(&buf, data); 
			blobmsg_close_array(&buf, arr); 	
			blobmsg_close_table(&buf, obj); 
			// send the response
			json_socket_send(jr->sock, jr->peer, UBUS_MSG_METHOD_RETURN, jr->serial, buf.head); 
		}
		printf("request done!\n"); 
	} else {
		_server_send_error(self, peer, UBUS_STATUS_NOT_SUPPORTED, serial, "Method not supported!"); 
	}
}

static bool done = false; 
static void _handle_ctrl_c(int sig){
	done = true; 
}

int main(int argc, char **argv){
	struct json_socket *sock = json_socket_new(); 
	struct ubus_context *ctx = ubus_connect(NULL); 

	if(!ctx){
		fprintf(stderr, "Could not connect to ubus!\n"); 
		return -1; 
	}

	blob_buf_init(&buf, 0); 

	signal(SIGINT, _handle_ctrl_c); 
	signal(SIGPIPE, SIG_IGN); 

	if(json_socket_listen(sock, "/var/run/ubus-json.sock") < 0){
		fprintf(stderr, "could not listen on socket!\n");
		return -1; 
	}
	
	json_socket_on_client_connected(sock, _on_json_connected); 
	json_socket_on_message(sock, _on_json_message); 
	json_socket_set_userdata(sock, ctx); 

	while(!done){
		json_socket_poll(sock, 10); 
	}

	json_socket_delete(&sock); 
	ubus_free(ctx); 

	return 0; 
}
