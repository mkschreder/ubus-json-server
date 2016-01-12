
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

static void _on_call_result_data(struct ubus_request *req, int type, struct blob_attr *msg){
	//printf("got response!\n"); 
	struct json_request *jr = (struct json_request*)req->priv; 
	blob_buf_init(&buf, 0); 
	blobmsg_buf_init(&buf); 
	void *obj = blobmsg_open_table(&buf, NULL); 
	blobmsg_add_string(&buf, "jsonrpc", "2.0"); 
	blobmsg_add_u32(&buf, "id", jr->serial); 
	void *arr = blobmsg_open_array(&buf, "result"); 
	void *data = blobmsg_open_table(&buf, NULL); 
	blobmsg_add_blob(&buf, blobmsg_data(msg)); 
	blobmsg_close_table(&buf, data); 
	blobmsg_close_array(&buf, arr); 	
	blobmsg_close_table(&buf, obj); 
	// send the response
	json_socket_send(jr->sock, jr->peer, UBUS_MSG_METHOD_RETURN, jr->serial, buf.head); 
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
		{ .type = BLOBMSG_TYPE_ARRAY },
	};
	struct blob_attr *tb[__RPC_MAX];
	struct blob_attr *tb2[4];
	struct blob_attr *cur;

	blobmsg_parse(rpc_policy, __RPC_MAX, tb, blobmsg_data(msg), blobmsg_len(msg));
	
	//printf("got json message\n"); 
	cur = tb[RPC_JSONRPC];
	if (!cur || strcmp(blobmsg_data(cur), "2.0") != 0){
		printf("invalid rpc version!\n"); 
		return;
	}

	cur = tb[RPC_METHOD];
	if (!cur){
		printf("method unspecified!\n"); 
		return;
	}

	cur = tb[RPC_PARAMS];
	if (!cur){
		printf("json_socket: params unspecified in request!\n"); 
		return;
	}

	if(tb[RPC_ID])
		serial = blobmsg_get_u32(tb[RPC_ID]); 

	blobmsg_parse_array(data_policy, ARRAY_SIZE(data_policy), tb2,
			    blobmsg_data(tb[RPC_PARAMS]), blobmsg_len(tb[RPC_PARAMS]));

	/*if (!tb2[0]){
		printf("sid unspecified\n"); 
		return; 
	}
	const char *sid = blobmsg_data(tb2[0]);

*/
	if (!tb2[0]){
		printf("object unspecified!\n"); 
		return; 
	}

	const char *object = blobmsg_data(tb2[0]);

	if (!tb2[1]){
		printf("method unspecified!\n"); 
		return; 
	}
	
	const char *method = blobmsg_data(tb2[1]);
			
	if(!tb2[2]){
		printf("params unspecified!\n"); 
		return; 
	}

	if(strcmp(object, "crash_me") == 0){
		int *foo = 0; 
		*foo = 1; 
	}

	uint32_t id = 0; 
	if(ubus_lookup_id(ctx, object, &id) < 0) {
		printf("object not found!\n");
		return;
	}

	if(strcmp(object, "/ubus/peer") == 0 && strcmp(method, "ubus.peer.list") == 0){
		printf("proxy: list request from %08x\n", peer); 
		blob_buf_init(&buf, 0); 
		blobmsg_buf_init(&buf); 
		void *obj = blobmsg_open_table(&buf, NULL); 
		blobmsg_add_string(&buf, "jsonrpc", "2.0"); 
		blobmsg_add_u32(&buf, "id", serial); 
		void *arr = blobmsg_open_array(&buf, "result"); 
		void *data = blobmsg_open_table(&buf, NULL); 
		ubus_lookup(ctx, "*", receive_list_result, &buf);
		blobmsg_close_table(&buf, data); 
		blobmsg_close_array(&buf, arr); 	
		blobmsg_close_table(&buf, obj); 
		json_socket_send(self, peer, UBUS_MSG_METHOD_RETURN, serial, buf.head); 
		return; 
	} else {
		printf("proxy: call from %08x, object=%s, method=%s\n", peer, object, method);  
		struct json_request *jr = json_request_new(self, peer, serial);  

		ubus_invoke_async(ctx, id, method, tb2[2], jr->req);

		// NOTE: this is incredibly retarded! Holy fuck! Why is invoke sync INITIALIZING the request? What idiot wrote original ubus libraries???
		jr->req->priv = jr; 
		jr->req->data_cb = _on_call_result_data; 

		ubus_complete_request(ctx, jr->req, 5000); 
	}
}

static bool done = false; 
static void _handle_ctrl_c(int sig){
	done = true; 
}

int main(int argc, char **argv){
	struct json_socket *sock = json_socket_new(); 
	struct ubus_context *ctx = ubus_connect(NULL); 

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
		json_socket_poll(sock, 0); 
	}

	json_socket_delete(&sock); 
	ubus_free(ctx); 

	return 0; 
}
