
#include "json_socket.h"
#include <libubox/blobmsg.h>
#include <libubox/blobmsg_json.h>
#include <libubus.h>

struct json_request {
	struct list_head list; 
	uint32_t peer; 
	struct json_socket *sock; 
	struct ubus_request *req; 
}; 

struct json_request *json_request_new(struct json_socket *sock, uint32_t src_peer); 
void json_request_delete(struct json_request **self); 

struct json_request *json_request_new(struct json_socket *sock, uint32_t src_peer){
	struct json_request *self = calloc(1, sizeof(struct json_request)); 
	self->req = calloc(1, sizeof(struct ubus_request)); 
	self->req->priv = self; 
	self->sock = sock; 
	self->peer = src_peer; 
	return self; 
}

void json_request_delete(struct json_request **self){
	free(*self); 
	*self = NULL; 
}

static void _on_call_result_data(struct ubus_request *req, int type, struct blob_attr *msg){
	//printf("got response!\n"); 
	struct json_request *jr = (struct json_request*)req->priv; 

	// send the response
	json_socket_send(jr->sock, jr->peer, 0, 0, msg); 
}

void _on_json_message(struct json_socket *self, uint32_t peer, uint8_t type, uint32_t serial, struct blob_attr *msg){
	//printf("got message from peer %08x\n", peer); 
	struct ubus_context *ctx = (struct ubus_context*)json_socket_get_userdata(self); 	
	enum {
		RPC_JSONRPC,
		RPC_METHOD,
		RPC_PARAMS,
		RPC_ID,
		__RPC_MAX,
	};

	static const struct blobmsg_policy rpc_policy[__RPC_MAX] = {
		[RPC_JSONRPC] = { .name = "jsonrpc", .type = BLOBMSG_TYPE_STRING },
		[RPC_METHOD] = { .name = "method", .type = BLOBMSG_TYPE_STRING },
		[RPC_PARAMS] = { .name = "params", .type = BLOBMSG_TYPE_ARRAY },
		[RPC_ID] = { .name = "id", .type = BLOBMSG_TYPE_UNSPEC },
	};

	const struct blobmsg_policy data_policy[] = {
		{ .type = BLOBMSG_TYPE_STRING },
		{ .type = BLOBMSG_TYPE_STRING },
		{ .type = BLOBMSG_TYPE_STRING },
		{ .type = BLOBMSG_TYPE_TABLE },
	};
	struct blob_attr *tb[__RPC_MAX];
	struct blob_attr *tb2[4];
	struct blob_attr *cur;

	blobmsg_parse(rpc_policy, __RPC_MAX, tb, blobmsg_data(msg), blobmsg_len(msg));

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
		printf("params unspecified!\n"); 
		return;
	}

	blobmsg_parse_array(data_policy, ARRAY_SIZE(data_policy), tb2,
			    blobmsg_data(tb[RPC_PARAMS]), blobmsg_len(tb[RPC_PARAMS]));

	if (!tb2[0]){
		printf("sid unspecified\n"); 
		return; 
	}

	const char *sid = blobmsg_data(tb2[0]);

	if (!tb2[1]){
		printf("object unspecified!\n"); 
		return; 
	}

	const char *object = blobmsg_data(tb2[1]);

	if (!tb2[2]){
		printf("method unspecified!\n"); 
		return; 
	}
	
	const char *method = blobmsg_data(tb2[2]);
			
	if(!tb2[3]){
		printf("params unspecified!\n"); 
		return; 
	}

	printf("call %s %s %s\n", sid, object, method); 

	uint32_t id = 0; 
	if(ubus_lookup_id(ctx, object, &id) < 0) {
		printf("object not found!\n");
		return;
	}

	struct json_request *jr = json_request_new(self, peer);  

	ubus_invoke_async(ctx, id, method, tb2[3], jr->req);

	// NOTE: this is incredibly retarded! Holy fuck! Why is invoke sync INITIALIZING the request? What idiot wrote original ubus libraries???
	jr->req->priv = jr; 
	jr->req->data_cb = _on_call_result_data; 

	ubus_complete_request(ctx, jr->req, 5000); 
}

int main(int argc, char **argv){
	struct json_socket *sock = json_socket_new(); 
	struct ubus_context *ctx = ubus_connect(NULL); 

	signal(SIGPIPE, SIG_IGN); 

	if(json_socket_listen(sock, "/var/run/ubus-json.sock") < 0){
		fprintf(stderr, "could not listen on socket!\n");
		return -1; 
	}
	
	json_socket_on_message(sock, _on_json_message); 
	json_socket_set_userdata(sock, ctx); 

	while(true){
		json_socket_poll(sock, 0); 
	}
	return 0; 
}
