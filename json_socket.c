/*
 * Copyright (C) 2015,2016 Martin Schröder <mkschreder.uk@gmail.com>
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License version 2.1
 * as published by the Free Software Foundation
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#define _GNU_SOURCE

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/uio.h>
#ifdef FreeBSD
#include <sys/param.h>
#endif
#include <signal.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>

#include <libubox/usock.h>
#include <libubox/blobmsg.h>

#include "ubus_id.h"

#include <libubox/blobmsg_json.h>

#include "json_socket.h"
#include <assert.h>

#define STATIC_IOV(_var) { .iov_base = (char *) &(_var), .iov_len = sizeof(_var) }

#define UBUS_MSGBUF_REDUCTION_INTERVAL	16

struct ubus_frame {
	struct list_head list; 

	char *data; 
	int data_size; 
	int send_count; 
}; 

struct ubus_client {
	struct ubus_id id; 
	struct list_head tx_queue; 
	int fd; 

	char *recv_buffer; 
	int recv_size; 
	int recv_count; 
	struct blob_buf buf; 
	//struct list_head rx_queue;
}; 

uint16_t _crc16(char* data_p, uint32_t length){
    unsigned char x;
    uint16_t crc = 0xFFFF;

    while (length--){
        x = crc >> 8 ^ *data_p++;
        x ^= x>>4;
        crc = (crc << 8) ^ ((uint16_t)(x << 12)) ^ ((uint16_t)(x <<5)) ^ ((uint16_t)x);
    }
    return crc;
}

static struct ubus_client *ubus_client_new(int fd){
	struct ubus_client *self = calloc(1, sizeof(struct ubus_client)); 
	INIT_LIST_HEAD(&self->tx_queue); 
	self->fd = fd; 
	self->recv_buffer = calloc(1, 1024); 
	self->recv_size = 1024; 
	self->recv_count = 0; 
	blob_buf_init(&self->buf, 0); 
	return self; 
}

static void ubus_client_delete(struct ubus_client **self){
	shutdown((*self)->fd, SHUT_RDWR); 
	close((*self)->fd); 
	blob_buf_free(&(*self)->buf); 
	free((*self)->recv_buffer); 
	free(*self); 
	*self = NULL;
}

struct ubus_frame *ubus_frame_new(int type, uint16_t seq, struct blob_attr *msg){
	assert(msg); 
	struct ubus_frame *self = calloc(1, sizeof(struct ubus_frame)); 
	char *json = blobmsg_format_json(msg, true); 
	self->data_size = strlen(json) + 1; 
	self->data = calloc(1, self->data_size + 1); 
	sprintf(self->data, "%s\n", json); 
	free(json); 
	INIT_LIST_HEAD(&self->list); 
	return self; 
}

void ubus_frame_delete(struct ubus_frame **self){
	free((*self)->data); 
	free(*self); 
	*self = NULL; 
}

struct json_socket *json_socket_new(void){
	struct json_socket *self = calloc(1, sizeof(struct json_socket)); 
	json_socket_init(self); 
	return self; 
}

void json_socket_delete(struct json_socket **self){
	json_socket_destroy(*self); 
	free(*self); 
	*self = NULL; 
}

void json_socket_init(struct json_socket *self){
	//INIT_LIST_HEAD(&self->clients); 
	ubus_id_tree_init(&self->clients); 
}

void json_socket_destroy(struct json_socket *self){
	struct ubus_id *id, *tmp; 
	avl_for_each_element_safe(&self->clients, id, avl, tmp){
		struct ubus_client *client = container_of(id, struct ubus_client, id);  
		ubus_id_free(&self->clients, &client->id); 
		ubus_client_delete(&client); 
	}
	if(self->listen_fd) close(self->listen_fd);
}

static void _accept_connection(struct json_socket *self){
	bool done = false; 

	do {
		int client = accept(self->listen_fd, NULL, 0);
		if ( client < 0 ) {
			switch (errno) {
			case ECONNABORTED:
			case EINTR:
				done = true;
			default:
				return;  
			}
		}

		// configure client into non blocking mode
		fcntl(client, F_SETFL, fcntl(client, F_GETFL) | O_NONBLOCK | O_CLOEXEC);

		struct ubus_client *cl = ubus_client_new(client); 
		ubus_id_alloc(&self->clients, &cl->id, 0); 
		
		if(self->on_client_connected){
			self->on_client_connected(self, cl->id.id); 
		}
	} while (!done);
}

static void _split_address_port(char *address, int addrlen, char **port){
	for(int c = 0; c < addrlen; c++){
		if(address[c] == ':' && c != (addrlen - 1)) {
			address[c] = 0; 
			*port = address + c + 1; 
			break; 
		}
	}
}

int json_socket_listen(struct json_socket *self, const char *_address){
	assert(_address);
	int addrlen = strlen(_address); 
	char *address = alloca(addrlen); 
	strcpy(address, _address); 
	char *port = NULL; 
	int flags =  USOCK_SERVER | USOCK_NONBLOCK; 
	if(address[0] == '/' || address[0] == '.'){
		umask(0177);
		unlink(address);
		flags |= USOCK_UNIX; 
	} else {
		_split_address_port(address, addrlen, &port); 
	}
	//printf("trying to listen on %s %s\n", address, port); 
	self->listen_fd = usock(flags, address, port);
	if (self->listen_fd < 0) {
		perror("usock");
		return -1; 
	}
	return 0; 
}

int json_socket_connect(struct json_socket *self, const char *_address, uint32_t *id){
	int flags = 0; 
	int addrlen = strlen(_address); 
	char *address = alloca(addrlen); 
	strcpy(address, _address); 
	char *port = NULL; 
	if(address[0] == '/' || address[0] == '.') flags |= USOCK_UNIX; 
	else _split_address_port(address, addrlen, &port); 
	int fd = usock(flags, address, port);
	if (fd < 0)
		return -1;

	fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK | O_CLOEXEC);

	struct ubus_client *cl = ubus_client_new(fd); 
	ubus_id_alloc(&self->clients, &cl->id, 0); 
	
	// connecting out generates the same event as connecting in
	if(self->on_client_connected){
		self->on_client_connected(self, cl->id.id); 
	}

	if(id) *id = cl->id.id; 

	return 0; 
}

bool _ubus_client_recv(struct ubus_client *self, struct json_socket *socket){
	int rc = recv(self->fd, self->recv_buffer + self->recv_count, self->recv_size - self->recv_count, 0); 
	if(rc == 0){
		//printf("eof reached!\n"); 
		return false; 
	}

	if(rc > 0){
		// check if we got a new line (message separator)
		self->recv_count += rc;

		// check if buffer full
		if(self->recv_count == self->recv_size){
			//TODO: handle properly or resize the buffer 
			printf("too large message!\n"); 
			self->recv_count = 0;
			return false; 
			//close(self->fd); 
		}

		// process as many messages as we can and save any extra data in the recv buffer 
		while(true){
			char *ch; 
			for(ch = self->recv_buffer; 
				*ch && *ch != '\n' && ch < (self->recv_buffer + self->recv_count); ch++){
			}
			if(*ch == '\n'){
				*ch = 0; 
				blob_buf_init(&self->buf, 0); 
				blobmsg_buf_init(&self->buf); 
				if(blobmsg_add_json_from_string(&self->buf, self->recv_buffer)){
					printf("got message: %s from %08x\n", self->recv_buffer, self->id.id); 
					if(socket->on_message){
						socket->on_message(socket, self->id.id, 0, 1, self->buf.head); 
					}
				} else {
					printf("got invalid json! %s\n", self->recv_buffer); 
					// TODO: disconnect client
				}
				int pos = (ch - self->recv_buffer + 1); 
				int rest_size = self->recv_count - pos; 
				//printf("rest size %d\n", rest_size); 
				if(rest_size > 0){
					char *rest = calloc(1, self->recv_size); 
					memcpy(rest, self->recv_buffer + pos, rest_size); 
					free(self->recv_buffer); 
					self->recv_buffer = rest; 
					self->recv_count = rest_size; 
					continue; 
				} else {
					self->recv_count = 0; 
				}
			} 
			break; 
		}
	} 
	return true; 
}

void _ubus_client_send(struct ubus_client *self){
	if(list_empty(&self->tx_queue)){
		return; 
	}

	struct ubus_frame *req = list_first_entry(&self->tx_queue, struct ubus_frame, list);

	int sc; 
	while((sc = send(self->fd, req->data + req->send_count, req->data_size - req->send_count, MSG_NOSIGNAL)) > 0){
		req->send_count += sc; 
	}
	// TODO: handle disconnect
	if(req->send_count == req->data_size){
		// full buffer was transmitted so we destroy the request
		list_del_init(&req->list); 
		//printf("removed completed request from queue! %d bytes\n", req->send_count); 
		ubus_frame_delete(&req); 
	}
}

void json_socket_poll(struct json_socket *self, int timeout){
	int count = self->clients.count + 1; 
	struct pollfd *pfd = alloca(sizeof(struct pollfd) * count); 
	memset(pfd, 0, sizeof(struct pollfd) * count); 
	struct ubus_client **clients = alloca(sizeof(void*)*100); 
	pfd[0] = (struct pollfd){ .fd = self->listen_fd, .events = POLLIN | POLLERR }; 
	clients[0] = 0; 

	int c = 1; 
	struct ubus_id *id;  
	avl_for_each_element(&self->clients, id, avl){
		struct ubus_client *client = (struct ubus_client*)container_of(id, struct ubus_client, id);  
		pfd[c] = (struct pollfd){ .fd = client->fd, .events = POLLOUT | POLLIN | POLLERR };  
		clients[c] = client;  
		c++; 
	}		
	
	// try to send more data
	for(int c = 1; c < count; c++){
		_ubus_client_send(clients[c]); 
	}

	int ret = 0; 
	if((ret = poll(pfd, count, timeout)) > 0){
		if(pfd[0].revents != 0){
			// TODO: check for errors
			_accept_connection(self);
		}
		for(int c = 1; c < count; c++){
			if(pfd[c].revents != 0){
				if(pfd[c].revents & POLLHUP || pfd[c].revents & POLLRDHUP){
					printf("json_socket: peer hung up (%08x)!\n", clients[c]->id.id); 
					_ubus_client_recv(clients[c], self); 
					avl_delete(&self->clients, &clients[c]->id.avl); 
					ubus_client_delete(&clients[c]); 
					continue; 
				} else if(pfd[c].revents & POLLERR){
					printf("ERROR: json_socket error!\n"); 
				} else if(pfd[c].revents & POLLIN) {
					// receive as much data as we can
					if(!_ubus_client_recv(clients[c], self)){
						printf("json_socket: client %08x disconnected!\n", clients[c]->id.id); 
						avl_delete(&self->clients, &clients[c]->id.avl); 
						ubus_client_delete(&clients[c]); 
					}
				}
			}
		}
	}
}

int json_socket_send(struct json_socket *self, int32_t peer, int type, uint16_t serial, struct blob_attr *msg){
	struct ubus_id *id;  
	char *json = blobmsg_format_json(blobmsg_data(msg), false); 
	printf("sending %s\n", json); 
	free(json); 

	if(peer == UBUS_PEER_BROADCAST){
		avl_for_each_element(&self->clients, id, avl){
			struct ubus_client *client = (struct ubus_client*)container_of(id, struct ubus_client, id);  
			struct ubus_frame *req = ubus_frame_new(type, serial, blobmsg_data(msg));
			list_add(&req->list, &client->tx_queue); 
			// try to send as much as we can right away
			_ubus_client_send(client); 
			//printf("added request to tx_queue!\n"); 
		}		
	} else {
		struct ubus_id *id = ubus_id_find(&self->clients, peer); 
		if(!id) return -1; 
		struct ubus_client *client = (struct ubus_client*)container_of(id, struct ubus_client, id);  
		struct ubus_frame *req = ubus_frame_new(type, serial, blobmsg_data(msg));
		list_add(&req->list, &client->tx_queue); 
		_ubus_client_send(client); 
	}
	return 0; 	
}

