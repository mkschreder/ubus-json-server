all: ubus-json-server; 

CFLAGS+=-g -Wall

ubus-json-server: json_socket.c ubus_id.c main.c
	$(CC) $(CFLAGS) -std=gnu99 -o $@ $^ -lubus -lubox -ljson-c -lblobmsg_json $(LDFLAGS)

clean: 
	rm -f *.o ubus-json-server
