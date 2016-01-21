This is a service that makes openwrt ubus available using json frontend. 

It is meant to make ubus access more accessible for applications without having
to use libubus at all. 

It is currently in a very experimental stage (02-jan-2016). 

UBUS JSON-RPC Protocol
======================

CALL: 

	{"jsonrpc":"2.0","id":1,"method":"call","params":["object","method",{..method args..}]}

RETURN: 

	{"jsonrpc":"2.0","id":1,"result":{...}}

ERROR: 
	
	{"jsonrpc":"2.0","id":1,"error":{"code":X,"message":".."}}

SIGNAL: 
	
	{"jsonrpc":"2.0","method":"signal","params":["type",{..data..}]}

Methods: 
	
	"call"
	
	call method of an object on the rpc server. Takes an array of parameters
	that are passed to the method. Usually parameters are a single object of
	key value pairs. 

	"list"
	
	lists all available objects and their methods on the backend.  

	"signal"

	defines a signal being sent asynchronously. A signal must not have id field in the rpc object. 
