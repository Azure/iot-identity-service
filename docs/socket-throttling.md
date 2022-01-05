# Socket Throttling

Each of the services' sockets implement a throttling mechanism to prevent a malicious process from making continuous requests and denying service to other processes. This throttling mechanism limits each UNIX user to making 10 simultaneous requests per socket.

If requests on a socket exceed this limit, a service will deny all further requests on its socket until the number of in-progress requests falls below 10. When a service denies a request, it closes the socket connection without sending a reply; this will be reported as an OS-level error (not an HTTP API error) to the caller. It is always the caller's responsibility to retry a request that failed due to throttling.

In addition to closing the socket connection, services will also log a message. The exact message may change between versions, but it will always specify which user (UNIX UID) was throttled.

```
[INFO] Max simultaneous connections reached for user 1000
```

Note that even the services' users (i.e. `aziotks`, `aziotcs`, `aziotid`) are subject to throttling when they make a request to other services.
