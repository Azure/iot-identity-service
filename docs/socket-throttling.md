# Socket Throttling

Each of the services' sockets implement a throttling mechanism to prevent a malicious process from making continuous requests and denying service to other processes. By default, this throttling mechanism limits each caller to making 10 simultaneous requests per socket. Each caller is identified by its UID, so two processes sharing the same UNIX user will be throttled together.

If requests on a socket exceed this limit, a service will deny all further requests on its socket until the number of in-progress requests falls below 10. When a service denies a request, it closes the socket connection without sending a reply; this will be reported as an OS-level error (not an HTTP API error) to the caller. It is always the caller's responsibility to retry a request that failed due to throttling.

In addition to closing the socket connection, services will also log a message. The exact message may change between versions, but it will always specify which user (UNIX UID) was throttled.

```
[INFO] Max simultaneous connections reached for user 1000
```

Note that even the services' users (i.e. `aziotks`, `aziotcs`, `aziotid`) are subject to throttling when they make a request to other services.

## Raising the throttling limit

The default limit is 10 simultaneous requests per user. Should this be insufficient, a higher throttling limit can be specified in config.toml.

Each service's config.toml can specifiy the `max_requests` setting. For example, to raise the throttling limit for keyd to 50, add the following to keyd's config.toml.

```toml
max_requests = 50
```

The throttling limit can be specified in the super config for each service by adding the `[aziot_max_requests]`. For example:

```toml
[aziot_max_requests]
keyd = 20
certd = 30
tpmd = 40
identityd = 50
```
