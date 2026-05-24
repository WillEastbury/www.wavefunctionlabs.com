# Picoweb overload and abuse controls

Picoweb remains the production TLS listener on `:443`; do not add a proxy or
TLS terminator to absorb overload.

## Existing controls

- Kernel listen backlog plus per-worker preallocated connection pools bound the
  number of concurrent accepted connections.
- `POOL_CAP` in `k8s/wfl-www.yaml` is 64 per worker, with two workers in
  production.
- `MAXREQS` is 100 per keep-alive connection.
- `PICOWEB_INCOMPLETE_REQUEST_TIMEOUT_MS` bounds slow/incomplete requests.
- Score writes have token validation and per-client rate limiting; rejected
  writes return `429`, `400`, `503`, or `507` rather than silently dropping data.

## Signals

`/metricsz` exposes first-party overload counters:

```text
picoweb_accept_drops_total{reason="pool_exhausted"}
picoweb_accept_drops_total{reason="fd_limit"}
picoweb_score_rejects_total{reason="rate_limited"}
```

Any sustained increase in `pool_exhausted` means the preallocated pool is too
small for observed connection concurrency or a client is holding sockets open.
Any `fd_limit` increment means the process or pod file descriptor limit needs
inspection before raising traffic.

## Operator actions

1. Confirm `/readyz` remains ready and `/metricsz` is scrapeable.
2. If only score writes are rejected, inspect
   `picoweb_score_rejects_total{reason="rate_limited"}` and client IPs in the
   bounded access logs before changing limits.
3. If accept drops increase, first raise `POOL_CAP` by a small step and deploy a
   unique image/config tag. Do not add replicas unless the single-writer
   picowal storage model has been changed.
4. If incomplete request timeouts dominate, lower
   `PICOWEB_INCOMPLETE_REQUEST_TIMEOUT_MS` only after checking mobile/browser
   clients are not being cut off during normal TLS handshakes.
