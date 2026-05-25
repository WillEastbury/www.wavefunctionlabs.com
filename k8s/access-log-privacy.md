# Access log privacy and retention

Picoweb emits optional first-party access logs to container stderr when
`PICOWEB_ACCESS_LOG=1`. The repository does not deploy a log collector, log PVC,
or long-term log store.

## Logged fields

Each request log is one NDJSON object:

```json
{"event":"access","ts_ms":123,"method":"GET","route":"static","status":200,"latency_us":42,"request_bytes":100,"response_plaintext_bytes":1024,"client_ip":"redacted","aborted":false}
```

Intentional data minimization:

- no raw URL path,
- no query string,
- no headers,
- no cookies,
- no request or response body,
- score API requests are logged only as route `scores` or `scores_start`,
- client IP is redacted by default.

## IP handling

`PICOWEB_ACCESS_LOG_IP` controls the `client_ip` field:

| Value | Behavior |
| --- | --- |
| unset / `redacted` | emit `"client_ip":"redacted"` |
| `none`, `0`, `off` | emit `"client_ip":"-"` |
| `full` | emit the accepted peer IP |

Production sets `PICOWEB_ACCESS_LOG_IP=redacted`. Use `full` only during a
time-bounded incident where source IP is necessary and no lower-sensitivity
signal answers the question. Revert to `redacted` immediately after the
incident.

## Retention

Access logs are container stderr only. This repository intentionally provisions
no persistent log volume and no additional logging backend. Operational
retention is therefore whatever the Kubernetes/container runtime keeps for pod
logs; do not add persistent logging storage without a separate privacy review.

## Operator use

Use logs for coarse debugging: route, status class, latency, response size, and
aborted requests. Use `/metricsz` counters for trend/alerting. Prefer metrics
over IP-bearing logs for routine overload and score-rate-limit analysis.
