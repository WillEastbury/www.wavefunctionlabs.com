# Alerting and SLO runbook

Picoweb owns the production TLS listener directly on `:443`. Alerts should
drive picoweb or storage fixes; do not insert a reverse proxy or TLS terminator
to hide failures.

## Service objectives

| Objective | Target | Signal |
| --- | --- | --- |
| Public HTTPS availability | 99.9% monthly | `GET /readyz` returns `{"status":"ready"}` |
| Picowal writable storage | 99.9% monthly | `/readyz` reports `picowal=ready`; write APIs avoid sustained `5xx`/`507` |
| Recovery integrity | 100% clean production starts | `picowal_recovery_status <= 2` and zero corrupt records |
| WAL headroom | Warning before exhaustion | `picowal_used_bytes / (used + free) < 70%` |
| Overload visibility | No silent drops | `picoweb_accept_drops_total` does not increase |
| TLS validity | At least 14 days remaining | live certificate passes `openssl x509 -checkend 1209600` |

## One-shot check

Run this from an operator shell or a scheduled job:

```sh
scripts/alerting-slo-check.sh
```

Useful knobs:

```sh
SAMPLE_SECONDS=300 WARN_PCT=70 CRIT_PCT=85 scripts/alerting-slo-check.sh
```

Exit codes are Nagios-compatible: `0` ok, `1` warning, `2` critical.

## Prometheus-style alert queries

Use these if `/metricsz` is scraped by Prometheus or a compatible system.

```promql
up{job="wfl-www"} == 0
```

Critical: metrics scraping failed for 2 minutes.

```promql
picowal_recovery_status > 2
or picowal_recovery_corrupt_records > 0
```

Critical: picowal did not recover cleanly. Follow `k8s/backup-restore.md` and
do not write new data until the recovery state is understood.

```promql
picowal_used_bytes / (picowal_used_bytes + picowal_free_bytes) > 0.85
```

Critical: bounded WAL is close to full. Follow `k8s/picowal-capacity.md`.
Warn at `> 0.70`.

```promql
increase(picoweb_accept_drops_total[5m]) > 0
```

Critical: the preallocated accept pool or process fd limit is rejecting accepted
connections. Follow `k8s/overload-abuse.md`.

```promql
increase(picoweb_request_status_total{class="5xx"}[5m]) > 0
```

Critical: users are seeing server errors. Check recent rollout, picowal health,
and pod logs.

```promql
increase(picoweb_score_rejects_total{reason="rate_limited"}[5m]) > 100
```

Warning: score writes are being rate-limited heavily. Inspect abuse patterns
before raising limits.

```promql
kube_deployment_status_replicas_unavailable{namespace="wfl-www",deployment="wfl-www"} > 0
or increase(kube_pod_container_status_restarts_total{namespace="wfl-www",pod=~"wfl-www-.*"}[15m]) > 0
```

Critical: production pod is unavailable or restarting.

```promql
probe_ssl_earliest_cert_expiry{instance="wavefunctionlabs.com:443"} - time() < 1209600
```

Critical: live TLS certificate expires in less than 14 days. Use
`scripts/cert-rotation-check.sh --restart-if-needed` after cert-manager updates
the Secret.

## First response

1. Run `scripts/release-smoke.sh` to separate user-visible outage from a stale
   alert.
2. Run `scripts/alerting-slo-check.sh` and keep its output with the incident
   notes.
3. If the issue started after a rollout, roll back to the last known-good unique
   image tag with `scripts/rollback-image.sh`.
4. If picowal recovery or capacity is involved, follow `k8s/backup-restore.md`
   or `k8s/picowal-capacity.md` before changing traffic.
5. If overload counters are increasing, follow `k8s/overload-abuse.md`; do not
   add a proxy to absorb symptoms.
