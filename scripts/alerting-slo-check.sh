#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BASE_URL:-https://wavefunctionlabs.com}"
HOST="${HOST:-wavefunctionlabs.com}"
SAMPLE_SECONDS="${SAMPLE_SECONDS:-60}"
CURL_MAX_TIME="${CURL_MAX_TIME:-10}"
WARN_PCT="${WARN_PCT:-70}"
CRIT_PCT="${CRIT_PCT:-85}"
ACCEPT_DROP_CRIT_DELTA="${ACCEPT_DROP_CRIT_DELTA:-1}"
SCORE_RATE_LIMIT_WARN_DELTA="${SCORE_RATE_LIMIT_WARN_DELTA:-10}"
SCORE_RATE_LIMIT_CRIT_DELTA="${SCORE_RATE_LIMIT_CRIT_DELTA:-100}"
FIVEXX_CRIT_DELTA="${FIVEXX_CRIT_DELTA:-1}"
CERT_MIN_VALID_SECONDS="${CERT_MIN_VALID_SECONDS:-1209600}"
TMPDIR="${TMPDIR:-/tmp}"

READY_BODY="$TMPDIR/wfl-alert-ready.$$"
METRICS_A="$TMPDIR/wfl-alert-metrics-a.$$"
METRICS_B="$TMPDIR/wfl-alert-metrics-b.$$"
LIVE_CERT="$TMPDIR/wfl-alert-live-cert.$$"
trap 'rm -f "$READY_BODY" "$METRICS_A" "$METRICS_B" "$LIVE_CERT"' EXIT

warns=0
crits=0

warn() {
    warns=$((warns + 1))
    echo "warning: $*" >&2
}

crit() {
    crits=$((crits + 1))
    echo "critical: $*" >&2
}

url() {
    printf '%s%s' "${BASE_URL%/}" "$1"
}

metric_value() {
    local metric="$1"
    local file="$2"
    awk -v metric="$metric" '$1 == metric { print int($2); found=1 } END { if (!found) print 0 }' "$file"
}

metric_sum_matching() {
    local pattern="$1"
    local file="$2"
    awk -v pattern="$pattern" '$1 ~ pattern { sum += int($2) } END { print sum + 0 }' "$file"
}

counter_delta() {
    local metric="$1"
    local before after
    before=$(metric_value "$metric" "$METRICS_A")
    after=$(metric_value "$metric" "$METRICS_B")
    echo $((after - before))
}

curl -fsS --max-time "$CURL_MAX_TIME" "$(url /readyz)" -o "$READY_BODY" ||
    crit "/readyz is not reachable"
if [ -s "$READY_BODY" ]; then
    grep -q '"status":"ready"' "$READY_BODY" || crit "/readyz status is not ready"
    grep -q '"picowal":"ready"' "$READY_BODY" || crit "/readyz picowal is not ready"
fi

curl -fsS --max-time "$CURL_MAX_TIME" "$(url /metricsz)" -o "$METRICS_A" ||
    crit "/metricsz is not reachable"

if [ -s "$METRICS_A" ]; then
    recovery_status=$(metric_value "picowal_recovery_status" "$METRICS_A")
    corrupt_records=$(metric_value "picowal_recovery_corrupt_records" "$METRICS_A")
    truncated_records=$(metric_value "picowal_recovery_truncated_records" "$METRICS_A")
    if [ "$recovery_status" -gt 2 ]; then
        crit "picowal recovery status is $recovery_status"
    fi
    if [ "$corrupt_records" -gt 0 ]; then
        crit "picowal recovery reported $corrupt_records corrupt records"
    fi
    if [ "$truncated_records" -gt 0 ]; then
        warn "picowal recovery reported $truncated_records truncated records"
    fi

    used=$(metric_value "picowal_used_bytes" "$METRICS_A")
    free=$(metric_value "picowal_free_bytes" "$METRICS_A")
    total=$((used + free))
    if [ "$total" -le 0 ]; then
        crit "picowal capacity metrics are unavailable"
    else
        pct=$((used * 100 / total))
        if [ "$pct" -ge "$CRIT_PCT" ]; then
            crit "picowal usage ${pct}% >= ${CRIT_PCT}%"
        elif [ "$pct" -ge "$WARN_PCT" ]; then
            warn "picowal usage ${pct}% >= ${WARN_PCT}%"
        fi
    fi
fi

if command -v openssl >/dev/null 2>&1; then
    connect_host="${RESOLVE_IP:-$HOST}"
    if echo | openssl s_client -servername "$HOST" -connect "$connect_host:443" -showcerts 2>/dev/null |
        sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' > "$LIVE_CERT" &&
        [ -s "$LIVE_CERT" ]; then
        openssl x509 -in "$LIVE_CERT" -noout -checkend "$CERT_MIN_VALID_SECONDS" >/dev/null ||
            crit "TLS certificate expires within ${CERT_MIN_VALID_SECONDS}s"
    else
        crit "TLS certificate could not be fetched"
    fi
else
    warn "openssl is unavailable; skipped TLS expiry check"
fi

if [ "$SAMPLE_SECONDS" -gt 0 ] && [ -s "$METRICS_A" ]; then
    sleep "$SAMPLE_SECONDS"
    curl -fsS --max-time "$CURL_MAX_TIME" "$(url /metricsz)" -o "$METRICS_B" ||
        crit "/metricsz second sample is not reachable"
fi

if [ -s "$METRICS_B" ]; then
    pool_drop_delta=$(counter_delta 'picoweb_accept_drops_total{reason="pool_exhausted"}')
    fd_drop_delta=$(counter_delta 'picoweb_accept_drops_total{reason="fd_limit"}')
    score_rl_delta=$(counter_delta 'picoweb_score_rejects_total{reason="rate_limited"}')
    fivexx_before=$(metric_sum_matching '^picoweb_request_status_total\{.*class="5xx".*\}$' "$METRICS_A")
    fivexx_after=$(metric_sum_matching '^picoweb_request_status_total\{.*class="5xx".*\}$' "$METRICS_B")
    fivexx_delta=$((fivexx_after - fivexx_before))

    if [ "$pool_drop_delta" -ge "$ACCEPT_DROP_CRIT_DELTA" ]; then
        crit "accepted connection pool exhausted by ${pool_drop_delta} over ${SAMPLE_SECONDS}s"
    fi
    if [ "$fd_drop_delta" -ge "$ACCEPT_DROP_CRIT_DELTA" ]; then
        crit "fd-limit accept failures increased by ${fd_drop_delta} over ${SAMPLE_SECONDS}s"
    fi
    if [ "$fivexx_delta" -ge "$FIVEXX_CRIT_DELTA" ]; then
        crit "5xx responses increased by ${fivexx_delta} over ${SAMPLE_SECONDS}s"
    fi
    if [ "$score_rl_delta" -ge "$SCORE_RATE_LIMIT_CRIT_DELTA" ]; then
        crit "score rate-limit rejects increased by ${score_rl_delta} over ${SAMPLE_SECONDS}s"
    elif [ "$score_rl_delta" -ge "$SCORE_RATE_LIMIT_WARN_DELTA" ]; then
        warn "score rate-limit rejects increased by ${score_rl_delta} over ${SAMPLE_SECONDS}s"
    fi
fi

if command -v kubectl >/dev/null 2>&1 && kubectl get namespace wfl-www >/dev/null 2>&1; then
    unavailable=$(kubectl get deployment wfl-www -n wfl-www -o jsonpath='{.status.unavailableReplicas}' 2>/dev/null || true)
    [ -z "$unavailable" ] || [ "$unavailable" = "0" ] || crit "wfl-www has $unavailable unavailable replicas"
    restarts=$(kubectl get pods -n wfl-www -l app=wfl-www \
        -o jsonpath='{range .items[*]}{range .status.containerStatuses[*]}{.restartCount}{"\n"}{end}{end}' 2>/dev/null |
        awk '{ sum += int($1) } END { print sum + 0 }')
    [ "$restarts" -eq 0 ] || warn "wfl-www pod containers have $restarts cumulative restarts"
fi

if [ "$crits" -gt 0 ]; then
    echo "alerting SLO check failed: $crits critical, $warns warnings" >&2
    exit 2
fi
if [ "$warns" -gt 0 ]; then
    echo "alerting SLO check warning: $warns warnings" >&2
    exit 1
fi

echo "alerting SLO check ok: $BASE_URL"
