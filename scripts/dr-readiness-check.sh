#!/usr/bin/env bash
set -euo pipefail

NAMESPACE="${NAMESPACE:-wfl-www}"
DEPLOYMENT="${DEPLOYMENT:-wfl-www}"
SERVICE="${SERVICE:-wfl-www}"
PVC="${PVC:-wfl-www-picowal}"
DNS_RESOURCE_GROUP="${DNS_RESOURCE_GROUP:-wavefunction}"
DNS_ZONE="${DNS_ZONE:-wavefunctionlabs.com}"
HOSTS="${HOSTS:-wavefunctionlabs.com www.wavefunctionlabs.com}"
SNAPSHOT_CLASS="${SNAPSHOT_CLASS:-azure-disk-csi-snapshot-retain}"
TMPDIR="${TMPDIR:-/tmp}"
METRICS="$TMPDIR/wfl-dr-metrics.$$"
trap 'rm -f "$METRICS"' EXIT

fail=0

check() {
    echo "ok: $*"
}

warn() {
    echo "warning: $*" >&2
}

crit() {
    fail=1
    echo "critical: $*" >&2
}

kubectl get deployment "$DEPLOYMENT" -n "$NAMESPACE" >/dev/null ||
    crit "deployment $NAMESPACE/$DEPLOYMENT missing"
kubectl get pvc "$PVC" -n "$NAMESPACE" >/dev/null ||
    crit "PVC $NAMESPACE/$PVC missing"
kubectl get volumesnapshotclass "$SNAPSHOT_CLASS" >/dev/null ||
    crit "snapshot class $SNAPSHOT_CLASS missing"

lb_ip=$(kubectl get service "$SERVICE" -n "$NAMESPACE" -o jsonpath='{.status.loadBalancer.ingress[0].ip}' 2>/dev/null || true)
if [ -z "$lb_ip" ]; then
    crit "service $NAMESPACE/$SERVICE has no LoadBalancer IP"
else
    check "service LoadBalancer IP is $lb_ip"
fi

for host in $HOSTS; do
    resolved=$(getent ahostsv4 "$host" | awk 'NR == 1 { print $1 }')
    if [ -z "$resolved" ]; then
        crit "$host does not resolve"
    elif [ -n "$lb_ip" ] && [ "$resolved" != "$lb_ip" ]; then
        crit "$host resolves to $resolved, expected $lb_ip"
    else
        check "$host resolves to $resolved"
    fi
done

if command -v az >/dev/null 2>&1; then
    az network dns zone show -g "$DNS_RESOURCE_GROUP" -n "$DNS_ZONE" >/dev/null ||
        crit "Azure DNS zone $DNS_RESOURCE_GROUP/$DNS_ZONE unavailable"
else
    warn "az unavailable; skipped Azure DNS zone check"
fi

cert_status=$(kubectl get certificate wfl-www-tls -n "$NAMESPACE" -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}' 2>/dev/null || true)
if [ "$cert_status" != "True" ]; then
    crit "certificate $NAMESPACE/wfl-www-tls is not Ready"
else
    check "certificate $NAMESPACE/wfl-www-tls is Ready"
fi

snapshot_count=$(kubectl get volumesnapshot -n "$NAMESPACE" \
    -o jsonpath='{range .items[?(@.spec.volumeSnapshotClassName=="azure-disk-csi-snapshot-retain")]}{.metadata.name}{"\n"}{end}' 2>/dev/null |
    wc -l | tr -d ' ')
if [ "$snapshot_count" -eq 0 ]; then
    warn "no retained VolumeSnapshot objects found in $NAMESPACE; confirm retained Azure snapshots out-of-band"
else
    check "$snapshot_count retained VolumeSnapshot object(s) found"
fi

if curl -fsS --max-time "${CURL_MAX_TIME:-10}" "https://wavefunctionlabs.com/metricsz" -o "$METRICS"; then
    grep -q '^picowal_recovery_status ' "$METRICS" || crit "picowal recovery metric missing"
    grep -q '^picowal_used_bytes ' "$METRICS" || crit "picowal capacity metric missing"
else
    crit "production /metricsz is unreachable"
fi

if [ "$fail" -ne 0 ]; then
    echo "DR readiness check failed" >&2
    exit 2
fi

echo "DR readiness check ok"
