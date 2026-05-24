#!/usr/bin/env bash
set -euo pipefail

NAMESPACE="${NAMESPACE:-wfl-www}"
DEPLOYMENT="${DEPLOYMENT:-wfl-www}"
SOURCE_PVC="${SOURCE_PVC:-wfl-www-picowal}"
SNAPSHOT_CLASS="${SNAPSHOT_CLASS:-azure-disk-csi-snapshot-delete}"
RESTORE_TIMEOUT="${RESTORE_TIMEOUT:-180s}"
DRILL_NAME="${DRILL_NAME:-picowal-restore-$(date +%Y%m%d-%H%M%S)}"
SNAPSHOT_NAME=""
KEEP_RESTORE="${KEEP_RESTORE:-0}"
ALLOW_TAIL_TRUNCATED="${ALLOW_TAIL_TRUNCATED:-0}"
SENTINEL_SCORE="${SENTINEL_SCORE:-1000000000}"

usage() {
    cat >&2 <<EOF
usage: $0 [--snapshot-name NAME] [--keep]

Runs a picowal restore drill in Kubernetes:
  - without --snapshot-name, writes a sentinel score, quiesces picoweb,
    snapshots $SOURCE_PVC, resumes writes, and restores the snapshot
  - with --snapshot-name, restores and validates an existing VolumeSnapshot

Environment:
  NAMESPACE=$NAMESPACE
  DEPLOYMENT=$DEPLOYMENT
  SOURCE_PVC=$SOURCE_PVC
  SNAPSHOT_CLASS=$SNAPSHOT_CLASS
  KEEP_RESTORE=$KEEP_RESTORE
  ALLOW_TAIL_TRUNCATED=$ALLOW_TAIL_TRUNCATED
  SENTINEL_SCORE=$SENTINEL_SCORE
EOF
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --snapshot-name)
            SNAPSHOT_NAME="${2:-}"
            [ -n "$SNAPSHOT_NAME" ] || { usage; exit 2; }
            shift 2
            ;;
        --keep)
            KEEP_RESTORE=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            usage
            exit 2
            ;;
    esac
done

require() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "missing required command: $1" >&2
        exit 2
    }
}

require kubectl
require curl

RESTORE_PVC="$DRILL_NAME-pvc"
RESTORE_POD="$DRILL_NAME-pod"
RESTORE_LABEL="picowal-restore-drill-$DRILL_NAME"
CREATED_SNAPSHOT=0
CREATED_PVC=0
CREATED_POD=0
QUIESCED=0
SENTINEL_NAME=""
START_TS=$(date +%s)

elapsed() {
    now=$(date +%s)
    printf '%ss' "$((now - START_TS))"
}

source_pod() {
    kubectl get pod -n "$NAMESPACE" -l "app=$DEPLOYMENT" \
        -o jsonpath='{.items[0].metadata.name}'
}

resume_writes() {
    if [ "$QUIESCED" != "1" ]; then
        return 0
    fi
    pod="$(source_pod 2>/dev/null || true)"
    if [ -n "$pod" ]; then
        kubectl exec -n "$NAMESPACE" "$pod" -c "$DEPLOYMENT" -- sh -c 'kill -USR2 1' >/dev/null 2>&1 || true
    fi
    QUIESCED=0
}

cleanup() {
    rc=$?
    resume_writes
    if [ "$KEEP_RESTORE" != "1" ]; then
        if [ "$CREATED_POD" = "1" ]; then
            kubectl delete pod "$RESTORE_POD" -n "$NAMESPACE" --ignore-not-found --wait=false >/dev/null 2>&1 || true
        fi
        if [ "$CREATED_PVC" = "1" ]; then
            kubectl delete pvc "$RESTORE_PVC" -n "$NAMESPACE" --ignore-not-found >/dev/null 2>&1 || true
        fi
        if [ "$CREATED_SNAPSHOT" = "1" ]; then
            kubectl delete volumesnapshot "$SNAPSHOT_NAME" -n "$NAMESPACE" --ignore-not-found >/dev/null 2>&1 || true
        fi
    else
        echo "keeping restore artifacts: snapshot=$SNAPSHOT_NAME pvc=$RESTORE_PVC pod=$RESTORE_POD" >&2
    fi
    exit "$rc"
}
trap cleanup EXIT INT TERM

json_get() {
    kubectl get "$1" "$2" -n "$NAMESPACE" -o "jsonpath=$3"
}

wait_ready_body() {
    local pod="$1"
    local want="$2"
    for _ in $(seq 1 80); do
        body=$(kubectl exec -n "$NAMESPACE" "$pod" -c "$DEPLOYMENT" -- \
            sh -c 'wget -qO- --no-check-certificate https://127.0.0.1/readyz' 2>/dev/null || true)
        if printf '%s' "$body" | grep -q "$want"; then
            printf '%s\n' "$body"
            return 0
        fi
        sleep 0.25
    done
    echo "timed out waiting for $pod /readyz to contain $want" >&2
    return 1
}

score_token() {
    curl -fsS --max-time 10 -X POST https://wavefunctionlabs.com/api/scores/start |
        sed -n 's/.*"token":"\([^"]*\)".*/\1/p'
}

write_sentinel_score() {
    SENTINEL_NAME="RDrill-$(date +%s)"
    token="$(score_token)"
    [ -n "$token" ] || { echo "failed to issue score token" >&2; exit 1; }
    curl -fsS --max-time 10 \
        -H 'Content-Type: application/json' \
        -H "X-Score-Token: $token" \
        -d "{\"name\":\"$SENTINEL_NAME\",\"score\":$SENTINEL_SCORE}" \
        https://wavefunctionlabs.com/api/scores >/dev/null
    echo "sentinel score written: $SENTINEL_NAME ($(elapsed))"
}

preflight() {
    kubectl get crd volumesnapshots.snapshot.storage.k8s.io >/dev/null
    kubectl get volumesnapshotclass "$SNAPSHOT_CLASS" >/dev/null
    kubectl get pvc "$SOURCE_PVC" -n "$NAMESPACE" >/dev/null
    kubectl get deployment "$DEPLOYMENT" -n "$NAMESPACE" >/dev/null
}

create_snapshot() {
    local pod
    pod="$(source_pod)"
    [ -n "$pod" ] || { echo "no source pod found for app=$DEPLOYMENT" >&2; exit 1; }

    write_sentinel_score

    kubectl exec -n "$NAMESPACE" "$pod" -c "$DEPLOYMENT" -- sh -c 'kill -USR1 1'
    QUIESCED=1
    wait_ready_body "$pod" '"writes":"quiesced"' >/dev/null
    echo "source quiesced ($(elapsed))"

    SNAPSHOT_NAME="$DRILL_NAME-snapshot"
    cat <<EOF | kubectl apply -f -
apiVersion: snapshot.storage.k8s.io/v1
kind: VolumeSnapshot
metadata:
  name: $SNAPSHOT_NAME
  namespace: $NAMESPACE
  labels:
    app: picowal-restore-drill
    drill: $DRILL_NAME
spec:
  volumeSnapshotClassName: $SNAPSHOT_CLASS
  source:
    persistentVolumeClaimName: $SOURCE_PVC
EOF
    CREATED_SNAPSHOT=1
    kubectl wait -n "$NAMESPACE" --for=jsonpath='{.status.readyToUse}'=true \
        "volumesnapshot/$SNAPSHOT_NAME" --timeout="$RESTORE_TIMEOUT"
    echo "snapshot ready: $SNAPSHOT_NAME ($(elapsed))"
    resume_writes
    echo "source writes resumed ($(elapsed))"
}

create_restore_pvc() {
    size="$(json_get pvc "$SOURCE_PVC" '{.spec.resources.requests.storage}')"
    storage_class="$(json_get pvc "$SOURCE_PVC" '{.spec.storageClassName}')"
    storage_class_block=""
    if [ -n "$storage_class" ]; then
        storage_class_block="  storageClassName: $storage_class"
    fi
    cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: $RESTORE_PVC
  namespace: $NAMESPACE
  labels:
    app: picowal-restore-drill
    drill: $DRILL_NAME
spec:
$storage_class_block
  dataSource:
    name: $SNAPSHOT_NAME
    kind: VolumeSnapshot
    apiGroup: snapshot.storage.k8s.io
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: $size
EOF
    CREATED_PVC=1
    echo "restore pvc created: $RESTORE_PVC ($(elapsed))"
}

create_restore_pod() {
    image="$(kubectl get deployment "$DEPLOYMENT" -n "$NAMESPACE" \
        -o jsonpath='{.spec.template.spec.containers[?(@.name=="wfl-www")].image}')"
    [ -n "$image" ] || { echo "failed to discover $DEPLOYMENT image" >&2; exit 1; }
    cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: $RESTORE_POD
  namespace: $NAMESPACE
  labels:
    app: picowal-restore-drill
    drill: $RESTORE_LABEL
spec:
  restartPolicy: Never
  tolerations:
    - key: dedicated
      operator: Equal
      value: server
      effect: NoSchedule
  nodeSelector:
    role: server
  securityContext:
    runAsNonRoot: true
    runAsUser: 65532
    runAsGroup: 65532
    fsGroup: 65532
    fsGroupChangePolicy: OnRootMismatch
    seccompProfile:
      type: RuntimeDefault
  containers:
    - name: $DEPLOYMENT
      image: $image
      imagePullPolicy: IfNotPresent
      env:
        - name: PICOWEB_SCORE_TOKEN_KEYS_HEX
          valueFrom:
            secretKeyRef:
              name: wfl-score-token-keys
              key: keys_hex
      command: ["./picoweb"]
      args:
        - "--tls"
        - "--tls-cert=/certs/tls.crt"
        - "--tls-key=/certs/tls.key"
        - "--http-early-hints"
        - "--picowal-device=/data/picowal.wal"
        - "--picowal-prefix=/wal/"
        - "--picowal-bytes=10485760"
        - "443"
        - "wwwroot"
        - "1"
        - "100"
        - "0"
        - "64"
      securityContext:
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        capabilities:
          drop: ["ALL"]
          add: ["NET_BIND_SERVICE", "IPC_LOCK"]
      volumeMounts:
        - name: tls-certs
          mountPath: /certs
          readOnly: true
        - name: tmp
          mountPath: /tmp
        - name: picowal-data
          mountPath: /data
  volumes:
    - name: tls-certs
      secret:
        secretName: wfl-www-tls
    - name: tmp
      emptyDir: {}
    - name: picowal-data
      persistentVolumeClaim:
        claimName: $RESTORE_PVC
EOF
    CREATED_POD=1
    kubectl wait -n "$NAMESPACE" --for=jsonpath='{.status.phase}'=Bound \
        "pvc/$RESTORE_PVC" --timeout="$RESTORE_TIMEOUT"
    echo "restore pvc bound: $RESTORE_PVC ($(elapsed))"
    kubectl wait -n "$NAMESPACE" --for=condition=Ready "pod/$RESTORE_POD" --timeout="$RESTORE_TIMEOUT"
    echo "restore pod ready: $RESTORE_POD ($(elapsed))"

    pod_ip="$(json_get pod "$RESTORE_POD" '{.status.podIP}')"
    if kubectl get endpoints "$DEPLOYMENT" -n "$NAMESPACE" \
        -o jsonpath='{range .subsets[*].addresses[*]}{.ip}{"\n"}{end}' | grep -Fxq "$pod_ip"; then
        echo "restore pod $RESTORE_POD is present in production Service endpoints" >&2
        exit 1
    fi
}

validate_restore() {
    ready="$(wait_ready_body "$RESTORE_POD" '"status":"ready"')"
    printf '%s' "$ready" | grep -q '"picowal":"ready"'
    if [ "$ALLOW_TAIL_TRUNCATED" = "1" ]; then
        printf '%s' "$ready" | grep -Eq '"status":"(clean|tail_truncated)"'
    else
        printf '%s' "$ready" | grep -q '"status":"clean"'
    fi
    printf '%s' "$ready" | grep -q '"corrupt_records":0'

    scores=$(kubectl exec -n "$NAMESPACE" "$RESTORE_POD" -c "$DEPLOYMENT" -- \
        sh -c 'wget -qO- --header="Host: wavefunctionlabs.com" --no-check-certificate https://127.0.0.1/api/scores')
    printf '%s' "$scores" | grep -q '"name"'
    if [ -n "$SENTINEL_NAME" ]; then
        printf '%s' "$scores" | grep -q "\"name\":\"$SENTINEL_NAME\""
    fi

    code=$(kubectl exec -n "$NAMESPACE" "$RESTORE_POD" -c "$DEPLOYMENT" -- \
        sh -c 'wget -qO- --server-response --header="Host: wavefunctionlabs.com" --no-check-certificate https://127.0.0.1/wal/42 2>&1 | sed -n "s/  HTTP\\/.* \\([0-9][0-9][0-9]\\).*/\\1/p" | tail -1')
    [ "$code" = "404" ] || { echo "expected restored /wal/42 to be 404, got $code" >&2; exit 1; }

    metrics=$(kubectl exec -n "$NAMESPACE" "$RESTORE_POD" -c "$DEPLOYMENT" -- \
        sh -c 'wget -qO- --header="Host: wavefunctionlabs.com" --no-check-certificate https://127.0.0.1/metricsz')
    printf '%s' "$metrics" | grep -q '^picowal_recovery_status '
    echo "restore validation ok ($(elapsed))"
}

preflight
if [ -z "$SNAPSHOT_NAME" ]; then
    create_snapshot
else
    echo "using existing snapshot: $SNAPSHOT_NAME"
fi
create_restore_pvc
create_restore_pod
validate_restore
echo "picowal restore drill ok: snapshot=$SNAPSHOT_NAME pvc=$RESTORE_PVC pod=$RESTORE_POD elapsed=$(elapsed)"
