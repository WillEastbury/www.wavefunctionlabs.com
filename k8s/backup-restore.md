# picowal PVC backup and restore

The live score store is the `wfl-www-picowal` PVC mounted at `/data` in the
`wfl-www` container. Backups use a quiesce-and-snapshot flow: picoweb keeps
serving reads and static files, rejects new picowal writes, flushes the WAL,
then an operator takes a CSI/Azure `VolumeSnapshot` of the PVC.

Do not use `kubectl cp` as a production backup. It is not a block-level
snapshot and can miss filesystem/journal state. Use the CSI snapshot path.

## Backup

1. Select the current picoweb pod.

   ```sh
   POD=$(kubectl get pod -n wfl-www -l app=wfl-www \
     -o jsonpath='{.items[0].metadata.name}')
   ```

2. Quiesce picowal writes. `SIGUSR1` drains any in-flight picowal write under
   the storage mutex, runs `fdatasync()` on the WAL fd, fsyncs the parent
   directory, then marks writes as quiesced.

   ```sh
   kubectl exec -n wfl-www "$POD" -c wfl-www -- sh -c 'kill -USR1 1'
   ```

3. Wait for the pod-local readiness body to report quiesced writes. Kubernetes
   readiness remains HTTP 200 so the single-replica site continues serving
   static pages and read-only APIs during the snapshot.

   ```sh
   kubectl exec -n wfl-www "$POD" -c wfl-www -- \
     sh -c 'for i in $(seq 1 50); do
       body=$(wget -qO- --no-check-certificate https://127.0.0.1/readyz || true)
       echo "$body" | grep -q "\"writes\":\"quiesced\"" && exit 0
       sleep 0.1
     done
     exit 1'
   ```

4. Create a `VolumeSnapshot` for the PVC. Apply the Azure Disk snapshot
   classes once if the cluster does not already have them:

   ```sh
   kubectl apply -f k8s/azure-disk-snapshotclass.yaml
   ```

   Use `azure-disk-csi-snapshot-retain` for backup artifacts that must survive
   deletion of the Kubernetes `VolumeSnapshot` object. Use
   `azure-disk-csi-snapshot-delete` only for disposable drills.

   ```yaml
   apiVersion: snapshot.storage.k8s.io/v1
   kind: VolumeSnapshot
   metadata:
     name: wfl-www-picowal-YYYYMMDD-HHMM
     namespace: wfl-www
   spec:
     volumeSnapshotClassName: azure-disk-csi-snapshot-retain
     source:
       persistentVolumeClaimName: wfl-www-picowal
   ```

   ```sh
   kubectl apply -f snapshot.yaml
   kubectl wait -n wfl-www --for=jsonpath='{.status.readyToUse}'=true \
     volumesnapshot/wfl-www-picowal-YYYYMMDD-HHMM --timeout=120s
   ```

5. Resume writes.

   ```sh
   kubectl exec -n wfl-www "$POD" -c wfl-www -- sh -c 'kill -USR2 1'
   kubectl exec -n wfl-www "$POD" -c wfl-www -- \
     wget -qO- --no-check-certificate https://127.0.0.1/readyz
   ```

## Restore drill

Restore into a fresh PVC first; do not overwrite the live PVC in place.

The scripted drill writes a sentinel score record, quiesces the live pod, takes
a disposable snapshot, resumes writes, restores the snapshot to a fresh PVC,
starts an isolated picoweb pod that is not selected by the production Service,
and validates WAL recovery plus score readback:

```sh
kubectl apply -f k8s/azure-disk-snapshotclass.yaml
scripts/picowal-restore-drill.sh
```

To rehearse an existing retained backup artifact instead of taking a new
snapshot:

```sh
scripts/picowal-restore-drill.sh --snapshot-name wfl-www-picowal-YYYYMMDD-HHMM
```

The drill expects restored `/readyz` to report clean recovery with zero corrupt
records. `tail_truncated` is a failure for a quiesced snapshot; only use
`ALLOW_TAIL_TRUNCATED=1` when deliberately inspecting an unquiesced external
artifact. Set `KEEP_RESTORE=1` or pass `--keep` to leave the temporary pod/PVC
for manual inspection.

Expected RTO for the current 1Gi Azure Disk PVC is the elapsed time printed by
the drill: quiesce and snapshot readiness, restore PVC binding, restore pod
readiness, and validation. Use the latest successful drill output as the live
RTO expectation rather than a guessed number.

For cluster, region, or DNS cutover recovery, use
`k8s/disaster-recovery-dns.md`.

```yaml
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: wfl-www-picowal-restore
  namespace: wfl-www
spec:
  dataSource:
    name: wfl-www-picowal-YYYYMMDD-HHMM
    kind: VolumeSnapshot
    apiGroup: snapshot.storage.k8s.io
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 1Gi
```

Attach the restored PVC to a temporary picoweb pod using the same image and
`--picowal-device=/data/picowal.wal`, then verify:

```sh
curl -fsS https://<temporary-host>/readyz
curl -fsS https://<temporary-host>/api/scores
curl -ksS -o /dev/null -w '%{http_code}\n' https://<temporary-host>/wal/42
```

Expected results: `/readyz` reports `picowal=ready`, scores include records
from before the snapshot, and raw `/wal/*` remains `404`.

## Failure modes

- If picoweb restarts while quiesced, abort the snapshot and start over; quiesce
  state is intentionally process-local and a fresh process resumes writes.
- If quiesce fails, do not snapshot. Inspect the pod logs for the `fdatasync` or
  directory `fsync` error.
- If the snapshot does not become `readyToUse`, resume writes with `SIGUSR2`,
  delete the failed `VolumeSnapshot`, and retry later.
