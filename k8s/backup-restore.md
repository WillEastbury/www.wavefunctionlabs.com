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

4. Create a `VolumeSnapshot` for the PVC. Use the cluster's Azure Disk CSI
   `VolumeSnapshotClass` name.

   ```yaml
   apiVersion: snapshot.storage.k8s.io/v1
   kind: VolumeSnapshot
   metadata:
     name: wfl-www-picowal-YYYYMMDD-HHMM
     namespace: wfl-www
   spec:
     volumeSnapshotClassName: <azure-disk-snapshot-class>
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

## Restore smoke

Restore into a fresh PVC first; do not overwrite the live PVC in place.

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
