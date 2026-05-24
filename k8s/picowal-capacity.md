# Picowal capacity and compaction policy

The production WAL is deliberately bounded by picoweb's
`--picowal-bytes=10485760` setting. When the append-only WAL reaches that cap,
new picowal writes fail with HTTP `507 Insufficient Storage`; static pages and
read-only APIs continue serving.

## Signals

Picoweb exposes current logical WAL capacity in `/metricsz`:

```text
picowal_used_bytes
picowal_free_bytes
```

Run the operator check manually or from a monitor:

```sh
scripts/picowal-capacity-check.sh
```

Defaults are warning at 70% and critical at 85%. Override with `WARN_PCT` and
`CRIT_PCT` if the alerting system has different thresholds.

## Operator actions

1. At warning: run `scripts/picowal-restore-drill.sh` so the latest snapshot
   path is known-good before any storage intervention.
2. At critical: quiesce and snapshot with `k8s/backup-restore.md`, then either
   deploy a larger `--picowal-bytes` setting or rebuild a compacted WAL from an
   exported score set in a staging pod.
3. Do not truncate or edit `/data/picowal.wal` in place. The WAL is the source
   of truth; in-place edits can invalidate recovery checksums and make the next
   startup fail closed.

Online compaction is intentionally not enabled yet. The safe compaction path is
offline: snapshot, restore into an isolated pod, export the application-level
records that should be retained, create a fresh WAL, import those records, run
the restore drill, then roll the production deployment to the compacted PVC.
