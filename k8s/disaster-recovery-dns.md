# Disaster recovery and DNS cutover

This runbook covers rebuilding the public site when the AKS node, PVC, cluster,
or region is lost. Picoweb must remain the direct TLS listener on `:443`; do not
place nginx, Envoy, or another TLS terminator in front as a recovery shortcut.

## Current production facts

- Kubernetes context: `picowal-cluster`
- Namespace: `wfl-www`
- Deployment/container: `wfl-www` / `wfl-www`
- Service: `wfl-www` LoadBalancer on ports `443` and `80`
- Current public IP: `51.142.214.73`
- DNS zone: `wavefunctionlabs.com` in resource group `wavefunction`
- Hostnames: `wavefunctionlabs.com`, `www.wavefunctionlabs.com`
- TLS Secret: `wfl-www-tls`, issued by `letsencrypt-prod-dns01`
- Storage: `wfl-www-picowal` PVC, mounted at `/data/picowal.wal`
- Backup primitive: quiesced Azure Disk CSI `VolumeSnapshot`

Run the current-state check before and after any recovery rehearsal:

```sh
scripts/dr-readiness-check.sh
```

## Recovery inputs

Before starting, identify:

1. The target cluster/resource group and whether it can access
   `tileforgeacr.azurecr.io`.
2. The image tag/digest to run. Use `docs/image-provenance.md` and prefer the
   last known-good unique tag.
3. The WAL source: latest successful retained `VolumeSnapshot`, exported disk,
   or externally preserved Azure snapshot.
4. DNS authority for the `wavefunctionlabs.com` zone.
5. cert-manager DNS-01 readiness for `letsencrypt-prod-dns01`.

If the WAL source is unquiesced, restore to an isolated pod first and inspect
recovery. Do not promote `tail_truncated` or `corrupt` recovery to production.

## Same-cluster PVC/node recovery

Use this when the cluster and Azure Disk snapshots still exist.

1. Restore the snapshot into a fresh PVC and validate it first:

   ```sh
   scripts/picowal-restore-drill.sh --snapshot-name wfl-www-picowal-YYYYMMDD-HHMM --keep
   ```

2. Scale down or delete the failed production pod so no process owns the old
   WAL.
3. Update `k8s/wfl-www.yaml` to reference the restored PVC name only after the
   isolated restore pod reports clean `/readyz` and expected `/api/scores`.
4. Apply and wait:

   ```sh
   kubectl apply -f k8s/wfl-www.yaml
   kubectl rollout status deployment/wfl-www -n wfl-www --timeout=180s
   ```

5. Run:

   ```sh
   scripts/release-smoke.sh
   scripts/alerting-slo-check.sh
   scripts/dr-readiness-check.sh
   ```

## New-cluster or region recovery

Use this when the original cluster is unavailable.

1. Create or select an AKS cluster with arm64 capacity and access to the private
   ACR. Preserve the two-node cost limit unless explicitly approved.
2. Install/verify cert-manager, the Azure DNS-01 ClusterIssuer
   `letsencrypt-prod-dns01`, and the Azure Disk CSI snapshot CRDs/classes.
3. Create namespace and prerequisites:

   ```sh
   kubectl create namespace wfl-www
   kubectl apply -f k8s/azure-disk-snapshotclass.yaml
   ```

4. Recreate the score-token Secret from the protected secret store; never commit
   token keys to git.
5. Restore the selected WAL snapshot into a new `wfl-www-picowal` PVC, then run
   the isolated restore validation from `k8s/backup-restore.md`.
6. Apply `k8s/wfl-www.yaml` with the selected known-good image tag.
7. Wait for the new LoadBalancer IP:

   ```sh
   kubectl get service wfl-www -n wfl-www -w
   ```

8. Confirm cert-manager issues `wfl-www-tls` via DNS-01. The pod mounts
   `/certs/tls.crt` and `/certs/tls.key`; picoweb reads them at startup.
9. Smoke the new endpoint before DNS cutover:

   ```sh
   RESOLVE_IP=<new-lb-ip> scripts/release-smoke.sh
   RESOLVE_IP=<new-lb-ip> scripts/alerting-slo-check.sh
   ```

10. Update Azure DNS A records for `@` and `www` to the new LoadBalancer IP:

    ```sh
    az network dns record-set a update -g wavefunction -z wavefunctionlabs.com -n @ --set ttl=60
    az network dns record-set a update -g wavefunction -z wavefunctionlabs.com -n www --set ttl=60
    az network dns record-set a remove-record -g wavefunction -z wavefunctionlabs.com -n @ -a <old-lb-ip>
    az network dns record-set a remove-record -g wavefunction -z wavefunctionlabs.com -n www -a <old-lb-ip>
    az network dns record-set a add-record -g wavefunction -z wavefunctionlabs.com -n @ -a <new-lb-ip>
    az network dns record-set a add-record -g wavefunction -z wavefunctionlabs.com -n www -a <new-lb-ip>
    ```

11. Verify public DNS and the live site:

    ```sh
    getent ahostsv4 wavefunctionlabs.com
    getent ahostsv4 www.wavefunctionlabs.com
    scripts/release-smoke.sh
    scripts/dr-readiness-check.sh
    ```

## Expected downtime

Same-cluster restore should fit within the latest successful restore drill RTO
plus rollout time. New-cluster/region recovery is bounded by cluster readiness,
snapshot transfer/restore, cert issuance, and DNS TTL; record observed times in
the incident notes and update this runbook after a full rehearsal.
