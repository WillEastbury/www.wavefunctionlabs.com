# Recovery manifests — 2026-05-16

picoweb's AF_XDP TLS server is currently misbehaving on this AKS
cluster (TCP SYN-ACKs from AF_XDP bypass conntrack so Azure LB
reverse-NAT loses replies — known issue, see stored memories). To
keep the site up while picoweb is debugged, we route the public
LoadBalancer `wfl-www` Service at a plain nginx TLS-terminator
deployment that proxies through to the still-working `wfl-www-legacy`
picoweb pod (which serves plaintext :80 with kernel sockets and is
unaffected by the AF_XDP issue).

## Topology

```
Azure LB (51.142.214.73:443)
        │
        ▼
Service wfl-www  ──selector──►  Deployment tls-terminator
                                  └─ nginx :443 (TLS) → proxy_pass
                                       http://wfl-www-legacy.wfl-www.svc:80
                                  └─ nginx :80 → 301 https://$host
                                                       │
                                                       ▼
                                            Service wfl-www-legacy
                                                       │
                                                       ▼
                                      Deployment wfl-www-legacy
                                        └─ picoweb v1arm (:80, kernel sockets)
```

## Files
- `tls-terminator-cm.yaml`  — nginx config (TLS term + :80 redirect)
- `tls-terminator-deploy.yaml` — nginx deployment (uses `wfl-www-tls` Secret)
- `wfl-www-svc.yaml` — wfl-www Service patched to select `app: tls-terminator`

## Re-applying after a cluster reset

```sh
kubectl apply -f k8s/recovery/tls-terminator-cm.yaml
kubectl apply -f k8s/recovery/tls-terminator-deploy.yaml
kubectl apply -f k8s/recovery/wfl-www-svc.yaml
```

## Restoring picoweb-on-AF_XDP

Once the AF_XDP/conntrack issue is solved upstream, scale
`tls-terminator` to 0 and revert the Service selector to
`app: wfl-www` (see `k8s/wfl-www.yaml`).

## Verifying

```sh
curl -sS -o /dev/null -w "%{http_code} %{time_total}\n" https://www.wavefunctionlabs.com/
# expect: 200 <1s
```

Playwright smoke test in `/tmp/pw/tests/site.spec.ts` validates title
and content render correctly.
