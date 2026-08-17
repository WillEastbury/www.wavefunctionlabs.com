---
name: wfl-blog-post-creation
description: Create, publish, and deploy WaveFunction Labs engineering blog posts without overwriting existing articles.
---

# WaveFunction Labs blog post creation

Use this skill when creating or publishing an engineering article for
WaveFunction Labs.

## Content and placement

- Add each article as a new clean-URL page under
  `wwwroot/wavefunctionlabs.com/_pages/<section>/<slug>/index.html`.
- Use `broadcast` for public engineering articles unless the user specifies a
  more appropriate section.
- Follow the existing static markup patterns:
  `wf-section`, `wf-back`, `wf-section-hdr`, `wf-section-desc`, and
  `wf-article-body`.
- Add a tile linking to the new article in the section index.
- Never replace or remove an existing article or job post to make room for a
  new one.
- Do not publish subscription IDs, credentials, API keys, tokens, or other
  secrets in article content.

## Implementation workflow

1. Inspect the section index and at least one existing article before editing.
2. Choose a stable, lowercase, hyphen-separated slug.
3. Add the article page and section-index tile as an additive change.
4. Run `git diff --check` and verify both the new route and preserved existing
   routes.
5. Commit with a descriptive message and include:
   `Co-authored-by: Copilot <223556219+Copilot@users.noreply.github.com>`.
6. Push the commit to `main`.

## Production publication

The site is static content packaged into the picoweb ARM64 image. For an
explicitly requested production publication:

```sh
TAG="pNN-article-slug-$(date +%H%M)"
az acr build --registry tileforgeacr \
  --image "wfl-www:${TAG}" \
  --platform linux/arm64 \
  --file Dockerfile .
```

Update the `wfl-www` image in `k8s/wfl-www.yaml`, commit and push that manifest
change, then deploy:

```sh
kubectl apply -f k8s/ingress-nginx-security.yaml
kubectl apply -f k8s/wfl-www.yaml
kubectl rollout status deployment/wfl-www -n wfl-www --timeout=180s
```

After rollout, verify the new URL and at least one preserved existing URL with
HTTP requests. Run `scripts/release-gate.sh` when a Bash environment with
`kubectl` and `curl` is available. Do not claim production publication until
the rollout succeeds and the live URL responds.
