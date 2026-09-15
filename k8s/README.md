# Reference Kubernetes manifests (legacy layout)

These mirror the original k0s deployment (namespace → storage → configmaps →
deployments → services → jobs) and are **reference only**. The v20 rebuild's
manifests are the `k8s/*.yaml` files alongside this README, driven by
`k8s/kustomization.yaml`.

Notes if you are adapting these:

- The schema (`weirvern/schema/*.sql`) ships inside the application package and
  is applied by `weirvern init-db`. Do NOT re-add a ConfigMap copy of the SQL,
  and do NOT re-add boot-time dependency installs (both were legacy failure
  modes: schema drift, and a container that broke whenever the network did).
- Persist `/models` and the ClickHouse data directory on PVCs.
- Keep the probes from the current manifests — they encode measured startup
  behaviour, not guesses.
