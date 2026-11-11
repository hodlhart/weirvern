#!/bin/sh
# Bounded canary rehearsal for the GUI image. It copies the running configuration into a
# throwaway namespace, starts ONE pod, waits for readiness, reads /api/healthz from inside the
# pod, and deletes the namespace on every exit path. No Service, no Ingress, no writes.
#
# WHY A POD AND NOT A SECOND DEPLOYMENT: a single node has no separate failure domain, so the
# only honest canary is a bounded copy that cannot receive production traffic. It proves the
# image starts with the shipped configuration and answers its own health probe before the
# operator promotes it.
set -eu

IMAGE=${1:?usage: canary_rehearsal.sh <image:tag>}
NS=${CANARY_NS:-weirvern-canary}
SRC_NS=${SRC_NS:-weirvern}
NAME=gui-canary
TMP=$(mktemp -d)
trap 'kubectl delete namespace "$NS" --ignore-not-found --wait=false >/dev/null 2>&1 || true; rm -rf "$TMP"' EXIT INT TERM

cleanup_on_fail() {
    echo "--- canary logs ---" >&2
    kubectl -n "$NS" logs "pod/$NAME" --tail=80 >&2 2>/dev/null || true
    exit 1
}

echo "=== canary: $IMAGE in namespace $NS ==="
# A prior unsuccessful run may still be terminating; create only after it is gone, otherwise the
# copied ConfigMap races the namespace deletion.
kubectl delete namespace "$NS" --ignore-not-found --wait=true >/dev/null 2>&1 || true
kubectl create namespace "$NS"

for cm in weirvern-env weirvern-users; do
    kubectl -n "$SRC_NS" get configmap "$cm" -o yaml \
        | sed "s/namespace: $SRC_NS/namespace: $NS/" \
        | kubectl apply -f - >/dev/null
done
kubectl -n "$SRC_NS" get secret weirvern-secrets -o yaml \
    | sed "s/namespace: $SRC_NS/namespace: $NS/" \
    | kubectl apply -f - >/dev/null

kubectl apply -f - >/dev/null <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: $NAME
  namespace: $NS
  labels:
    app.kubernetes.io/name: weirvern-gui-canary
spec:
  containers:
    - name: gui
      image: $IMAGE
      imagePullPolicy: IfNotPresent
      command: ["python", "-m", "weirvern.admin.cli", "gui"]
      ports:
        - containerPort: 8088
      env:
        # The canary is in its own namespace, so the service short name cannot resolve. Name
        # the production Service explicitly; this is configuration, not a second deployment.
        - name: CLICKHOUSE_HOST
          value: clickhouse.weirvern.svc.cluster.local
        - name: GUI_HOST
          value: "0.0.0.0"
        - name: GUI_PORT
          value: "8088"
      envFrom:
        - configMapRef:
            name: weirvern-env
        - secretRef:
            name: weirvern-secrets
      readinessProbe:
        httpGet:
          path: /api/healthz
          port: 8088
        initialDelaySeconds: 3
        periodSeconds: 3
        failureThreshold: 10
EOF

kubectl -n "$NS" wait --for=condition=Ready "pod/$NAME" --timeout=90s || cleanup_on_fail
kubectl -n "$NS" exec "$NAME" -- python -c \
    "import urllib.request, sys; r=urllib.request.urlopen('http://127.0.0.1:8088/api/healthz', timeout=5); sys.exit(0 if r.status==200 else 1)" \
    || cleanup_on_fail

echo "CANARY PASS: $IMAGE started with the shipped config and answered /api/healthz"
