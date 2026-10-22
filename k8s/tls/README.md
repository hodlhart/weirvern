# Local HTTPS edge

The console is a local management surface. This overlay terminates TLS at the
k3s Traefik that already owns host ports 80 and 443, and removes the plaintext
NodePort from the user path.

## Prerequisites

1. cert-manager is installed (the manifests use its `Certificate` and
   `ClusterIssuer` CRDs). The live deployment used v1.21.2:
   `kubectl apply -f https://github.com/cert-manager/cert-manager/releases/download/v1.21.2/cert-manager.yaml`
2. A two-tier internal CA exists. The root key stays offline; only the
   intermediate certificate and key are stored in the `weirvern-ca` TLS Secret
   in cert-manager's cluster-resource namespace.
3. `sensor.example` resolves to the node on the management network.

## Trust

Copy the root certificate to every managed client and install it in the OS or
browser trust store. The certificate's fingerprint is the identity of this CA;
publish it separately from this repository. Do not email a private key.

## Apply

```sh
kubectl apply -k k8s/tls
kubectl -n weirvern wait --for=condition=Ready certificate/weirvern-tls --timeout=120s
kubectl -n weirvern get ingress,certificate
```

## Verify

```sh
curl -I http://sensor.example                  # 308 to https://
curl --cacert root-ca.crt https://sensor.example/api/healthz
openssl s_client -connect sensor.example:443 -servername sensor.example </dev/null \
  | openssl x509 -noout -subject -issuer -ext subjectAltName
```

`sensor.example:30088` must no longer answer. If it does, the base Service was
re-applied after the overlay; re-apply this overlay.

## Rollback

Remove the two Ingress resources and the middlewares, then apply the base
Service again. That restores the plaintext NodePort for break-glass use. The
cert-manager Certificate and CA Secret can remain; they do not listen on a
port.
