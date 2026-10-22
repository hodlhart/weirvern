#!/bin/sh
# bootstrap-mtls.sh -- make the hub's mTLS ingest edge the DEFAULT, with no operator PKI work.
#
# WHAT IT CREATES, ONCE:
#   weirling-root       Secret (weirvern ns)  root-ca.crt -- the one trust anchor sensors get
#   weirling-ca         Secret (weirvern ns)  intermediate cert/key used to sign sensor leaves
#   weirling-ingest-tls Secret (weirvern ns)  server leaf + intermediate chain for the gateway
#
# The root private key is generated, used to sign the intermediate, and discarded. Sensors
# never receive a CA private key; the gateway holds only the intermediate. If the CA secrets
# already exist, they are LEFT ALONE -- re-running an installer must not invalidate every
# enrolled sensor. Only a missing or near-expiry server certificate is replaced.
#
# This deliberately does not require cert-manager. cert-manager remains a supported optional
# path (k8s/mtls/certificate.yaml), but a fresh deployment must not fail because an add-on was
# not installed before the operator knew it was needed.
set -eu

NAMESPACE="${WEIRVERN_NAMESPACE:-weirvern}"
HOST="${WEIRVERN_GATEWAY_HOST:-$(hostname -f 2>/dev/null || hostname)}"
DAYS_SERVER="${WEIRVERN_SERVER_CERT_DAYS:-825}"
DAYS_CA="${WEIRVERN_CA_CERT_DAYS:-3650}"

die() { printf 'bootstrap-mtls: %s\n' "$*" >&2; exit 1; }
say() { printf '%s\n' "$*"; }

command -v openssl >/dev/null 2>&1 || die "openssl is required to bootstrap the hub PKI"
command -v kubectl >/dev/null 2>&1 || die "kubectl is required to store the hub PKI"
[ -n "$HOST" ] || die "could not determine the gateway hostname; set WEIRVERN_GATEWAY_HOST"

kubectl get namespace "$NAMESPACE" >/dev/null 2>&1 || kubectl create namespace "$NAMESPACE" >/dev/null

TMP="$(mktemp -d)"
cleanup() { rm -rf "$TMP"; }
trap cleanup EXIT INT TERM

# All IPv4 addresses of this node are valid SANs, because deploy-weirling accepts either a
# hostname or an address and the certificate must match whichever the operator used.
IPS="$(hostname -I 2>/dev/null || true)"
{
    printf '[alt]\n'
    printf 'DNS.1=%s\n' "$HOST"
    printf 'DNS.2=localhost\n'
    printf 'DNS.3=weirvern-ingest\n'
    printf 'DNS.4=weirvern-ingest.%s\n' "$NAMESPACE"
    printf 'DNS.5=weirvern-ingest.%s.svc\n' "$NAMESPACE"
    i=6
    for ip in $IPS; do
        case "$ip" in *:*) continue ;; esac
        printf 'IP.%s=%s\n' "$((i - 5))" "$ip"
        i=$((i + 1))
    done
} > "$TMP/server.san"

write_server() {
    # $1 = intermediate cert, $2 = intermediate key
    openssl genrsa -out "$TMP/server.key" 2048 >/dev/null 2>&1
    openssl req -new -key "$TMP/server.key" -subj "/CN=weirvern-ingest/O=Weirvern" \
        -out "$TMP/server.csr" >/dev/null 2>&1
    cat > "$TMP/server.ext" <<EOF
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
subjectAltName=@alt
$(cat "$TMP/server.san")
EOF
    openssl x509 -req -in "$TMP/server.csr" -CA "$1" -CAkey "$2" -CAcreateserial \
        -out "$TMP/server.crt" -days "$DAYS_SERVER" -sha256 -extfile "$TMP/server.ext" \
        >/dev/null 2>&1
    cat "$TMP/server.crt" "$1" > "$TMP/server.chain.crt"
    kubectl -n "$NAMESPACE" create secret tls weirling-ingest-tls \
        --cert="$TMP/server.chain.crt" --key="$TMP/server.key" \
        --dry-run=client -o yaml | kubectl apply -f - >/dev/null
    say "  weirling-ingest-tls: server certificate written for $HOST"
}

# REUSE AN EXISTING CA. Rotation here is a deliberate operation, not an installer side effect:
# replacing the intermediate would invalidate every sensor already enrolled against it.
if kubectl -n "$NAMESPACE" get secret weirling-ca >/dev/null 2>&1; then
    kubectl -n "$NAMESPACE" get secret weirling-ca -o jsonpath='{.data.tls\.crt}' | base64 -d > "$TMP/int.crt"
    kubectl -n "$NAMESPACE" get secret weirling-ca -o jsonpath='{.data.tls\.key}' | base64 -d > "$TMP/int.key"
    say "  weirling-ca: existing intermediate reused (enrolled sensors stay valid)"
else
    say "  weirling-ca: creating the Weirvern root and Weirling intermediate"
    openssl genrsa -out "$TMP/root.key" 2048 >/dev/null 2>&1
    openssl req -x509 -new -nodes -key "$TMP/root.key" -sha256 -days "$DAYS_CA" \
        -subj "/CN=Weirvern Local Root CA/O=Weirvern" \
        -addext "basicConstraints=critical,CA:TRUE" \
        -addext "keyUsage=critical,keyCertSign,cRLSign" \
        -out "$TMP/root.crt" >/dev/null 2>&1
    openssl genrsa -out "$TMP/int.key" 2048 >/dev/null 2>&1
    openssl req -new -key "$TMP/int.key" -subj "/CN=Weirling Intermediate CA/O=Weirvern" \
        -out "$TMP/int.csr" >/dev/null 2>&1
    cat > "$TMP/int.ext" <<EOF
basicConstraints=critical,CA:TRUE,pathlen:0
keyUsage=critical,keyCertSign,cRLSign
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
EOF
    openssl x509 -req -in "$TMP/int.csr" -CA "$TMP/root.crt" -CAkey "$TMP/root.key" \
        -CAcreateserial -out "$TMP/int.crt" -days "$DAYS_CA" -sha256 -extfile "$TMP/int.ext" \
        >/dev/null 2>&1
    kubectl -n "$NAMESPACE" create secret generic weirling-root \
        --from-file=root-ca.crt="$TMP/root.crt" \
        --dry-run=client -o yaml | kubectl apply -f - >/dev/null
    kubectl -n "$NAMESPACE" create secret tls weirling-ca \
        --cert="$TMP/int.crt" --key="$TMP/int.key" \
        --dry-run=client -o yaml | kubectl apply -f - >/dev/null
    say "  weirling-root + weirling-ca: written (root private key discarded)"
fi

kubectl -n "$NAMESPACE" get secret weirling-root >/dev/null 2>&1 \
    || die "weirling-root is missing while weirling-ca exists; restore the root certificate before continuing"

# Keep a currently valid server certificate. A five-year-ish leaf is replaced only when it has
# less than 30 days left, or when the SAN does not include the host this hub is known by.
CURRENT="$TMP/current.crt"
if kubectl -n "$NAMESPACE" get secret weirling-ingest-tls >/dev/null 2>&1; then
    kubectl -n "$NAMESPACE" get secret weirling-ingest-tls -o jsonpath='{.data.tls\.crt}' \
        | base64 -d > "$CURRENT"
    if openssl x509 -in "$CURRENT" -noout -checkend 2592000 >/dev/null 2>&1; then
        if openssl x509 -in "$CURRENT" -noout -text 2>/dev/null | grep -F "DNS:$HOST" >/dev/null; then
            say "  weirling-ingest-tls: existing certificate covers $HOST; left in place"
            exit 0
        fi
        say "  weirling-ingest-tls: existing certificate does not cover $HOST; reissuing the leaf"
    else
        say "  weirling-ingest-tls: existing certificate expires within 30 days; reissuing the leaf"
    fi
fi

write_server "$TMP/int.crt" "$TMP/int.key"
say "bootstrap-mtls: done"
