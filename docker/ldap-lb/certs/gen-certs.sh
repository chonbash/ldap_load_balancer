#!/bin/bash
# Generate cert.pem and key.pem for LDAP Load Balancer (LDAPS listener).
# Uses CA from docker/ldap1/certs. SAN: ldap-load-balancer, ldap-lb, ldap-lb-ldaps, localhost.
set -e
DIR="$(cd "$(dirname "$0")" && pwd)"
CA_DIR="$DIR/../../ldap1/certs"
for f in ca.crt ca.key; do
  if [ ! -f "$CA_DIR/$f" ]; then
    echo "Missing $CA_DIR/$f — ensure ldap1 certs exist first (e.g. run ldap1/certs generation if present)." >&2
    exit 1
  fi
  cp "$CA_DIR/$f" "$DIR/$f"
done
openssl genrsa -out "$DIR/key.pem" 2048
openssl req -new -key "$DIR/key.pem" -out "$DIR/ldap-lb.csr" -subj "/CN=ldap-load-balancer/O=Example"
openssl x509 -req -in "$DIR/ldap-lb.csr" -CA "$DIR/ca.crt" -CAkey "$DIR/ca.key" -CAcreateserial \
  -out "$DIR/cert.pem" -days 3650 -extfile "$DIR/ldap-lb.ext"
echo "Generated cert.pem and key.pem in $DIR"
