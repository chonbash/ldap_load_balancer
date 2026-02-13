#!/bin/bash
# Generate ldap3.crt and ldap3.key using CA from ldap1. Copies ca.crt, ca.key, dhparam.pem from ldap1/certs.
set -e
DIR="$(cd "$(dirname "$0")" && pwd)"
CA_DIR="$DIR/../../ldap1/certs"
for f in ca.crt ca.key dhparam.pem; do
  if [ ! -f "$CA_DIR/$f" ]; then
    echo "Missing $CA_DIR/$f — ensure ldap1 certs exist first." >&2
    exit 1
  fi
  cp "$CA_DIR/$f" "$DIR/$f"
done
openssl genrsa -out "$DIR/ldap3.key" 2048
openssl req -new -key "$DIR/ldap3.key" -out "$DIR/ldap3.csr" -subj "/CN=ldap3/O=Example"
openssl x509 -req -in "$DIR/ldap3.csr" -CA "$DIR/ca.crt" -CAkey "$DIR/ca.key" -CAcreateserial \
  -out "$DIR/ldap3.crt" -days 3650 -extfile "$DIR/ldap3.ext"
echo "Generated ldap3.crt and ldap3.key in $DIR"
