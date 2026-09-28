#!/usr/bin/env bash
# AV-0019 — regenerate the RFC 3161 test fixtures OFFLINE with a local openssl TSA.
# TEST-ONLY PKI: every key is created in a throwaway temp dir and deleted; only
# public certificates and the DER tokens are written here. Nothing touches a real TSA.
set -euo pipefail
OUT="$(cd "$(dirname "$0")" && pwd)"
W="$(mktemp -d)"; trap 'rm -rf "$W"' EXIT; cd "$W"
ossl() { openssl "$@" 2>/dev/null; }
ca() { # name subject signer-key signer-cert extensions keyalg
  ossl req -new -newkey "$6" -nodes -keyout "$1.key" -subj "$2" -out "$1.csr"
  printf '%s\n' "$5" > "$1.ext"
  if [ "$3" = self ]; then ossl x509 -req -in "$1.csr" -signkey "$1.key" -days 36500 -extfile "$1.ext" -out "$1.pem"
  else ossl x509 -req -in "$1.csr" -CA "$4" -CAkey "$3" -set_serial "0x$(openssl rand -hex 8)" -days 36500 -extfile "$1.ext" -out "$1.pem"; fi
}
CAEXT='basicConstraints=critical,CA:TRUE
keyUsage=critical,keyCertSign,cRLSign'
TSAEXT='basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=critical,timeStamping'
ca root "/CN=AV-0019 TEST Root CA" self - "$CAEXT" ec:<(openssl ecparam -name prime256v1)
ca inter "/CN=AV-0019 TEST Intermediate CA" root.key root.pem "$CAEXT" ec:<(openssl ecparam -name prime256v1)
ca tsa-rsa "/CN=AV-0019 TEST TSA RSA" inter.key inter.pem "$TSAEXT" rsa:2048
ca tsa-ec "/CN=AV-0019 TEST TSA EC" root.key root.pem "$TSAEXT" ec:<(openssl ecparam -name prime256v1)
ca other "/CN=AV-0019 TEST Unrelated CA" self - "$CAEXT" ec:<(openssl ecparam -name prime256v1)
cat tsa-rsa.pem inter.pem > chain-rsa.pem
echo 01 > serial
stamp() { # signer chainfile ess-alg out
  cat > tsa.cnf <<EOF
[ tsa ]
default_tsa = t
[ t ]
serial = ./serial
signer_cert = $1.pem
certs = $2
signer_key = $1.key
signer_digest = sha256
default_policy = 1.3.6.1.4.1.99999.3161.1
digests = sha256
accuracy = secs:1
ordering = no
tsa_name = yes
ess_cert_id_alg = $3
EOF
  ossl ts -query -digest "$ROOT_HEX" -sha256 -cert -out req.tsq
  ossl ts -reply -config tsa.cnf -queryfile req.tsq -token_out -out "$4"
}
ROOT_HEX="$(printf 'av-0019 root A' | openssl dgst -sha256 -r | cut -d' ' -f1)"
printf '%s' "$(printf '%s' "$ROOT_HEX" | xxd -r -p | base64)" > "$OUT/root-hash-a.b64"
stamp tsa-rsa chain-rsa.pem sha1 token-rsa.der
stamp tsa-ec tsa-ec.pem sha256 token-ec.der
# the root of buildFixtureBundle() in src/__tests__/verify.spec.ts (deterministic seed)
ROOT_HEX="$(printf '%s' 'lo5GEZpdfhDWWEBM+DlDRPfGiJnfPe6090cajN0lyHQ=' | base64 -d | xxd -p -c 64)"
stamp tsa-ec tsa-ec.pem sha256 token-bundle-root.der
for f in token-rsa token-ec token-bundle-root; do base64 < "$f.der" | tr -d '\n' > "$OUT/$f.b64"; done
cp root.pem "$OUT/root-ca.pem"; cp other.pem "$OUT/other-ca.pem"; cp inter.pem "$OUT/intermediate-ca.pem"
echo "fixtures written to $OUT"
