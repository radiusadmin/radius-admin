#!/bin/bash
# Throwaway test PKI (NOT for production): Root CA -> Issuing CA -> server + client certs.
# RSA-3072 / SHA-256 everywhere. Usage: make-test-pki.sh <outdir>
set -euo pipefail
OUT=${1:?outdir}
mkdir -p "$OUT"; cd "$OUT"
umask 077
key() { openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out "$1" 2>/dev/null; }
ext() { # name body
  printf '[e]\n%s\n' "$2" > "$1.ext"
}
sign() { # name subject cakey capem extbody
  openssl req -new -sha256 -key "$1.key" -subj "$2" -out "$1.csr"
  ext "$1" "$5"
  openssl x509 -req -sha256 -days 825 -in "$1.csr" -CA "$4" -CAkey "$3" \
    -set_serial "0x$(openssl rand -hex 8)" -extfile "$1.ext" -extensions e -out "$1.pem" 2>/dev/null
}
CLIENT='basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=clientAuth
authorityKeyIdentifier=keyid'

key root.key
openssl req -new -x509 -sha256 -days 3650 -key root.key -subj "/CN=TEST-Example-RootCA" \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" -out root.pem
key issuing.key
sign issuing "/CN=TEST-Example-IssuingCA" root.key root.pem 'basicConstraints=critical,CA:TRUE,pathlen:0
keyUsage=critical,keyCertSign,cRLSign
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid'
key server.key
sign server "/CN=radius.example.net" issuing.key issuing.pem 'basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:radius.example.net,DNS:localhost,IP:127.0.0.1
authorityKeyIdentifier=keyid'
# LDAPS server cert for the emulated domain controller (slapd)
key dc.key
sign dc "/CN=dc01.example.net" issuing.key issuing.pem 'basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:dc01.example.net
authorityKeyIdentifier=keyid'
# OCSP responder cert (emulates http://pki.example.net:8080/ocsp)
key ocsp.key
sign ocsp "/CN=TEST-Example-OCSP" issuing.key issuing.pem 'basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=OCSPSigning
authorityKeyIdentifier=keyid'
for n in pc1 pc2 pc3 pc4 pc5 pc6 pc7 pc8 pc9; do
  key $n.key
  sign $n "/CN=$n.example.net" issuing.key issuing.pem "$CLIENT
subjectAltName=DNS:$n.example.net"
done
key nosan.key
sign nosan "/CN=nosan.example.net" issuing.key issuing.pem "$CLIENT"
# A client cert from a different (unknown) CA with a valid-looking SAN
key rogue-ca.key
openssl req -new -x509 -sha256 -days 3650 -key rogue-ca.key -subj "/CN=ROGUE-CA" \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" -out rogue-ca.pem
key rogue.key
sign rogue "/CN=pc1.example.net" rogue-ca.key rogue-ca.pem "$CLIENT
subjectAltName=DNS:pc1.example.net"
# OCSP index: everything valid except pc5 (revoked)
: > index.txt
for n in server dc pc1 pc2 pc3 pc4 pc5 pc6 pc7 pc8 pc9 nosan; do
  ser=$(openssl x509 -in $n.pem -noout -serial | cut -d= -f2)
  end=$(date -u -d "$(openssl x509 -in $n.pem -noout -enddate | cut -d= -f2)" +%y%m%d%H%M%SZ)
  subj=$(openssl x509 -in $n.pem -noout -subject -nameopt compat | sed 's/^subject=//')
  if [ $n = pc5 ]; then
    printf 'R\t%s\t%s\t%s\tunknown\t%s\n' "$end" "$(date -u +%y%m%d%H%M%SZ)" "$ser" "$subj" >> index.txt
  else
    printf 'V\t%s\t\t%s\tunknown\t%s\n' "$end" "$ser" "$subj" >> index.txt
  fi
done
echo 'unique_subject = no' > index.txt.attr
# Production layout: certs/site/ca.pem = IssuingCA + RootCA
cat issuing.pem root.pem > ca.pem
chmod 644 *.pem
for c in issuing server pc1 nosan rogue; do
  if openssl verify -CAfile ca.pem $c.pem >/dev/null 2>&1; then echo "$c: verifies against ca.pem"; else echo "$c: does NOT verify against ca.pem"; fi
done
# Client presenting its Issuing CA in the chain (common for Windows supplicants)
cat pc1.pem issuing.pem > pc1-chain.pem
