#!/bin/bash
set -e

# Create a new quoting key under the endorsement hierarchy (parent key 0x81010001)
tpm2_createak -C 0x81010001 -G rsa -g sha256 -c quotingkey.ctx

# Persist new key under first available handle and output ESYS_TR object
tpm2_evictcontrol -c quotingkey.ctx -o certs/quotingkey.tr  > /dev/null

# Generate and store signed certificate for quoting key
openssl req -provider tpm2 -provider default -propquery '?provider=tpm2' -new -subj "$1" -key object:certs/quotingkey.tr -out quotingkey.csr
openssl x509 -req -CA certs/maincacert.pem -CAkey certs/maincakey.pem -days 730 -in quotingkey.csr -out certs/quotingcert.pem

# Clear TPM key handles and remove temporary files
tpm2_flushcontext --transient-object && rm quotingkey.ctx quotingkey.csr