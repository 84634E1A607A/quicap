# QUICAP

## Introduction

**QUICAP** is a QUIC-based L2 tunnel.

## Configuration

### Deploy your own certificates to nodes

```sh
# Issue an CA certificate
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:secp384r1 -keyout tests/asset/ca_key.pem -out tests/asset/ca_crt.pem -sha384 -days 3650 -nodes -subj "/CN=ca.quicap.local"
# Generate an node key along with certificate sign request and use CA key to sign it
openssl req -newkey ec -pkeyopt ec_paramgen_curve:secp384r1 -keyout tests/asset/key.pem -out tests/asset/csr.pem -nodes -config tests/asset/san.conf
openssl x509 -req -in tests/asset/csr.pem -CA tests/asset/ca_crt.pem -CAkey tests/asset/ca_key.pem -CAcreateserial -out crt.pem -days 3650 -sha384 -extfile tests/asset/san.conf -extensions req_ext
rm tests/asset/csr.pem
```

And continue to issue for other nodes using the same CA key and certificate.

## Development

### Run tests

```sh
cargo test -- --test-threads=1
```
