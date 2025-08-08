# QUICAP

## Introduction

**QUICAP** is a QUIC-based L2 tunnel.

## Configuration

### Deploy your own certificates to nodes

```sh
# Issue an CA certificate
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:secp384r1 -keyout ca_key.pem -out ca_crt.pem -sha384 -days 3650 -nodes -subj "/CN=ca.quicap.local"
# Generate an node key along with certificate sign request and use CA key to sign it
openssl req -newkey ec -pkeyopt ec_paramgen_curve:secp384r1 -keyout key.pem -out csr.pem -sha384 -nodes -subj "/CN=n1.quicap.local"
openssl x509 -req -in csr.pem -CA ca_crt.pem -CAkey ca_key.pem -CAcreateserial -out crt.pem -days 3650 -sha384
rm csr.pem
```

And continue to issue for other nodes using the same CA key and certificate.

```sh
openssl req -newkey ec -pkeyopt ec_paramgen_curve:secp384r1 -keyout key.pem -out csr.pem -sha384 -nodes -subj "/CN=n2.quicap.local"
openssl x509 -req -in csr.pem -CA ca_crt.pem -CAkey ca_key.pem -CAcreateserial -out crt.pem -days 3650 -sha384
rm csr.pem
```
