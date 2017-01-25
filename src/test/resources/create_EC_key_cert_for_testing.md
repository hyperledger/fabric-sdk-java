# Create keys and certificates:

"Fake" keys and certificates were created for unit tests.
Whenever a password or passphrase is needed, I use **123456**

There are 2 keypairs:
1. **ca** which acts as the certificate authority, trusted cert
1. **keypair**  which is a normal key/certificate pair. The _keypair-signed_  certificate is signed by **ca**

The CN for the certificates is _CN=tuans-mbp-2.raleigh.ibm.com_.

There are 2 sets of keypairs, one created with the RSA key algorithm and the other with the elliptic curve key algorithm. I'm using the EC keypair in the unit tests. The RSA keypairs are in the files with suffix "-rsa".

All are created with *openssl*.

For elliptic curve, I use the curve **secp384r1**. Note that the Go tls package only supports 3 curves [secp256r1, secp384r1, secp521r1](https://golang.org/pkg/crypto/tls/#CurveID) while *openssl* and *keytool* support [many more](http://www.iana.org/assignments/tls-parameters/tls-parameters.xml#tls-parameters-8). **secp384r1** happened to be the common one.

1. create CA cert:
  1. for RSA
    - openssl req -new -x509 -keyout ca.key -out ca.crt  -days 3650
  1. for EC
    - openssl ecparam -name _secp384r1_ -out _secp384r1.pem_ (do this once only so *openssl* has an ec param file. It's possible to combine this with the genkey command but then Go cannot read the key file.)
    - openssl ecparam -in secp384r1.pem -genkey -noout -out ca.key
    - openssl req -x509 -new -key ca.key -out ca.crt -outform PEM -days 3650

1. create keypair signed with CA cert
  1. for RSA
    - openssl genrsa -out orderer.key 2048
  1. for EC
    - openssl ecparam -in secp384r1.pem -genkey -noout -out orderer.key
  1. sign with CA certificate
    - openssl req -new -key orderer.key -out orderer.csr -outform PEM
    - openssl x509 -req -CA ca.crt -CAkey ca.key -in orderer.csr -out  orderer-signed.crt  -days 3650  -CAcreateserial -passin pass:123456

# Utilities

- to see signed certificate:
   - openssl x509 -noout -text -in _cert-file_  (should have an Issuer and a Subject sections)

- to check that a certificate can be used for signing
  - openssl x509 -purpose -in _ca_cert_file_ -inform PEM
  - check output for _any purpose CA: YES_

- to verify chain of trust:
  - openssl verify -CAfile _ca-cert-file_ _cert-file_

- [keystore explorer](http://www.keystore-explorer.org/) can read keystores and truststores
