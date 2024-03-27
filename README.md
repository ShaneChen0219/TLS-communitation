
# TLS-communitation

Build a simplified version of the TLS protocol

## Description

The simplified TLS (Transport Layer Security) protocol involves the establishment of a secure communication channel between a server and a client. To initiate the protocol, both the server and client generate key files locally through terminal commands. Following this, a handshake process occurs where the server and client exchange cryptographic parameters and establish a secure connection. Once the handshake is complete, both sides are permitted to send encrypted messages to each other over the secure channel, ensuring confidentiality and integrity of data transmission.

### Dependencies

* RSA public/private key pair for the CA
    * openssl req -x509 -newkey rsa:4096 -keyout CAprivateKey.pem -out CAcertificate.pem -days 30 -nodes

* Client/Server keys and certificate signature requests (CSRs)
    * openssl req -new -newkey rsa:4096 -nodes -keyout serverPrivate.key -out server.csr
    * openssl req -new -newkey rsa:4096 -nodes -keyout clientPrivate.key -out client.csr

* CA config
    * config.cnf

* Fulfill CSR requests
    * openssl ca -config config.cnf  -cert CAcertificate.pem -keyfile CAprivateKey.pem -in server.csr -out CASignedServerCertificate.pem
    openssl ca -config config.cnf  -cert CAcertificate.pem -keyfile CAprivateKey.pem -in client.csr -out CASignedClientCertificate.pem

* Formats
    * openssl pkcs8 -topk8 -outform DER -in serverPrivate.key -out serverPrivateKey.der -nocrypt
    * openssl pkcs8 -topk8 -outform DER -in clientPrivate.key -out clientPrivateKey.der -nocrypt


## Authors
Hsiang-Yuan(Shane) Chen


## Version History
* 0.1
    * Initial Release
