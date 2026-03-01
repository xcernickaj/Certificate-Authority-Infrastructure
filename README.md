# Certificate-Authority-Infrastructure

This project is a command-line simulation of a simplified Public Key Infrastructure (PKI).  
The user controls three actors:

- Certificate Authority (CA)
- Server
- Client

The simulation demonstrates how asymmetric cryptography, digital certificates, and trust relationships work in secure communication systems. It also allows testing invalid and malicious scenarios such as certificate forgery.

---

## Objectives

The project helps students understand:

- Public and private key pairs
- Digital signatures
- Certificate signing and validation
- Secure key exchange
- Certificate revocation
- Effects of forged or invalid certificates

---

## System Description

The system simulates the following structure:

Certificate Authority  
  issues and manages certificates  

Server  
  requests certificates and provides data  

Client  
  verifies certificates and communicates securely with the server  

Each actor uses asymmetric cryptography for identification and secure communication.

---

## Core Concepts

### Asymmetric Cryptography

Each actor owns:
- A private key (kept secret)
- A public key (shared)

Private keys are used for signing.  
Public keys are used for verification and encryption.

### Digital Certificates

A certificate contains:
- Server identity
- Server public key
- CA digital signature

The client trusts the server only if the certificate is valid and signed by the CA.

### Certificate Revocation

Certificates can be revoked or removed by the CA.  
A revoked certificate should no longer be trusted by the client.

---

## Console Commands

### Certificate Authority Commands

- ca.revoke  
  Revoke an issued certificate.

- ca.remove  
  Remove a certificate from CA records.

- ca.log  
  Display all issued certificates.

---

### Server Commands

- server.csr  
  Request a valid certificate from the CA.

- server.fakecer  
  Generate a forged certificate (invalid signature).

---

### Client Commands

- client.connect  
  Connect to the server and perform key exchange.

- client.msg  
  Send a message to the server.

- client.get  
  Retrieve the current message stored on the server.

- client.post  
  Modify the message stored on the server.

---

### General Command

- exit  
  Terminate the simulation.

---

## Example Scenarios

### Valid Communication

1. The server requests a certificate using server.csr.
2. The CA signs and issues the certificate.
3. The client connects using client.connect.
4. The client verifies the certificate.
5. Secure communication is established.

### Forgery Attempt

1. The server generates a forged certificate using server.fakecer.
2. The client attempts to connect.
3. Certificate verification fails.
4. The connection is rejected.

### Revocation

1. The server has a valid certificate.
2. The CA revokes it using ca.revoke.
3. The client attempts to connect.
4. The certificate is rejected due to revocation.

---

## Notes

This project is an educational simulation.  
It simplifies real-world PKI systems to focus on fundamental cryptographic concepts.  
It is not intended for production use.
