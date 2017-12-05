---
title: Example Handshake Traces for TLS 1.3
abbrev: TLS 1.3 Traces
docname: draft-ietf-tls-tls13-vectors-latest
date: 2017
category: std

ipr: trust200902
area: Security
workgroup: TLS
keyword: Internet-Draft

stand_alone: yes
pi: [toc, tocindent, sortrefs, symrefs, strict, compact, comments, inline, docmapping]

author:
 -
    ins: M. Thomson
    name: Martin Thomson
    organization: Mozilla
    email: martin.thomson@gmail.com

normative:

informative:
  FIPS186:
    title: "Digital Signature Standard (DSS)"
    author:
      - org: National Institute of Standards and Technology (NIST)
    date: July 2013
    seriesinfo: NIST PUB 186-4


--- abstract

Examples of TLS 1.3 handshakes are shown.  Private keys and inputs are
provided so that these handshakes might be reproduced.  Intermediate
values, including secrets, traffic keys and ivs are shown so that
implementations might be checked incrementally against these values.


--- middle

# Introduction

TLS 1.3 {{!I-D.ietf-tls-tls13}} defines a new key schedule and a number new
cryptographic operations.  This document includes sample handshakes that
show all intermediate values.  This allows an implementation to be verified
incrementally, examining inputs and outputs of each cryptographic computation
independently.

Private keys are included with the traces so that implementations can be
checked by importing these values and verifying that the same outputs are
produced.


# Private Keys

Ephemeral private keys are shown as they are generated in the traces.

The server in most examples uses an RSA certificate with a private key of:

modulus (public):

: b4 bb 49 8f 82 79 30 3d 98 08 36 39 9b 36 c6 98 8c 0c 68 de 55 e1 bd b8 26 d3
  90 1a 24 61 ea fd 2d e4 9a 91 d0 15 ab bc 9a 95 13 7a ce 6c 1a f1 9e aa 6a f9
  8c 7c ed 43 12 09 98 e1 87 a8 0e e0 cc b0 52 4b 1b 01 8c 3e 0b 63 26 4d 44 9a
  6d 38 e2 2a 5f da 43 08 46 74 80 30 53 0e f0 46 1c 8c a9 d9 ef bf ae 8e a6 d1
  d0 3e 2b d1 93 ef f0 ab 9a 80 02 c4 74 28 a6 d3 5a 8d 88 d7 9f 7f 1e 3f

public exponent:

: 01 00 01

private exponent:

: 04 de a7 05 d4 3a 6e a7 20 9d d8 07 21 11 a8 3c 81 e3 22 a5 92 78 b3 34 80 64
  1e af 7c 0a 69 85 b8 e3 1c 44 f6 de 62 e1 b4 c2 30 9f 61 26 e7 7b 7c 41 e9 23
  31 4b bf a3 88 13 05 dc 12 17 f1 6c 81 9c e5 38 e9 22 f3 69 82 8d 0e 57 19 5d
  8c 84 88 46 02 07 b2 fa a7 26 bc f7 08 bb d7 db 7f 67 9f 89 34 92 fc 2a 62 2e
  08 97 0a ac 44 1c e4 e0 c3 08 8d f2 5a e6 79 23 3d f8 a3 bd a2 ff 99 41

prime1:

: e4 35 fb 7c c8 37 37 75 6d ac ea 96 ab 7f 59 a2 cc 10 69 db 7d eb 19 0e 17 e3
  3a 53 2b 27 3f 30 a3 27 aa 0a aa bc 58 cd 67 46 6a f9 84 5f ad c6 75 fe 09 4a
  f9 2c 4b d1 f2 c1 bc 33 dd 2e 05 15

prime2:

: ca bd 3b c0 e0 43 86 64 c8 d4 cc 9f 99 97 7a 94 d9 bb fe ad 8e 43 87 0a ba e3
  f7 eb 8b 4e 0e ee 8a f1 d9 b4 71 9b a6 19 6c f2 cb ba ee eb f8 b3 49 0a fe 9e
  9f fa 74 a8 8a a5 1f c6 45 62 93 03

exponent1:

: 3f 57 34 5c 27 fe 1b 68 7e 6e 76 16 27 b7 8b 1b 82 64 33 dd 76 0f a0 be a6 a6
  ac f3 94 90 aa 1b 47 cd a4 86 9d 68 f5 84 dd 5b 50 29 bd 32 09 3b 82 58 66 1f
  e7 15 02 5e 5d 70 a4 5a 08 d3 d3 19

exponent2:

: 18 3d a0 13 63 bd 2f 28 85 ca cb dc 99 64 bf 47 64 f1 51 76 36 f8 64 01 28 6f
  71 89 3c 52 cc fe 40 a6 c2 3d 0d 08 6b 47 c6 fb 10 d8 fd 10 41 e0 4d ef 7e 9a
  40 ce 95 7c 41 77 94 e1 04 12 d1 39

coefficient:

: 83 9c a9 a0 85 e4 28 6b 2c 90 e4 66 99 7a 2c 68 1f 21 33 9a a3 47 78 14 e4 de
  c1 18 33 05 0e d5 0d d1 3c c0 38 04 8a 43 c5 9b 2a cc 41 68 89 c0 37 66 5f e5
  af a6 05 96 9f 8c 01 df a5 ca 96 9d


# Simple 1-RTT Handshake {#onertt}

In this example, the simplest possible handshake is completed.  The server is
authenticated, but the client remains anonymous.  After connecting, a few
application data octets are exchanged.  The server sends a session ticket that
permits the use of 0-RTT in any resumed session.

>>> Version13Only/TlsConnectTls13.ZeroRtt/0 initial resumed
<<< Version13Only/TlsConnectTls13.ZeroRtt/0 initial


# Resumed 0-RTT Handshake {#zerortt}

This handshake resumes from the handshake in {{onertt}}.  Since the server
provided a session ticket that permitted 0-RTT, and the client is configured for
0-RTT, the client is able to send 0-RTT data.

<<< Version13Only/TlsConnectTls13.ZeroRtt/0 resumed


# HelloRetryRequest

In this example, the client initiates a handshake with an X25519 {{?RFC7748}}
share.  The server however prefers P-256 {{FIPS186}} and sends a
HelloRetryRequest that requires the client to generate a key share on the P-256
curve.

>>> KeyExchangeTest/TlsKeyExchangeTest13.EqualPriorityTestRetryECServer13/0 hrr
<<< KeyExchangeTest/TlsKeyExchangeTest13.EqualPriorityTestRetryECServer13/0 hrr


# Client Authentication

In this example, the server requests client authentication.  The client uses a
certificate with an RSA key, the server uses an ECDSA certificate with a P-256
key.

>>> GenericStream/TlsConnectGeneric.ClientAuthEcdsa/0 client_auth
<<< GenericStream/TlsConnectGeneric.ClientAuthEcdsa/0 client_auth



# Security Considerations

It probably isn't a good idea to use the private key here.  If it weren't for
the fact that it is too small to provide any meaningful security, it is now very
well known.


--- back

# Acknowledgements

This draft is generated using tests that were written for
[NSS](https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS).  None of
this would have been possible without Franziskus Kiefer, Eric Rescorla and Tim
Taubert, who did a lot of the work in NSS.
