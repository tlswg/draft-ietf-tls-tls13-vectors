---
title: Example Handshake Traces for TLS 1.3
abbrev: TLS 1.3 Traces
docname: draft-thomson-tls-tls13-vectors-latest
date: 2016
category: std

ipr: trust200902
area: Applications and Real-Time
workgroup: HTTP
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
: b4bb498f8279303d 980836399b36c698 8c0c68de55e1bdb8 26d3901a2461eafd
  2de49a91d015abbc 9a95137ace6c1af1 9eaa6af98c7ced43 120998e187a80ee0
  ccb0524b1b018c3e 0b63264d449a6d38 e22a5fda43084674 8030530ef0461c8c
  a9d9efbfae8ea6d1 d03e2bd193eff0ab 9a8002c47428a6d3 5a8d88d79f7f1e3f

public exponent:
: 010001

private exponent:
: 04dea705d43a6ea7 209dd8072111a83c 81e322a59278b334 80641eaf7c0a6985
  b8e31c44f6de62e1 b4c2309f6126e77b 7c41e923314bbfa3 881305dc1217f16c
  819ce538e922f369 828d0e57195d8c84 88460207b2faa726 bcf708bbd7db7f67
  9f893492fc2a622e 08970aac441ce4e0 c3088df25ae67923 3df8a3bda2ff9941

prime1:
: e435fb7cc8373775 6dacea96ab7f59a2 cc1069db7deb190e 17e33a532b273f30
  a327aa0aaabc58cd 67466af9845fadc6 75fe094af92c4bd1 f2c1bc33dd2e0515

prime2:
: cabd3bc0e0438664 c8d4cc9f99977a94 d9bbfead8e43870a bae3f7eb8b4e0eee
  8af1d9b4719ba619 6cf2cbbaeeebf8b3 490afe9e9ffa74a8 8aa51fc645629303

exponent1:
: 3f57345c27fe1b68 7e6e761627b78b1b 826433dd760fa0be a6a6acf39490aa1b
  47cda4869d68f584 dd5b5029bd32093b 8258661fe715025e 5d70a45a08d3d319

exponent2:
: 183da01363bd2f28 85cacbdc9964bf47 64f1517636f86401 286f71893c52ccfe
  40a6c23d0d086b47 c6fb10d8fd1041e0 4def7e9a40ce957c 417794e10412d139

coefficient:
: 839ca9a085e4286b 2c90e466997a2c68 1f21339aa3477814 e4dec11833050ed5
  0dd13cc038048a43 c59b2acc416889c0 37665fe5afa60596 9f8c01dfa5ca969d


# Simple 1-RTT Handshake {#onertt}

In this example, the simplest possible handshake is completed.  The server is
authenticated, but the client remains anonymous.  After connecting, a few
application data octets are exchanged.  The server sends a session ticket that
permits the use of 0-RTT in any resumed session.

Note:
: This example doesn't include the calculation of the exporter secret.  Support
  for that will be added to NSS soon.

>>> Version13Only/TlsConnectTls13.ZeroRtt/0 initial resumed
<<< Version13Only/TlsConnectTls13.ZeroRtt/0 initial


# Resumed 0-RTT Handshake {#zerortt}

This handshake resumes from the handshake in {{onertt}}.  Since the server
provided a session ticket that permitted 0-RTT, and the client is configured for
0-RTT, the client is able to send 0-RTT data.

<<< Version13Only/TlsConnectTls13.ZeroRtt/0 resumed


# Security Considerations

It probably isn't a good idea to use the private key here.  If it weren't for
the fact that it is too small to provide any meaningful security, it is now very
well known.


--- back

# Acknowledgements

None of this would have been possible without Franziskus Kiefer, Eric Rescorla
and Tim Taubert, who did a lot of the work in NSS.
