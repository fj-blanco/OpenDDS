# OpenDDS Security

This document is intended as a collection of high-level notes on OpenDDS
Security. OpenDDS Security provides security controls and capabilities for
RTPS, which includes authentication of participants and encryption of messages.
It is an implementation of DDS Security Version 1.1 (OMG formal/2018-04-01).

## DDS Security 1.2 Participant Algorithm Negotiation

OpenDDS includes a deliberately limited subset of DDS Security 1.2
(OMG formal/2025-03-06) for participant-level cryptographic algorithm
negotiation.  This subset lets Authentication plugins advertise and constrain
signature and key-establishment algorithms without claiming complete DDS
Security 1.2 conformance.

The implemented subset consists of:

- `CryptoAlgorithmBit`, `CryptoAlgorithmSet`, and the participant algorithm
  information types from clauses 7.3.8 through 7.3.14;
- `ParticipantSecurityConfig` and the Authentication
  `set_participant_security_config` operation;
- participant discovery parameters 0x1010, 0x1011, and 0x1012, including the
  DDS Security 1.2 defaults when a parameter is absent;
- the bilateral compatibility checks from clauses 7.3.10 through 7.3.13 before
  participant authentication starts; and
- configuration of the built-in PKI-DH Authentication implementation for its
  existing RSA-PSS/ECDSA and ECDHE-P256 algorithms.

The current DDS Security 1.1 Access Control result is adapted into a 1.2
`ParticipantSecurityConfig`.  Authentication adjusts the signature and
key-establishment fields.  The symmetric-cipher fields reflect the existing
AES-128/AES-256 built-in Cryptographic implementation.

The following DDS Security 1.2 work remains out of scope for this subset:

- the Access Control `get_*_security_config` operations and governance XML
  algorithm constraints;
- the revised Cryptographic SPI and its adjusted algorithm information;
- endpoint algorithm discovery and compatibility;
- PSK and AXK protection modes, key revision, and the revised protection-info
  masks; and
- a complete migration of the existing DDS Security 1.1 IDL and behavior.

Bits 16 through 30 of a `CryptoAlgorithmSet` are vendor-specific in DDS
Security 1.2 and are interpreted in the context of the RTPS vendor ID.  OpenDDS
therefore rejects a participant configuration that requires one of those bits
when the remote participant has another vendor ID.  Plugins that use these
bits need standardized assignments or an explicitly shared convention for
cross-vendor interoperability.

## Debug Logging

OpenDDS Security has debug messages like the rest of OpenDDS, many are under
the `DCPSSecurityDebug` but, as of writing, there are sill many messages still
under `DCPSDebugLevel` and `DCPSTransportDebugLevel` and need to be
transitioned. Security debug messages are broken broken down into named
categories which can be specified individually or activated on the same
accumulative 1 to 10 scale as `DCPSDebugLevel`.

See https://opendds.readthedocs.io/en/master/devguide/run_time_configuration.html#security-debug-logging
for the categories and usage, or `dds/DCPS/debug.h` and `dds/DCPS/debug.cpp`
for the source.

## Authentication

Authentication occurs after participants discover each other. It consists of a
three-way handshake using the "builtin SPDP participant" readers and writers.

- Request
  - Based on GUIDs, one side takes the lead and starts the handshake by sending
    their security documents. We can call this participant the leader, with the
    other side being the follower.
- Reply
  - The follower will verify the leader and send their own documents back.
- Final
  - Finally the leader will verify the follower and send a "final" message
    back, signaling that association can continue.

The role taken in the authentication handshake can be overridden using
`OpenDDS::DCPS::security_debug.force_auth_role`.

<!-- TODO: List OMG authentication states and what they actually mean -->

## Key Exchange

During key exchange all keys of secure entities will be exchanged using the
"Builtin Participant Volatile Message Secure" topic. It can be thought of as a
boot strap to the normal security.

- Because they are special keys, "volatile" keys all have the key id `00 00 00 00`.

- Each side should send at least 8 keys, one for each secure entity.

- `bookkeeping` security debug logging category will show when these keys are
  generated and exchanged. `showkeys` security debug logging category will log
  the keys themselves.

## Fake Encryption

Anyone debugging OpenDDS security to any significant extent will probably find
the fake encryption option useful. It disables all encryption in OpenDDS
Security, but leaves the rest of the infrastructure alone. This allows one to
see what is being sent in Wireshark.

To enable it, pass `-DCPSSecurityFakeEncryption=1` to all programs using
security. If all participants are not set the same, it will cause security to
fail. It can also be set in the common section of ini files. Refer to the RTPS
and DDS Security specs for the structure of secure RTPS packets to aid in
manually demarshaling them.
