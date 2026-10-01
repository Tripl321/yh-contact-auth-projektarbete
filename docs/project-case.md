# SHALLOT — Project Case Study

SHALLOT (Secure Hardware Authenticated Contact Link / Offline Transceiver) is a cybersecurity prototype for local, offline authentication in OT/ICS-adjacent environments. It explores how a portable identity device can authenticate to an enforcement node without depending on public networks or cloud-based identity services.

> **Project status:** Security-focused educational prototype. The active MVP uses physically docked UART communication. LoRa remains an archived or future transport track and is not the primary authentication path.

## 1. Context and Objective

Industrial and other isolated environments may need local access control even when internet connectivity, central identity providers, or conventional network services are unavailable or undesirable. A traditional physical key and paper log provide limited cryptographic assurance, freshness verification, and automated failure handling.

The objective of SHALLOT was to design and evaluate a bounded proof of concept for local authentication between:

- **PAW (Portable Access Wearable):** a portable identity device that responds to authentication challenges.
- **DEN (Defensive Edge Node):** the enforcement node that initiates authentication and makes the access decision.
- **Mama Bear:** the provisioning authority responsible for key generation and distribution workflows.

The project focused on challenge-response authentication, protocol validation, fail-closed behaviour, key-management boundaries, revocation controls, privacy-conscious user feedback, and transparent documentation of residual risk.

## 2. Security Problem and Threat Model

The central problem was to verify that a physically connected device possesses the correct key without transmitting that key over the authentication link. The design also needed to reject malformed, delayed, replayed, or unauthenticated messages safely.

The prototype was designed to reduce risks including:

- replay of previously captured authentication responses;
- manipulation or corruption of UART frames;
- unauthorised access after timeouts, disconnection, or validation errors;
- probing of revocation logic before authentication;
- information exposure through the wearable's display; and
- basic timing leakage during HMAC comparison.

The project does not claim to solve advanced physical attacks, hardware key extraction, sophisticated side-channel analysis, tamper resistance, or production-grade key lifecycle management.

## 3. My Role and Responsibilities

My work focused on translating security requirements into a testable hardware-oriented prototype and maintaining traceability between the threat model, protocol, implementation, tests, and documentation.

Key responsibilities included:

- defining and refining the active project scope;
- documenting the architecture pivot from LoRa-based authentication to physically docked UART;
- specifying the PAW-to-DEN challenge-response protocol;
- analysing fail-closed behaviour and residual risks;
- reviewing key provisioning and revocation boundaries;
- creating and evaluating protocol, security, and integration tests; and
- communicating what was implemented, simulated, physically verified, or still incomplete.

An important part of the work was avoiding unsupported security claims and clearly separating secure design intent from verified operational behaviour.

## 4. Approach and Technical Implementation

The active authentication flow is initiated by DEN:

1. DEN generates and sends a fresh 64-bit nonce in a `CHALLENGE` frame.
2. PAW calculates `HMAC-SHA256(K_mac, nonce)` and returns a 32-byte `RESPONSE`.
3. DEN validates the frame, CRC32, response length, deadline, and HMAC.
4. DEN checks the signed PAW blocklist after successful HMAC verification.
5. DEN sends an explicit approved or denied acknowledgement.
6. Any missing prerequisite or validation failure results in denied access.

The UART protocol uses a bounded frame format with a synchronisation byte, payload length, message type, payload, and CRC32. Partial frames, invalid lengths, unknown message types, CRC failures, byte timeouts, and missed session deadlines are rejected.

Security controls include:

- HMAC-SHA256 challenge-response with a derived MAC key;
- fresh nonces to reduce replay risk;
- constant-time HMAC comparison;
- a two-second response deadline and a 100 ms inter-byte timeout;
- responder-only behaviour for PAW;
- no key material transmitted over the docked UART link;
- fail-closed handling for malformed or uncertain states; and
- a signed, versioned Ed25519 blocklist checked only after authentication.

The implementation combines embedded firmware, shared protocol code, Python-based test tooling, technical documentation, and issue-driven project planning.

## 5. Results and Evidence

The project produced a documented UART authentication architecture, a shared framing protocol, HMAC-based challenge-response logic, fail-closed decision paths, privacy-conscious status output, and a signed blocklist design.

Automated tests and source-level checks cover areas such as:

- protocol framing and CRC32 validation;
- malformed, truncated, oversized, or unknown messages;
- HMAC verification and constant-time comparison requirements;
- authentication deadlines and fail-closed behaviour;
- Ed25519 signing and verification using test vectors;
- manipulated signatures, rollback attempts, and incorrect trust roots; and
- blocklisted, unlisted, and unknown revocation states.

The outcome is a security-oriented prototype rather than a production-ready access-control system. The current DEN firmware contains an all-zero placeholder for the Ed25519 blocklist public key. Consequently, no production blocklist signature can validate in that configuration, and the fail-closed logic denies access. This is a safe default, but it also means that successful production-style end-to-end authentication cannot be claimed until a valid trust root and signed blocklist are provisioned.

Further physical verification is also required for the complete provisioning flow, blocklist transfer, hardware entropy, target-device side-channel resistance, persistent storage, and final hardware acceptance.

## 6. Lessons Learned and Next Steps

The project demonstrated that selecting a strong cryptographic primitive is only one part of building a secure system. Security depends on the entire chain: requirements, protocol design, key handling, trust anchors, revocation, implementation, testing, hardware integration, failure behaviour, and operational procedures.

The architecture pivot from LoRa to physically docked UART reduced the remote attack surface and made the MVP easier to reason about and test. It also reinforced the importance of changing technical direction when evidence shows that the original approach introduces unnecessary complexity or exposure.

The most important lesson was the distinction between a control existing in code and being operationally usable. The blocklist can be correctly designed and fail safely while the system still cannot meet its access-control objective until the trust root and provisioning process are complete.

Recommended next steps are:

- provision a valid Ed25519 trust root and signed blocklist;
- complete and document physical end-to-end testing;
- establish secure production key provisioning, rotation, and revocation;
- add persistent, integrity-protected blocklist storage;
- independently review the cryptographic implementation;
- evaluate hardware-backed key protection or a secure element; and
- perform target-hardware side-channel and tamper-resistance assessments.

## Repository Evidence

Detailed evidence is available in the repository, including:

- [`README.md`](../README.md)
- [`docs/00-scope.md`](00-scope.md)
- [`docs/architecture-pivot-2026-09-09.md`](architecture-pivot-2026-09-09.md)
- [`docs/11-dockat-uart-protokoll.md`](11-dockat-uart-protokoll.md)
- [`docs/13-pro-53-fail-closed.md`](13-pro-53-fail-closed.md)
- [`docs/17-pro-98-paw-blocklist.md`](17-pro-98-paw-blocklist.md)

---

*This case study intentionally distinguishes verified controls from simulations, incomplete integrations, and future production requirements.*