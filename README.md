# TLS Handshake Visualised — See How HTTPS Works

[![Netlify Status](https://api.netlify.com/api/v1/badges/placeholder/deploy-status)](https://tls-handshake.securityronin.com)

Interactive step-by-step **TLS 1.3 handshake** demonstration. See how key exchange, authentication, encryption, and integrity work together. Toggle failure scenarios to see what breaks.

**[Live Demo →](https://tls-handshake.securityronin.com)**

## What It Teaches

Every HTTPS connection starts with a handshake. This demo walks through the TLS 1.3 protocol step by step, mapping each step to the four cryptographic pillars:

1. **ClientHello** — Key Exchange begins (ECDHE key share sent)
2. **ServerHello** — Key exchange complete; handshake traffic keys derived. Authentication not yet established.
3. **Certificate** — Server authenticates: encrypted Certificate + CertificateVerify flight verified. Encryption already active.
4. **Client Finished** — Integrity established: Finished authenticates the handshake transcript; both sides derive complementary client/server application traffic secrets via HKDF
5. **Encrypted Data** — AEAD-authenticated application records flow (auth tag is integral to the cipher, not a separate HMAC)
6. **Done** — All four pillars active. Connection secure.

## What-If Scenarios

Toggle scenarios to see how the handshake changes or breaks:

**TLS 1.3 — Baseline & Variations**

| Scenario | Effect |
|----------|--------|
| **HelloRetryRequest** | Step 2 — server rejects the client's key_share group; client retries with secp256r1, adding one RTT |
| **PSK Session Resumption** | Step 2 — server accepts a session ticket; ECDHE still used for forward secrecy |
| **0-RTT Early Data** | Step 5 — early data sent before server Finished; replayable, bound to resumption key (not fresh ECDHE share) |
| **Mutual TLS** | Step 4 — client presents its own certificate after server CertificateRequest |

**TLS 1.3 — Certificate & Auth Failures**

| Scenario | Effect |
|----------|--------|
| **Expired Certificate** | Step 3 fails — certificate validity period has ended |
| **Hostname Mismatch** | Step 3 fails — certificate CN/SAN does not match the requested hostname |
| **Weak Signature (SHA-1)** | Step 3 fails — SHA-1 is cryptographically broken; TLS 1.3 forbids it in CertificateVerify |
| **Revoked Certificate (OCSP staple)** | Step 3 fails — OCSP staple embedded in Certificate message shows certStatus: revoked |
| **Certificate Pinning Failure** | Step 3 fails — cert is valid but SPKI hash doesn't match the pinned value |
| **MITM Attempt** | Step 3 fails — rogue certificate signed by an untrusted CA, or CertificateVerify invalid |
| **Client Authentication Failure** | Step 4 fails — server required a client certificate; client sent an empty Certificate message |

**TLS 1.3 — Privacy & Extensions**

| Scenario | Effect |
|----------|--------|
| **SNI Exposed (no ECH)** | Step 1 — server name visible in plaintext ClientHello extension |
| **ECH Success** | Step 1 — inner ClientHello encrypted with server's published public key; supersedes ESNI |
| **ALPN Mismatch** | Step 3 fails — client offered only `h2`; server supports only `http/1.1`; fatal `no_application_protocol` alert (RFC 7301 §3.3.2) |
| **HSTS** | Step 6 — server delivers `Strict-Transport-Security` in the HTTP response; browser enforces HTTPS-only for future visits |
| **QUIC / HTTP/3 contrast** | Step 1 — educational comparison; QUIC carries the TLS 1.3 handshake inside CRYPTO frames over UDP instead of a TLS record layer |

**TLS 1.3 — Active Attacks**

| Scenario | Effect |
|----------|--------|
| **Session Ticket Theft** | Step 2 — attacker replays a stolen PSK ticket to hijack the session |
| **Record Tampering** | Step 5 — attacker modifies an application data record; AES-256-GCM detects it via authentication tag mismatch; connection aborted |

**TLS 1.2 Downgrade path**

| Scenario | Effect |
|----------|--------|
| **TLS 1.2 downgrade (RSA)** | Full downgrade — RSA key exchange, no forward secrecy |
| **TLS 1.2 + CBC cipher** | Warning from step 3 — Lucky13/POODLE exploit CBC padding oracles; BEAST exploits predictable TLS 1.0 CBC IVs |
| **TLS 1.2 + expired certificate** | Step 2 fails — certificate validity check |
| **Export RSA Downgrade (FREAK)** | Step 2 — illustrative TLS 1.2 server silently accepts an export-grade RSA suite; downgrade succeeds with no client alert |
| **Export DHE Downgrade (Logjam)** | Step 2 — illustrative TLS 1.2 server sends weak 512-bit DHE parameters in ServerKeyExchange; shared secret becomes recoverable |
| **Renegotiation Injection** | Step 5 — pre-RFC 5746 TLS 1.2 allows attacker prefix injection via unauthenticated renegotiation |

## Development

```bash
npm install
npx playwright install chromium
python3 -m http.server 3009 --directory web
# Open http://localhost:3009
```

## Testing

```bash
npm test
```

154 Playwright E2E tests covering security headers, happy path, scenario toggles, protocol trees, and reset.

## Tech Stack

- Vanilla HTML/CSS/JS (single file, no framework)
- Playwright for E2E testing
- Netlify for static deployment

## Part of The Codebreakers

This demo accompanies **The Codebreakers Part II: The Algorithms** — an introductory information security course by [Albert Hui (Security Ronin)](https://linkedin.com/in/albert.hui).

## Licence

MIT
