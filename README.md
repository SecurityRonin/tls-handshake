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

**TLS 1.3 path**

| Scenario | Effect |
|----------|--------|
| **Expired Certificate** | Step 3 fails — certificate validity check aborts the connection |
| **MITM Attempt** | Step 3 catches the rogue certificate — untrusted CA or invalid CertificateVerify |
| **Certificate Pinning Failure** | Step 3 fails — cert is valid but SPKI hash doesn't match the pinned value |
| **PSK Session Resumption** | Step 2 — server accepts a session ticket; ECDHE still used for forward secrecy |
| **SNI Exposed (no ECH)** | Step 1 — server name visible in plaintext ClientHello extension |
| **0-RTT Early Data** | Step 5 — early data sent before server Finished; weaker protection than 1-RTT (no replay protection by default, bound to resumption key rather than fresh ECDHE share) |
| **Mutual TLS** | Step 4 — client presents its own certificate after server CertificateRequest |

**TLS 1.2 Downgrade path**

| Scenario | Effect |
|----------|--------|
| **TLS 1.2 downgrade (RSA)** | Full downgrade — RSA key exchange, no forward secrecy |
| **TLS 1.2 + CBC cipher** | Warning from step 3 — Lucky13/POODLE exploit CBC padding oracles; BEAST exploits predictable TLS 1.0 CBC IVs (chosen-plaintext, not a padding oracle) |
| **TLS 1.2 + expired certificate** | Step 2 fails — certificate validity check |
| **Export RSA Downgrade (FREAK-style)** | Step 2 — illustrative TLS 1.2 server silently accepts an export-grade RSA suite; downgrade succeeds with no client alert |
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

77 Playwright E2E tests covering security headers, happy path, scenario toggles, and reset.

## Tech Stack

- Vanilla HTML/CSS/JS (single file, no framework)
- Playwright for E2E testing
- Netlify for static deployment

## Part of The Codebreakers

This demo accompanies **The Codebreakers Part II: The Algorithms** — an introductory information security course by [Albert Hui (Security Ronin)](https://linkedin.com/in/albert.hui).

## Licence

MIT
