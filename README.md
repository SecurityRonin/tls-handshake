# TLS Handshake Visualised — See How HTTPS Works

[![Netlify Status](https://api.netlify.com/api/v1/badges/placeholder/deploy-status)](https://tls-handshake.securityronin.com)

Interactive step-by-step **TLS 1.3 handshake** demonstration. See how key exchange, authentication, encryption, and integrity work together. Toggle failure scenarios to see what breaks.

**[Live Demo →](https://tls-handshake.securityronin.com)**

## What It Teaches

Every HTTPS connection starts with a handshake. This demo walks through the TLS 1.3 protocol step by step, mapping each step to the four cryptographic pillars:

1. **ClientHello** — Key Exchange (ECDHE key share sent)
2. **ServerHello** — Authentication (certificate presented)
3. **Certificate Verify** — Chain of trust validated (Root CA → Intermediate → Leaf)
4. **Key Derivation** — Encryption (both sides derive the same session key)
5. **Encrypted Data** — Integrity (HMAC-tagged packets flow)
6. **Done** — All four pillars active. Connection secure.

## What-If Toggles

Toggle failure scenarios to see how the handshake breaks:

| Toggle | Effect |
|--------|--------|
| **Expired Certificate** | Step 3 fails — connection refused |
| **No Forward Secrecy** | Warning at step 4 — recorded traffic at risk |
| **MITM Attempt** | Step 3 catches the interception |
| **CBC Mode** | Warning at step 5 — padding oracle risk |

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

27 Playwright E2E tests covering security headers, happy path, failure toggles, and reset.

## Tech Stack

- Vanilla HTML/CSS/JS (single file, no framework)
- Playwright for E2E testing
- Netlify for static deployment

## Part of The Codebreakers

This demo accompanies **The Codebreakers Part II: The Algorithms** — an introductory information security course by [Albert Hui (Security Ronin)](https://linkedin.com/in/albert.hui).

## Licence

MIT
