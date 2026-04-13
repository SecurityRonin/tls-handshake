import { test, expect } from '@playwright/test';
import fs from 'node:fs';

test.describe('Capture fixtures', () => {
    test('generated capture manifest exists for high-value scenarios', async () => {
        const raw = fs.readFileSync('fixtures/captures/manifest.json', 'utf8');
        const manifest = JSON.parse(raw);
        expect(Object.keys(manifest).sort()).toEqual([
            'alpn-mismatch',
            'client-auth-fail',
            'freak',
            'hostname',
            'hrr',
            'logjam',
            'mitm',
            'mtls',
            'ocsp-revoked',
            'psk-resumption',
            'quic-http3',
            'sni',
            'zero-rtt',
        ]);
    });
});

test.describe('Security headers', () => {
    test('X-Frame-Options is DENY', async ({ request }) => {
        const res = await request.get('/');
        expect(res.headers()['x-frame-options']).toBe('DENY');
    });

    test('X-Content-Type-Options is nosniff', async ({ request }) => {
        const res = await request.get('/');
        expect(res.headers()['x-content-type-options']).toBe('nosniff');
    });

    test('Referrer-Policy is no-referrer', async ({ request }) => {
        const res = await request.get('/');
        expect(res.headers()['referrer-policy']).toBe('no-referrer');
    });
});

test.describe('Page structure', () => {
    test('title contains TLS Handshake', async ({ page }) => {
        await page.goto('/');
        await expect(page).toHaveTitle(/TLS Handshake/);
    });

    test('has client column', async ({ page }) => {
        await page.goto('/');
        await expect(page.locator('#client')).toBeVisible();
    });

    test('has server column', async ({ page }) => {
        await page.goto('/');
        await expect(page.locator('#server')).toBeVisible();
    });

    test('has four pillar indicators', async ({ page }) => {
        await page.goto('/');
        const pillars = page.locator('.pillar');
        await expect(pillars).toHaveCount(4);
    });

    test('pillars are: Key Exchange, Authentication, Encryption, Integrity', async ({ page }) => {
        await page.goto('/');
        await expect(page.locator('#pillar-key-exchange')).toContainText('Key Exchange');
        await expect(page.locator('#pillar-authentication')).toContainText('Authentication');
        await expect(page.locator('#pillar-encryption')).toContainText('Encryption');
        await expect(page.locator('#pillar-integrity')).toContainText('Integrity');
    });

    test('has Next Step button', async ({ page }) => {
        await page.goto('/');
        await expect(page.locator('#next-step')).toBeVisible();
    });

    test('has Reset button', async ({ page }) => {
        await page.goto('/');
        await expect(page.locator('#reset')).toBeVisible();
    });

    test('has step indicator showing step 1', async ({ page }) => {
        await page.goto('/');
        await expect(page.locator('#step-indicator')).toContainText('Step 1');
    });
});

test.describe('TLS 1.3 Happy Path', () => {
    test('step 1: ClientHello — key exchange pillar lights up', async ({ page }) => {
        await page.goto('/');
        await expect(page.locator('#step-indicator')).toContainText('Step 1');
        await expect(page.locator('.message-arrow')).toBeVisible();
        await expect(page.locator('#pillar-key-exchange')).toHaveClass(/active/);
    });

    test('step 2: ServerHello — key exchange and encryption active, auth not yet established', async ({ page }) => {
        await page.goto('/');
        await page.click('#next-step');
        await expect(page.locator('#step-indicator')).toContainText('Step 2');
        await expect(page.locator('#pillar-key-exchange')).toHaveClass(/active/);
        await expect(page.locator('#pillar-encryption')).toHaveClass(/active/);
        await expect(page.locator('#pillar-authentication')).not.toHaveClass(/active/);
    });

    test('step 3: Certificate — authentication and encryption pillars light up', async ({ page }) => {
        await page.goto('/');
        await page.click('#next-step');
        await page.click('#next-step');
        await expect(page.locator('#step-indicator')).toContainText('Step 3');
        await expect(page.locator('#pillar-authentication')).toHaveClass(/active/);
        await expect(page.locator('#pillar-encryption')).toHaveClass(/active/);
    });

    test('step 4: Key Derivation — encryption pillar lights up', async ({ page }) => {
        await page.goto('/');
        for (let i = 0; i < 3; i++) await page.click('#next-step');
        await expect(page.locator('#step-indicator')).toContainText('Step 4');
        await expect(page.locator('#pillar-encryption')).toHaveClass(/active/);
    });

    test('step 5: Encrypted Data — integrity pillar lights up', async ({ page }) => {
        await page.goto('/');
        for (let i = 0; i < 4; i++) await page.click('#next-step');
        await expect(page.locator('#step-indicator')).toContainText('Step 5');
        await expect(page.locator('#pillar-integrity')).toHaveClass(/active/);
    });

    test('step 6: Done — all four pillars active, success message', async ({ page }) => {
        await page.goto('/');
        for (let i = 0; i < 5; i++) await page.click('#next-step');
        await expect(page.locator('#step-indicator')).toContainText('Step 6');
        await expect(page.locator('.pillar.active')).toHaveCount(4);
        await expect(page.locator('#connection-status')).toContainText('secure');
    });
});

test.describe('What-If Toggles', () => {
    test('has toggle for expired certificate', async ({ page }) => {
        await page.goto('/');
        await expect(page.locator('#scenario-expired-cert')).toBeVisible();
    });

    test('has toggle for no forward secrecy', async ({ page }) => {
        await page.goto('/');
        await expect(page.locator('#scenario-tls12')).toBeVisible();
    });

    test('has toggle for MITM attempt', async ({ page }) => {
        await page.goto('/');
        await expect(page.locator('#scenario-mitm')).toBeVisible();
    });

    test('has toggle for CBC mode', async ({ page }) => {
        await page.goto('/');
        await expect(page.locator('#scenario-tls12-cbc')).toBeVisible();
    });

    test('expired cert: step 3 shows failure', async ({ page }) => {
        await page.goto('/');
        await page.click('#scenario-expired-cert');
        await page.click('#next-step');
        await page.click('#next-step');
        await expect(page.locator('#failure-message')).toBeVisible();
        await expect(page.locator('#failure-message')).toContainText('expired');
    });

    test('MITM: step 3 shows interception detected', async ({ page }) => {
        await page.goto('/');
        await page.click('#scenario-mitm');
        await page.click('#next-step');
        await page.click('#next-step');
        await expect(page.locator('#failure-message')).toBeVisible();
        await expect(page.locator('#failure-message')).toContainText(/MITM|intercept|mismatch/i);
    });

    test('no forward secrecy: shows warning at step 4', async ({ page }) => {
        await page.goto('/');
        await page.click('#scenario-tls12');
        for (let i = 0; i < 3; i++) await page.click('#next-step');
        await expect(page.locator('#warning-message')).toBeVisible();
        await expect(page.locator('#warning-message')).toContainText(/forward secrecy|recorded traffic/i);
    });

    test('CBC mode (TLS 1.2 downgrade): shows warning from step 3 onward', async ({ page }) => {
        await page.goto('/');
        await page.click('#scenario-tls12-cbc');
        for (let i = 0; i < 2; i++) await page.click('#next-step');
        await expect(page.locator('#warning-message')).toBeVisible();
        await expect(page.locator('#warning-message')).toContainText(/CBC|Lucky13|BEAST/i);
    });
});

test.describe('Reset', () => {
    test('reset returns to step 1', async ({ page }) => {
        await page.goto('/');
        for (let i = 0; i < 3; i++) await page.click('#next-step');
        await page.click('#reset');
        await expect(page.locator('#step-indicator')).toContainText('Step 1');
    });

    test('reset clears scenario selection', async ({ page }) => {
        await page.goto('/');
        await page.click('#scenario-expired-cert');
        await page.click('#reset');
        await expect(page.locator('#scenario-none')).toBeChecked();
    });
});

test.describe('Wireshark Packet List', () => {
    test('has 6 packet rows', async ({ page }) => {
        await page.goto('/');
        const rows = page.locator('.ws-packet-row');
        await expect(rows).toHaveCount(6);
    });

    test('packet 1 shows Client Hello', async ({ page }) => {
        await page.goto('/');
        await expect(page.locator('.ws-packet-row').first()).toContainText('Client Hello');
    });

    test('client-to-server rows have data-dir="c2s"', async ({ page }) => {
        await page.goto('/');
        // Packet 1 (ClientHello) is client→server
        await expect(page.locator('.ws-packet-row').first()).toHaveAttribute('data-dir', 'c2s');
    });

    test('server-to-client rows have data-dir="s2c"', async ({ page }) => {
        await page.goto('/');
        await page.click('#next-step'); // reveal row 2 (ServerHello — server→client)
        await expect(page.locator('.ws-packet-row:nth-child(2)')).toHaveAttribute('data-dir', 's2c');
    });

    test('clicking a row highlights it', async ({ page }) => {
        await page.goto('/');
        await page.click('#next-step'); // reveal row 2
        await page.click('.ws-packet-row:nth-child(2)');
        await expect(page.locator('.ws-packet-row:nth-child(2)')).toHaveClass(/selected/);
    });

    test('arrow down moves selection', async ({ page }) => {
        await page.goto('/');
        await page.click('.ws-packet-row:first-child');
        await page.keyboard.press('ArrowDown');
        await expect(page.locator('.ws-packet-row:nth-child(2)')).toHaveClass(/selected/);
    });

    test('arrow up moves selection', async ({ page }) => {
        await page.goto('/');
        for (let i = 0; i < 2; i++) await page.click('#next-step'); // reveal rows 2-3
        await page.click('.ws-packet-row:nth-child(3)');
        await page.keyboard.press('ArrowUp');
        await expect(page.locator('.ws-packet-row:nth-child(2)')).toHaveClass(/selected/);
    });

    test('selecting row updates detail pane', async ({ page }) => {
        await page.goto('/');
        await page.click('.ws-packet-row:first-child');
        await expect(page.locator('#ws-detail')).toContainText('Client Hello');
    });

    test('selecting row updates hex pane', async ({ page }) => {
        await page.goto('/');
        await page.click('.ws-packet-row:first-child');
        await expect(page.locator('#ws-hex')).not.toBeEmpty();
    });
});

test.describe('Wireshark Decrypt', () => {
    test('Load SSLKEYLOGFILE button exists', async ({ page }) => {
        await page.goto('/');
        await expect(page.locator('#load-keys')).toBeVisible();
    });

    test('before loading: packets 3-6 show Application Data', async ({ page }) => {
        await page.goto('/');
        for (let i = 3; i <= 6; i++) {
            await expect(page.locator(`.ws-packet-row:nth-child(${i}) .ws-info`)).toContainText('Application Data');
        }
    });

    test('after loading: packet 3 shows Certificate', async ({ page }) => {
        await page.goto('/');
        await page.click('#load-keys');
        await expect(page.locator('.ws-packet-row:nth-child(3) .ws-info')).toContainText('Certificate');
    });

    test('after loading: packet 5 protocol changes to HTTP/2', async ({ page }) => {
        await page.goto('/');
        await page.click('#load-keys');
        await expect(page.locator('.ws-packet-row:nth-child(5) .ws-proto')).toContainText('HTTP/2');
    });

    test('after loading: selecting packet 3 shows certificate detail', async ({ page }) => {
        await page.goto('/');
        await page.click('#load-keys');
        for (let i = 0; i < 2; i++) await page.click('#next-step'); // reveal row 3
        await page.click('.ws-packet-row:nth-child(3)');
        await expect(page.locator('#ws-detail')).toContainText('Certificate');
    });

    test('before loading: selecting packet 3 shows encrypted message', async ({ page }) => {
        await page.goto('/');
        for (let i = 0; i < 2; i++) await page.click('#next-step'); // reveal row 3
        await page.click('.ws-packet-row:nth-child(3)');
        await expect(page.locator('#ws-detail')).toContainText(/[Ee]ncrypted/);
    });

    test('educational callout appears after loading keys', async ({ page }) => {
        await page.goto('/');
        await page.click('#load-keys');
        await expect(page.locator('#decrypt-callout')).toBeVisible();
        await expect(page.locator('#decrypt-callout')).toContainText('TLS 1.3 encrypts everything after ServerHello');
    });

    test('load keys button changes to loaded state', async ({ page }) => {
        await page.goto('/');
        await page.click('#load-keys');
        await expect(page.locator('#load-keys')).toContainText(/loaded|Keys loaded/i);
    });
});

test.describe('Wizard Journey Header', () => {
    test('wizard header exists with 6 steps', async ({ page }) => {
        await page.goto('/');
        const steps = page.locator('.wizard-step');
        await expect(steps).toHaveCount(6);
    });

    test('selecting packet 1 highlights wizard step 1', async ({ page }) => {
        await page.goto('/');
        await page.click('.ws-packet-row:first-child');
        await expect(page.locator('.wizard-step').first()).toHaveClass(/active/);
    });

    test('selecting packet 3 highlights wizard step 3', async ({ page }) => {
        await page.goto('/');
        for (let i = 0; i < 2; i++) await page.click('#next-step'); // reveal row 3
        await page.click('.ws-packet-row:nth-child(3)');
        await expect(page.locator('.wizard-step:nth-child(3)')).toHaveClass(/active/);
    });
});

test.describe('What-If Scenarios — Extended', () => {
    // ── 1. TLS 1.3 0-RTT Early Data ──────────────────────────────────────────
    test('0-RTT: radio exists', async ({ page }) => {
        await page.goto('/');
        await expect(page.locator('#scenario-zero-rtt')).toBeVisible();
    });

    test('0-RTT: warning appears at step 5 (App Data)', async ({ page }) => {
        await page.goto('/');
        await page.click('#scenario-zero-rtt');
        for (let i = 0; i < 4; i++) await page.click('#next-step');
        await expect(page.locator('#step-indicator')).toContainText('Step 5');
        await expect(page.locator('#warning-message')).toBeVisible();
        await expect(page.locator('#warning-message')).toContainText('0-RTT Early Data');
    });

    test('0-RTT: next step is NOT disabled (warning only, no halt)', async ({ page }) => {
        await page.goto('/');
        await page.click('#scenario-zero-rtt');
        for (let i = 0; i < 4; i++) await page.click('#next-step');
        await expect(page.locator('#next-step')).not.toBeDisabled();
    });

    test('0-RTT: no effect when TLS 1.2 downgrade is active', async ({ page }) => {
        await page.goto('/');
        await page.click('#scenario-tls12');
        for (let i = 0; i < 4; i++) await page.click('#next-step');
        await expect(page.locator('#warning-message')).not.toContainText('0-RTT Early Data');
    });

    // ── 2. Certificate Pinning Failure ────────────────────────────────────────
    test('cert-pin: radio exists', async ({ page }) => {
        await page.goto('/');
        await expect(page.locator('#scenario-cert-pin')).toBeVisible();
    });

    test('cert-pin: failure appears at step 3 (Certificate)', async ({ page }) => {
        await page.goto('/');
        await page.click('#scenario-cert-pin');
        for (let i = 0; i < 2; i++) await page.click('#next-step');
        await expect(page.locator('#step-indicator')).toContainText('Step 3');
        await expect(page.locator('#failure-message')).toBeVisible();
        await expect(page.locator('#failure-message')).toContainText('Certificate pinning failure');
    });

    test('cert-pin: next step is disabled (halts)', async ({ page }) => {
        await page.goto('/');
        await page.click('#scenario-cert-pin');
        for (let i = 0; i < 2; i++) await page.click('#next-step');
        await expect(page.locator('#next-step')).toBeDisabled();
    });

    test('cert-pin: authentication pillar is NOT active after halt', async ({ page }) => {
        await page.goto('/');
        await page.click('#scenario-cert-pin');
        for (let i = 0; i < 2; i++) await page.click('#next-step');
        await expect(page.locator('#pillar-authentication')).not.toHaveClass(/active/);
    });

    test('cert-pin: no effect when TLS 1.2 downgrade is active', async ({ page }) => {
        await page.goto('/');
        await page.click('#scenario-tls12');
        for (let i = 0; i < 2; i++) await page.click('#next-step');
        await expect(page.locator('#failure-message')).not.toContainText('Certificate pinning failure');
    });

    // ── 3. PSK Session Resumption ─────────────────────────────────────────────
    test('PSK: radio exists', async ({ page }) => {
        await page.goto('/');
        await expect(page.locator('#scenario-psk')).toBeVisible();
    });

    test('PSK: warning appears at step 2 (ServerHello)', async ({ page }) => {
        await page.goto('/');
        await page.click('#scenario-psk');
        await page.click('#next-step');
        await expect(page.locator('#step-indicator')).toContainText('Step 2');
        await expect(page.locator('#warning-message')).toBeVisible();
        await expect(page.locator('#warning-message')).toContainText('PSK resumption');
    });

    test('PSK: next step is NOT disabled (warning only)', async ({ page }) => {
        await page.goto('/');
        await page.click('#scenario-psk');
        await page.click('#next-step');
        await expect(page.locator('#next-step')).not.toBeDisabled();
    });

    test('PSK: no effect when TLS 1.2 downgrade is active', async ({ page }) => {
        await page.goto('/');
        await page.click('#scenario-tls12');
        await page.click('#next-step');
        await expect(page.locator('#warning-message')).not.toContainText('PSK resumption');
    });

    // ── 4. SNI Leakage / No ECH ───────────────────────────────────────────────
    test('SNI: radio exists', async ({ page }) => {
        await page.goto('/');
        await expect(page.locator('#scenario-sni')).toBeVisible();
    });

    test('SNI: warning appears at step 1 (ClientHello)', async ({ page }) => {
        await page.goto('/');
        await page.click('#scenario-sni');
        await expect(page.locator('#step-indicator')).toContainText('Step 1');
        await expect(page.locator('#warning-message')).toBeVisible();
        await expect(page.locator('#warning-message')).toContainText('SNI leakage');
    });

    test('SNI: next step is NOT disabled (warning only)', async ({ page }) => {
        await page.goto('/');
        await page.click('#scenario-sni');
        await expect(page.locator('#next-step')).not.toBeDisabled();
    });

    test('SNI: no effect when TLS 1.2 downgrade is active', async ({ page }) => {
        await page.goto('/');
        await page.click('#scenario-tls12');
        await expect(page.locator('#warning-message')).not.toContainText('SNI leakage');
    });

    // ── 5. mTLS — Client Certificate ─────────────────────────────────────────
    test('mTLS: radio exists', async ({ page }) => {
        await page.goto('/');
        await expect(page.locator('#scenario-mtls')).toBeVisible();
    });

    test('mTLS: warning appears at step 4 (Client Finished)', async ({ page }) => {
        await page.goto('/');
        await page.click('#scenario-mtls');
        for (let i = 0; i < 3; i++) await page.click('#next-step');
        await expect(page.locator('#step-indicator')).toContainText('Step 4');
        await expect(page.locator('#warning-message')).toBeVisible();
        await expect(page.locator('#warning-message')).toContainText('Mutual TLS');
    });

    test('mTLS: next step is NOT disabled (warning only)', async ({ page }) => {
        await page.goto('/');
        await page.click('#scenario-mtls');
        for (let i = 0; i < 3; i++) await page.click('#next-step');
        await expect(page.locator('#next-step')).not.toBeDisabled();
    });

    test('mTLS: no effect when TLS 1.2 downgrade is active', async ({ page }) => {
        await page.goto('/');
        await page.click('#scenario-tls12');
        for (let i = 0; i < 3; i++) await page.click('#next-step');
        await expect(page.locator('#warning-message')).not.toContainText('Mutual TLS');
    });

    // ── 6. FREAK — Export RSA Downgrade ──────────────────────────────────────
    test('FREAK: radio exists', async ({ page }) => {
        await page.goto('/');
        await expect(page.locator('#scenario-freak')).toBeVisible();
    });

    test('FREAK: warning appears at step 2 (ServerHello) on TLS 1.2 path', async ({ page }) => {
        await page.goto('/');
        await page.click('#scenario-freak');
        await page.click('#next-step');
        await expect(page.locator('#step-indicator')).toContainText('Step 2');
        await expect(page.locator('#warning-message')).toBeVisible();
        await expect(page.locator('#warning-message')).toContainText('FREAK');
    });

    test('FREAK: next step is NOT disabled (attack succeeds silently, no halt)', async ({ page }) => {
        await page.goto('/');
        await page.click('#scenario-freak');
        await page.click('#next-step');
        await expect(page.locator('#next-step')).not.toBeDisabled();
    });

    test('FREAK: keyExchange pillar remains active (handshake completes with weak key)', async ({ page }) => {
        await page.goto('/');
        await page.click('#scenario-freak');
        await page.click('#next-step');
        await expect(page.locator('#pillar-key-exchange')).toHaveClass(/active/);
    });

    test('FREAK: plain TLS 1.2 downgrade does not show FREAK warning', async ({ page }) => {
        await page.goto('/');
        await page.click('#scenario-tls12');
        await page.click('#next-step');
        await expect(page.locator('#warning-message')).not.toContainText('FREAK');
    });

    // ── 7. Logjam — Export DHE Downgrade ─────────────────────────────────────
    test('Logjam: radio exists', async ({ page }) => {
        await page.goto('/');
        await expect(page.locator('#scenario-logjam')).toBeVisible();
    });

    test('Logjam: warning appears at step 2 (ServerHello) on TLS 1.2 path', async ({ page }) => {
        await page.goto('/');
        await page.click('#scenario-logjam');
        await page.click('#next-step');
        await expect(page.locator('#step-indicator')).toContainText('Step 2');
        await expect(page.locator('#warning-message')).toBeVisible();
        await expect(page.locator('#warning-message')).toContainText('Logjam');
    });

    test('Logjam: next step is NOT disabled (attack succeeds silently, no halt)', async ({ page }) => {
        await page.goto('/');
        await page.click('#scenario-logjam');
        await page.click('#next-step');
        await expect(page.locator('#next-step')).not.toBeDisabled();
    });

    test('Logjam: keyExchange pillar remains active (handshake completes with weak DHE)', async ({ page }) => {
        await page.goto('/');
        await page.click('#scenario-logjam');
        await page.click('#next-step');
        await expect(page.locator('#pillar-key-exchange')).toHaveClass(/active/);
    });

    // ── 8. TLS Renegotiation Injection ───────────────────────────────────────
    test('renego: radio exists', async ({ page }) => {
        await page.goto('/');
        await expect(page.locator('#scenario-renego')).toBeVisible();
    });

    test('renego: warning appears at step 5 (App Data)', async ({ page }) => {
        await page.goto('/');
        await page.click('#scenario-renego');
        for (let i = 0; i < 4; i++) await page.click('#next-step');
        await expect(page.locator('#step-indicator')).toContainText('Step 5');
        await expect(page.locator('#warning-message')).toBeVisible();
        await expect(page.locator('#warning-message')).toContainText('Renegotiation injection');
    });

    test('renego: next step is NOT disabled (warning only)', async ({ page }) => {
        await page.goto('/');
        await page.click('#scenario-renego');
        for (let i = 0; i < 4; i++) await page.click('#next-step');
        await expect(page.locator('#next-step')).not.toBeDisabled();
    });

    test('renego: no effect when TLS 1.2 downgrade is active', async ({ page }) => {
        await page.goto('/');
        await page.click('#scenario-tls12');
        for (let i = 0; i < 4; i++) await page.click('#next-step');
        await expect(page.locator('#warning-message')).not.toContainText('Renegotiation injection');
    });
});

test.describe('Scenario Protocol Trees', () => {
    test('FREAK: step 2 tree shows export cipher', async ({ page }) => {
        await page.goto('/');
        await page.click('#scenario-freak');
        await page.click('#next-step');
        await expect(page.locator('#ws-detail')).toContainText('EXPORT');
    });

    test('Logjam: step 2 tree shows weak DH parameters', async ({ page }) => {
        await page.goto('/');
        await page.click('#scenario-logjam');
        await page.click('#next-step');
        await expect(page.locator('#ws-detail')).toContainText('Server Key Exchange');
        await expect(page.locator('#ws-detail')).toContainText('512-bit export group');
    });

    test('expired cert: step 3 tree shows EXPIRED', async ({ page }) => {
        await page.goto('/');
        await page.click('#scenario-expired-cert');
        for (let i = 0; i < 2; i++) await page.click('#next-step');
        await expect(page.locator('#ws-detail')).toContainText('EXPIRED');
    });

    test('MITM: step 3 tree shows Evil Corp issuer', async ({ page }) => {
        await page.goto('/');
        await page.click('#scenario-mitm');
        for (let i = 0; i < 2; i++) await page.click('#next-step');
        await expect(page.locator('#ws-detail')).toContainText('Evil Corp');
    });

    test('cert-pin: step 3 tree shows SPKI mismatch', async ({ page }) => {
        await page.goto('/');
        await page.click('#scenario-cert-pin');
        for (let i = 0; i < 2; i++) await page.click('#next-step');
        await expect(page.locator('#ws-detail')).toContainText('SPKI');
    });

    test('PSK: step 2 tree shows pre_shared_key extension', async ({ page }) => {
        await page.goto('/');
        await page.click('#scenario-psk');
        await page.click('#next-step');
        await expect(page.locator('#ws-detail')).toContainText('pre_shared_key');
    });

    test('SNI: step 1 tree shows plaintext server name', async ({ page }) => {
        await page.goto('/');
        await page.click('#scenario-sni');
        await expect(page.locator('#ws-detail')).toContainText('example.com');
    });

    test('mTLS: step 4 tree shows client Certificate record', async ({ page }) => {
        await page.goto('/');
        await page.click('#scenario-mtls');
        for (let i = 0; i < 3; i++) await page.click('#next-step');
        await expect(page.locator('#ws-detail')).toContainText('CertificateRequest');
    });

    test('0-RTT: step 5 tree shows Early Data record', async ({ page }) => {
        await page.goto('/');
        await page.click('#scenario-zero-rtt');
        for (let i = 0; i < 4; i++) await page.click('#next-step');
        await expect(page.locator('#ws-detail')).toContainText('Early Data');
    });

    test('renego: step 5 tree shows injected prefix', async ({ page }) => {
        await page.goto('/');
        await page.click('#scenario-renego');
        for (let i = 0; i < 4; i++) await page.click('#next-step');
        await expect(page.locator('#ws-detail')).toContainText('ATTACKER');
    });
});

test.describe('What-If Scenarios — New', () => {
    // ── 1. ALPN Mismatch ──────────────────────────────────────────────────────
    test('ALPN: radio exists', async ({ page }) => {
        await page.goto('/');
        await expect(page.locator('#scenario-alpn')).toBeVisible();
    });

    test('ALPN: failure at step 3 containing no_application_protocol (fatal alert)', async ({ page }) => {
        await page.goto('/');
        await page.click('#scenario-alpn');
        for (let i = 0; i < 2; i++) await page.click('#next-step');
        await expect(page.locator('#step-indicator')).toContainText('Step 3');
        await expect(page.locator('#failure-message')).toBeVisible();
        await expect(page.locator('#failure-message')).toContainText('no_application_protocol');
    });

    test('ALPN: next step is disabled (fatal alert halts handshake)', async ({ page }) => {
        await page.goto('/');
        await page.click('#scenario-alpn');
        for (let i = 0; i < 2; i++) await page.click('#next-step');
        await expect(page.locator('#next-step')).toBeDisabled();
    });

    // ── 2. HelloRetryRequest ──────────────────────────────────────────────────
    test('HRR: radio exists', async ({ page }) => {
        await page.goto('/');
        await expect(page.locator('#scenario-hrr')).toBeVisible();
    });

    test('HRR: step 2 warning contains HelloRetryRequest', async ({ page }) => {
        await page.goto('/');
        await page.click('#scenario-hrr');
        await page.click('#next-step');
        await expect(page.locator('#step-indicator')).toContainText('Step 2');
        await expect(page.locator('#warning-message')).toBeVisible();
        await expect(page.locator('#warning-message')).toContainText('HelloRetryRequest');
    });

    test('HRR: packet 2 info shows Hello Retry Request', async ({ page }) => {
        await page.goto('/');
        await page.click('#scenario-hrr');
        await page.click('#next-step');
        await expect(page.locator('.ws-packet-row:nth-child(2) .ws-info')).toContainText('Hello Retry Request');
    });

    test('HRR: handshake completes (step 6 reachable)', async ({ page }) => {
        await page.goto('/');
        await page.click('#scenario-hrr');
        for (let i = 0; i < 5; i++) await page.click('#next-step');
        await expect(page.locator('#step-indicator')).toContainText('Step 6');
        await expect(page.locator('#connection-status')).toBeVisible();
    });

    test('HRR: next step is NOT disabled after step 2', async ({ page }) => {
        await page.goto('/');
        await page.click('#scenario-hrr');
        await page.click('#next-step');
        await expect(page.locator('#next-step')).not.toBeDisabled();
    });

    // ── 3. OCSP / Revoked Certificate ─────────────────────────────────────────
    test('OCSP: radio exists', async ({ page }) => {
        await page.goto('/');
        await expect(page.locator('#scenario-ocsp')).toBeVisible();
    });

    test('OCSP: failure at step 3 containing "revoked"', async ({ page }) => {
        await page.goto('/');
        await page.click('#scenario-ocsp');
        for (let i = 0; i < 2; i++) await page.click('#next-step');
        await expect(page.locator('#step-indicator')).toContainText('Step 3');
        await expect(page.locator('#failure-message')).toBeVisible();
        await expect(page.locator('#failure-message')).toContainText('revoked');
    });

    test('OCSP: next step is disabled', async ({ page }) => {
        await page.goto('/');
        await page.click('#scenario-ocsp');
        for (let i = 0; i < 2; i++) await page.click('#next-step');
        await expect(page.locator('#next-step')).toBeDisabled();
    });

    test('OCSP: auth pillar not active after halt', async ({ page }) => {
        await page.goto('/');
        await page.click('#scenario-ocsp');
        for (let i = 0; i < 2; i++) await page.click('#next-step');
        await expect(page.locator('#pillar-authentication')).not.toHaveClass(/active/);
    });

    // ── 4. Hostname Mismatch ──────────────────────────────────────────────────
    test('hostname: radio exists', async ({ page }) => {
        await page.goto('/');
        await expect(page.locator('#scenario-hostname')).toBeVisible();
    });

    test('hostname: failure at step 3 containing "hostname" or "mismatch"', async ({ page }) => {
        await page.goto('/');
        await page.click('#scenario-hostname');
        for (let i = 0; i < 2; i++) await page.click('#next-step');
        await expect(page.locator('#step-indicator')).toContainText('Step 3');
        await expect(page.locator('#failure-message')).toBeVisible();
        await expect(page.locator('#failure-message')).toContainText(/hostname|mismatch/i);
    });

    test('hostname: next step is disabled', async ({ page }) => {
        await page.goto('/');
        await page.click('#scenario-hostname');
        for (let i = 0; i < 2; i++) await page.click('#next-step');
        await expect(page.locator('#next-step')).toBeDisabled();
    });

    test('hostname: auth pillar not active after halt', async ({ page }) => {
        await page.goto('/');
        await page.click('#scenario-hostname');
        for (let i = 0; i < 2; i++) await page.click('#next-step');
        await expect(page.locator('#pillar-authentication')).not.toHaveClass(/active/);
    });

    // ── 5. Weak Signature Algorithm ───────────────────────────────────────────
    test('weak-sig: radio exists', async ({ page }) => {
        await page.goto('/');
        await expect(page.locator('#scenario-weak-sig')).toBeVisible();
    });

    test('weak-sig: failure at step 3 containing "SHA-1" or "weak"', async ({ page }) => {
        await page.goto('/');
        await page.click('#scenario-weak-sig');
        for (let i = 0; i < 2; i++) await page.click('#next-step');
        await expect(page.locator('#step-indicator')).toContainText('Step 3');
        await expect(page.locator('#failure-message')).toBeVisible();
        await expect(page.locator('#failure-message')).toContainText(/SHA-1|weak/i);
    });

    test('weak-sig: next step is disabled', async ({ page }) => {
        await page.goto('/');
        await page.click('#scenario-weak-sig');
        for (let i = 0; i < 2; i++) await page.click('#next-step');
        await expect(page.locator('#next-step')).toBeDisabled();
    });

    test('weak-sig: auth pillar not active after halt', async ({ page }) => {
        await page.goto('/');
        await page.click('#scenario-weak-sig');
        for (let i = 0; i < 2; i++) await page.click('#next-step');
        await expect(page.locator('#pillar-authentication')).not.toHaveClass(/active/);
    });

    // ── 6. QUIC / HTTP/3 ──────────────────────────────────────────────────────
    test('QUIC: radio exists', async ({ page }) => {
        await page.goto('/');
        await expect(page.locator('#scenario-quic')).toBeVisible();
    });

    test('QUIC: info/warning at step 1 containing "QUIC"', async ({ page }) => {
        await page.goto('/');
        await page.click('#scenario-quic');
        await expect(page.locator('#step-indicator')).toContainText('Step 1');
        await expect(page.locator('#warning-message')).toBeVisible();
        await expect(page.locator('#warning-message')).toContainText('QUIC');
    });

    test('QUIC: under-the-hood panel is visible with key phase and transport job', async ({ page }) => {
        await page.goto('/');
        await page.click('#scenario-quic');
        await expect(page.locator('#quic-under-hood')).toBeVisible();
        await expect(page.locator('#quic-under-hood')).toContainText('Key Phase');
        await expect(page.locator('#quic-under-hood')).toContainText('Initial keys');
    });

    test('QUIC: next step is NOT disabled', async ({ page }) => {
        await page.goto('/');
        await page.click('#scenario-quic');
        await expect(page.locator('#next-step')).not.toBeDisabled();
    });

    test('QUIC: handshake completes (step 6 reachable)', async ({ page }) => {
        await page.goto('/');
        await page.click('#scenario-quic');
        for (let i = 0; i < 5; i++) await page.click('#next-step');
        await expect(page.locator('#step-indicator')).toContainText('Step 6');
    });

    test('QUIC: under-the-hood panel switches from CRYPTO handshake to HTTP/3 stream view', async ({ page }) => {
        await page.goto('/');
        await page.click('#scenario-quic');
        await page.click('#next-step');
        await expect(page.locator('#quic-under-hood')).toContainText('Handshake keys');
        await expect(page.locator('#quic-under-hood')).toContainText('CRYPTO frames');
        for (let i = 0; i < 2; i++) await page.click('#next-step');
        await expect(page.locator('#quic-under-hood')).toContainText('1-RTT application keys');
        await expect(page.locator('#quic-under-hood')).toContainText('STREAM frame');
        await expect(page.locator('#quic-under-hood')).toContainText('HTTP/3 HEADERS');
    });

    // ── QUIC Swimlane ─────────────────────────────────────────────────────────
    test('QUIC: swimlane div is visible when QUIC selected', async ({ page }) => {
        await page.goto('/');
        await page.click('#scenario-quic');
        await expect(page.locator('#quic-swimlane')).toBeVisible();
    });

    test('QUIC: swimlane shows all three packet number space labels', async ({ page }) => {
        await page.goto('/');
        await page.click('#scenario-quic');
        await expect(page.locator('#quic-swimlane')).toContainText('Initial');
        await expect(page.locator('#quic-swimlane')).toContainText('Handshake');
        await expect(page.locator('#quic-swimlane')).toContainText('1-RTT');
    });

    test('QUIC: swimlane step 1 shows ClientHello arrow as active in Initial space', async ({ page }) => {
        await page.goto('/');
        await page.click('#scenario-quic');
        await expect(page.locator('#quic-swimlane .qsl-active')).toContainText('ClientHello');
        await expect(page.locator('#quic-swimlane .qsl-active')).toContainText('CRYPTO');
    });

    test('QUIC: swimlane step 2 marks step-1 arrow as visited', async ({ page }) => {
        await page.goto('/');
        await page.click('#scenario-quic');
        await page.click('#next-step');
        await expect(page.locator('#quic-swimlane .qsl-visited')).toContainText('ClientHello');
    });

    test('QUIC: swimlane step 2 shows server Certificate in Handshake space as active', async ({ page }) => {
        await page.goto('/');
        await page.click('#scenario-quic');
        await page.click('#next-step');
        await expect(page.locator('#quic-swimlane .qsl-row[data-space="handshake"] .qsl-active')).toContainText('Certificate');
    });

    test('QUIC: swimlane step 4 shows HTTP/3 GET in 1-RTT space as active', async ({ page }) => {
        await page.goto('/');
        await page.click('#scenario-quic');
        for (let i = 0; i < 3; i++) await page.click('#next-step');
        await expect(page.locator('#quic-swimlane .qsl-row[data-space="1rtt"] .qsl-active')).toContainText('GET');
    });

    test('QUIC: hex pane is hidden when QUIC selected', async ({ page }) => {
        await page.goto('/');
        await page.click('#scenario-quic');
        await expect(page.locator('#ws-hex')).toBeHidden();
    });

    // ── QUIC per-lane context ─────────────────────────────────────────────────
    test('QUIC: step 1 Under The Hood shows ClientHello-specific content (connection ID)', async ({ page }) => {
        await page.goto('/');
        await page.click('#scenario-quic');
        await expect(page.locator('#quic-under-hood')).toContainText('connection ID');
        await expect(page.locator('#quic-under-hood')).toContainText('CRYPTO frame');
    });

    test('QUIC: step 2 defaults to Handshake lane content (server auth flight)', async ({ page }) => {
        await page.goto('/');
        await page.click('#scenario-quic');
        await page.click('#next-step');
        await expect(page.locator('#quic-under-hood')).toContainText('Handshake keys');
        await expect(page.locator('#quic-under-hood')).toContainText('server auth flight');
    });

    test('QUIC: hovering Initial lane at step 2 shows Initial-specific content', async ({ page }) => {
        await page.goto('/');
        await page.click('#scenario-quic');
        await page.click('#next-step');
        await page.hover('#quic-lanes .qsl-row[data-space="initial"]');
        // 'crypto level upgrades' only appears in the Initial ServerHello arrow summary
        await expect(page.locator('#quic-under-hood')).toContainText('crypto level upgrades');
    });

    test('QUIC: hovering Handshake lane at step 2 shows Handshake-specific content', async ({ page }) => {
        await page.goto('/');
        await page.click('#scenario-quic');
        await page.click('#next-step');
        await page.hover('#quic-lanes .qsl-row[data-space="handshake"]');
        // 'server auth flight' only appears in the Handshake server flight arrow payload
        await expect(page.locator('#quic-under-hood')).toContainText('server auth flight');
    });

    test('QUIC: mousing off lanes restores step-default content', async ({ page }) => {
        await page.goto('/');
        await page.click('#scenario-quic');
        await page.click('#next-step');
        await page.hover('#quic-lanes .qsl-row[data-space="initial"]');
        await page.hover('#step-indicator');
        await expect(page.locator('#quic-under-hood')).toContainText('server auth flight');
    });

    test('QUIC: lane rows are keyboard-focusable (tabindex="0")', async ({ page }) => {
        await page.goto('/');
        await page.click('#scenario-quic');
        const row = page.locator('#quic-lanes .qsl-row[data-space="initial"]');
        await expect(row).toHaveAttribute('tabindex', '0');
    });

    test('QUIC: focusing Initial lane at step 2 shows Initial-specific content', async ({ page }) => {
        await page.goto('/');
        await page.click('#scenario-quic');
        await page.click('#next-step');
        await page.focus('#quic-lanes .qsl-row[data-space="initial"]');
        await expect(page.locator('#quic-under-hood')).toContainText('crypto level upgrades');
    });

    test('QUIC: focusing Handshake lane at step 2 shows Handshake-specific content', async ({ page }) => {
        await page.goto('/');
        await page.click('#scenario-quic');
        await page.click('#next-step');
        await page.focus('#quic-lanes .qsl-row[data-space="handshake"]');
        await expect(page.locator('#quic-under-hood')).toContainText('server auth flight');
    });

    test('QUIC: tabbing away from lanes restores step-default content', async ({ page }) => {
        await page.goto('/');
        await page.click('#scenario-quic');
        await page.click('#next-step');
        await page.focus('#quic-lanes .qsl-row[data-space="initial"]');
        await page.focus('#next-step');
        await expect(page.locator('#quic-under-hood')).toContainText('server auth flight');
    });

    test.describe('touch device', () => {
        test.use({ hasTouch: true });

        test('QUIC: tapping Initial lane at step 2 shows Initial-specific content (touch)', async ({ page }) => {
            await page.goto('/');
            await page.tap('#scenario-quic');
            await page.tap('#next-step');
            await page.tap('#quic-lanes .qsl-row[data-space="initial"]');
            await expect(page.locator('#quic-under-hood')).toContainText('crypto level upgrades');
        });

        test('QUIC: tapping Handshake lane at step 2 shows Handshake-specific content (touch)', async ({ page }) => {
            await page.goto('/');
            await page.tap('#scenario-quic');
            await page.tap('#next-step');
            await page.tap('#quic-lanes .qsl-row[data-space="handshake"]');
            await expect(page.locator('#quic-under-hood')).toContainText('server auth flight');
        });

        test('QUIC: tapping outside lanes restores step-default content (touch)', async ({ page }) => {
            await page.goto('/');
            await page.tap('#scenario-quic');
            await page.tap('#next-step');
            await page.tap('#quic-lanes .qsl-row[data-space="initial"]');
            await page.tap('#step-indicator');
            await expect(page.locator('#quic-under-hood')).toContainText('server auth flight');
        });
    });

    // ── 7. Session Ticket Theft ───────────────────────────────────────────────
    test('ticket-theft: radio exists', async ({ page }) => {
        await page.goto('/');
        await expect(page.locator('#scenario-ticket-theft')).toBeVisible();
    });

    test('ticket-theft: warning at step 2 containing "ticket"', async ({ page }) => {
        await page.goto('/');
        await page.click('#scenario-ticket-theft');
        await page.click('#next-step');
        await expect(page.locator('#step-indicator')).toContainText('Step 2');
        await expect(page.locator('#warning-message')).toBeVisible();
        await expect(page.locator('#warning-message')).toContainText(/ticket/i);
    });

    test('ticket-theft: next step is NOT disabled', async ({ page }) => {
        await page.goto('/');
        await page.click('#scenario-ticket-theft');
        await page.click('#next-step');
        await expect(page.locator('#next-step')).not.toBeDisabled();
    });

    test('ticket-theft: handshake completes (step 6 reachable)', async ({ page }) => {
        await page.goto('/');
        await page.click('#scenario-ticket-theft');
        for (let i = 0; i < 5; i++) await page.click('#next-step');
        await expect(page.locator('#step-indicator')).toContainText('Step 6');
    });

    // ── 8. Record Tampering ───────────────────────────────────────────────────
    test('record-tamper: radio exists', async ({ page }) => {
        await page.goto('/');
        await expect(page.locator('#scenario-record-tamper')).toBeVisible();
    });

    test('record-tamper: failure at step 5 containing "AEAD" or "tamper"', async ({ page }) => {
        await page.goto('/');
        await page.click('#scenario-record-tamper');
        for (let i = 0; i < 4; i++) await page.click('#next-step');
        await expect(page.locator('#step-indicator')).toContainText('Step 5');
        await expect(page.locator('#failure-message')).toBeVisible();
        await expect(page.locator('#failure-message')).toContainText(/AEAD|tamper/i);
    });

    test('record-tamper: next step is disabled', async ({ page }) => {
        await page.goto('/');
        await page.click('#scenario-record-tamper');
        for (let i = 0; i < 4; i++) await page.click('#next-step');
        await expect(page.locator('#next-step')).toBeDisabled();
    });

    test('record-tamper: auth pillar remains active (auth established before tamper)', async ({ page }) => {
        await page.goto('/');
        await page.click('#scenario-record-tamper');
        for (let i = 0; i < 4; i++) await page.click('#next-step');
        await expect(page.locator('#pillar-authentication')).toHaveClass(/active/);
    });

    // ── 9. Client Authentication Failure ─────────────────────────────────────
    test('client-auth-fail: radio exists', async ({ page }) => {
        await page.goto('/');
        await expect(page.locator('#scenario-client-auth-fail')).toBeVisible();
    });

    test('client-auth-fail: failure at step 4 containing "client" and "certificate"', async ({ page }) => {
        await page.goto('/');
        await page.click('#scenario-client-auth-fail');
        for (let i = 0; i < 3; i++) await page.click('#next-step');
        await expect(page.locator('#step-indicator')).toContainText('Step 4');
        await expect(page.locator('#failure-message')).toBeVisible();
        await expect(page.locator('#failure-message')).toContainText(/client/i);
        await expect(page.locator('#failure-message')).toContainText(/certificate/i);
    });

    test('client-auth-fail: next step is disabled', async ({ page }) => {
        await page.goto('/');
        await page.click('#scenario-client-auth-fail');
        for (let i = 0; i < 3; i++) await page.click('#next-step');
        await expect(page.locator('#next-step')).toBeDisabled();
    });

    test('client-auth-fail: server auth pillar remains active (server was authenticated; only client cert absent)', async ({ page }) => {
        await page.goto('/');
        await page.click('#scenario-client-auth-fail');
        for (let i = 0; i < 3; i++) await page.click('#next-step');
        await expect(page.locator('#pillar-authentication')).toHaveClass(/active/);
    });

    // ── 10. ECH Success ───────────────────────────────────────────────────────
    test('ECH: radio exists', async ({ page }) => {
        await page.goto('/');
        await expect(page.locator('#scenario-ech')).toBeVisible();
    });

    test('ECH: info/warning at step 1 containing "ECH" or "Encrypted Client Hello"', async ({ page }) => {
        await page.goto('/');
        await page.click('#scenario-ech');
        await expect(page.locator('#step-indicator')).toContainText('Step 1');
        await expect(page.locator('#warning-message')).toBeVisible();
        await expect(page.locator('#warning-message')).toContainText(/ECH|Encrypted Client Hello/i);
    });

    test('ECH: next step is NOT disabled', async ({ page }) => {
        await page.goto('/');
        await page.click('#scenario-ech');
        await expect(page.locator('#next-step')).not.toBeDisabled();
    });

    test('ECH: handshake completes (step 6 reachable)', async ({ page }) => {
        await page.goto('/');
        await page.click('#scenario-ech');
        for (let i = 0; i < 5; i++) await page.click('#next-step');
        await expect(page.locator('#step-indicator')).toContainText('Step 6');
    });

    // ── 11. HSTS ──────────────────────────────────────────────────────────────
    test('HSTS: radio exists', async ({ page }) => {
        await page.goto('/');
        await expect(page.locator('#scenario-hsts')).toBeVisible();
    });

    test('HSTS: warning at step 6 containing "HSTS"', async ({ page }) => {
        await page.goto('/');
        await page.click('#scenario-hsts');
        for (let i = 0; i < 5; i++) await page.click('#next-step');
        await expect(page.locator('#step-indicator')).toContainText('Step 6');
        await expect(page.locator('#warning-message')).toBeVisible();
        await expect(page.locator('#warning-message')).toContainText('HSTS');
    });

    test('HSTS: step 6 is last step (next-step disabled)', async ({ page }) => {
        await page.goto('/');
        await page.click('#scenario-hsts');
        for (let i = 0; i < 5; i++) await page.click('#next-step');
        await expect(page.locator('#next-step')).toBeDisabled();
    });
});

test.describe('Scenario Protocol Trees — New', () => {
    test('ALPN: step 3 protocol tree shows no_application_protocol', async ({ page }) => {
        await page.goto('/');
        await page.click('#scenario-alpn');
        for (let i = 0; i < 2; i++) await page.click('#next-step');
        await expect(page.locator('#ws-detail')).toContainText('no_application_protocol');
    });

    test('HRR: step 2 protocol tree shows HelloRetryRequest', async ({ page }) => {
        await page.goto('/');
        await page.click('#scenario-hrr');
        await page.click('#next-step');
        await expect(page.locator('#ws-detail')).toContainText('HelloRetryRequest');
    });

    test('OCSP: step 3 protocol tree shows revoked', async ({ page }) => {
        await page.goto('/');
        await page.click('#scenario-ocsp');
        for (let i = 0; i < 2; i++) await page.click('#next-step');
        await expect(page.locator('#ws-detail')).toContainText('revoked');
    });

    test('hostname: step 3 protocol tree shows mismatch', async ({ page }) => {
        await page.goto('/');
        await page.click('#scenario-hostname');
        for (let i = 0; i < 2; i++) await page.click('#next-step');
        await expect(page.locator('#ws-detail')).toContainText('mismatch');
    });

    test('weak-sig: step 3 protocol tree shows SHA-1', async ({ page }) => {
        await page.goto('/');
        await page.click('#scenario-weak-sig');
        for (let i = 0; i < 2; i++) await page.click('#next-step');
        await expect(page.locator('#ws-detail')).toContainText('SHA-1');
    });

    test('QUIC: step 1 protocol tree shows CRYPTO frame', async ({ page }) => {
        await page.goto('/');
        await page.click('#scenario-quic');
        await expect(page.locator('#ws-detail')).toContainText('CRYPTO Frame');
    });

    test('QUIC: step 1 protocol tree shows packet number space', async ({ page }) => {
        await page.goto('/');
        await page.click('#scenario-quic');
        await expect(page.locator('#ws-detail')).toContainText('Packet Number Space');
    });

    test('ticket-theft: step 2 protocol tree shows stolen', async ({ page }) => {
        await page.goto('/');
        await page.click('#scenario-ticket-theft');
        await page.click('#next-step');
        await expect(page.locator('#ws-detail')).toContainText('stolen');
    });

    test('record-tamper: step 5 protocol tree shows authentication tag', async ({ page }) => {
        await page.goto('/');
        await page.click('#scenario-record-tamper');
        for (let i = 0; i < 4; i++) await page.click('#next-step');
        await expect(page.locator('#ws-detail')).toContainText('authentication tag');
    });

    test('client-auth-fail: step 4 protocol tree shows CertificateRequest', async ({ page }) => {
        await page.goto('/');
        await page.click('#scenario-client-auth-fail');
        for (let i = 0; i < 3; i++) await page.click('#next-step');
        await expect(page.locator('#ws-detail')).toContainText('CertificateRequest');
    });

    test('ECH: step 1 protocol tree shows encrypted_client_hello', async ({ page }) => {
        await page.goto('/');
        await page.click('#scenario-ech');
        await expect(page.locator('#ws-detail')).toContainText('encrypted_client_hello');
    });

    test('HSTS: step 6 protocol tree shows Strict-Transport-Security (HTTP response row)', async ({ page }) => {
        await page.goto('/');
        await page.click('#scenario-hsts');
        for (let i = 0; i < 5; i++) await page.click('#next-step');
        await expect(page.locator('#step-indicator')).toContainText('Step 6');
        await expect(page.locator('#ws-detail')).toContainText('Strict-Transport-Security');
    });
});

test.describe('Scenario ordering', () => {
    test('scenarios are ordered by pedagogical groups', async ({ page }) => {
        await page.goto('/');
        const values = await page.locator('.toggles input[type="radio"]').evaluateAll(
            els => els.map(el => el.value)
        );
        const expected = [
            // TLS 1.3 baseline & variations
            'none', 'hrr', 'psk', 'zero-rtt', 'mtls',
            // Certificate & auth failures
            'expired-cert', 'hostname', 'weak-sig', 'ocsp', 'cert-pin', 'mitm', 'client-auth-fail',
            // Privacy & extensions
            'sni', 'ech', 'alpn', 'hsts', 'quic',
            // Active attacks
            'ticket-theft', 'record-tamper',
            // TLS 1.2 downgrade
            'tls12', 'tls12-cbc', 'tls12-expired', 'freak', 'logjam', 'renego',
        ];
        expect(values).toEqual(expected);
    });

    test('section labels appear in correct order', async ({ page }) => {
        await page.goto('/');
        const labels = await page.locator('.toggles .toggle-section-label').allTextContents();
        expect(labels).toEqual([
            'Certificate & Auth Failures',
            'Privacy & Extensions',
            'Active Attacks',
            'TLS 1.2 Downgrade',
        ]);
    });
});

test.describe('Correctness fixes', () => {
    // Issue 1: ALPN — no_application_protocol is a fatal alert, handshake must abort
    test('ALPN: handshake fails at step 3 (no_application_protocol is a fatal alert, not a fallback)', async ({ page }) => {
        await page.goto('/');
        await page.click('#scenario-alpn');
        for (let i = 0; i < 2; i++) await page.click('#next-step');
        await expect(page.locator('#step-indicator')).toContainText('Step 3');
        await expect(page.locator('#failure-message')).toBeVisible();
        await expect(page.locator('#failure-message')).toContainText('no_application_protocol');
    });

    test('ALPN: next step is disabled after fatal alert', async ({ page }) => {
        await page.goto('/');
        await page.click('#scenario-alpn');
        for (let i = 0; i < 2; i++) await page.click('#next-step');
        await expect(page.locator('#next-step')).toBeDisabled();
    });

    test('ALPN: protocol tree shows encrypted application_data carrying a fatal alert, not EncryptedExtensions', async ({ page }) => {
        await page.goto('/');
        await page.click('#scenario-alpn');
        for (let i = 0; i < 2; i++) await page.click('#next-step');
        await expect(page.locator('#ws-detail')).toContainText('Application Data (23)');
        await expect(page.locator('#ws-detail')).toContainText('Alert Message (decrypted)');
        await expect(page.locator('#ws-detail')).not.toContainText('EncryptedExtensions');
    });

    test('OCSP: protocol tree shows stapled status inside Certificate, not EncryptedExtensions', async ({ page }) => {
        await page.goto('/');
        await page.click('#scenario-ocsp');
        for (let i = 0; i < 2; i++) await page.click('#next-step');
        await expect(page.locator('#ws-detail')).toContainText('CertificateEntry');
        await expect(page.locator('#ws-detail')).toContainText('status_request');
        await expect(page.locator('#ws-detail')).not.toContainText('EncryptedExtensions');
    });

    // Issue 2: generic noFs "RSA key exchange" warning must not fire for Logjam (DHE) or Renegotiation
    test('Logjam: step 4 warning does not mention RSA key exchange (Logjam is DHE, not RSA)', async ({ page }) => {
        await page.goto('/');
        await page.click('#scenario-logjam');
        for (let i = 0; i < 3; i++) await page.click('#next-step');
        await expect(page.locator('#step-indicator')).toContainText('Step 4');
        await expect(page.locator('#warning-message')).not.toContainText('RSA key exchange');
    });

    test('Renego: step 4 warning does not mention RSA key exchange (renegotiation is not a key-exchange issue)', async ({ page }) => {
        await page.goto('/');
        await page.click('#scenario-renego');
        for (let i = 0; i < 3; i++) await page.click('#next-step');
        await expect(page.locator('#step-indicator')).toContainText('Step 4');
        await expect(page.locator('#warning-message')).not.toContainText('RSA key exchange');
    });

    // Issue 3: record-tamper fires post-handshake; failure banner must not say "Handshake failed"
    test('record-tamper: failure message says "Connection aborted", not "Handshake failed"', async ({ page }) => {
        await page.goto('/');
        await page.click('#scenario-record-tamper');
        for (let i = 0; i < 4; i++) await page.click('#next-step');
        await expect(page.locator('#failure-message')).toContainText('Connection aborted');
        await expect(page.locator('#failure-message')).not.toContainText('Handshake failed');
    });

    // Issue 5: OCSP label must be narrowed to what is actually modelled (stapled revocation)
    test('OCSP radio label is scoped to what is modelled: revoked certificate via OCSP staple', async ({ page }) => {
        await page.goto('/');
        const labelText = await page.locator('label[for="scenario-ocsp"]').textContent();
        expect(labelText).toContain('Revoked certificate (OCSP staple)');
    });
});

test.describe('ALPN wizard timeline override', () => {
    // The wizard timeline must not label step 3 "Certificate" when ALPN aborts before the cert flight.
    // The "Auth established" chip must not appear since auth was never established.

    test('ALPN step 3: wizard label is not "Certificate"', async ({ page }) => {
        await page.goto('/');
        await page.click('#scenario-alpn');
        for (let i = 0; i < 2; i++) await page.click('#next-step');
        const label = await page.locator('.wizard-step:nth-child(3) .ws-label').textContent();
        expect(label).not.toMatch(/Certificate/i);
    });

    test('ALPN step 3: wizard label mentions Alert or ALPN', async ({ page }) => {
        await page.goto('/');
        await page.click('#scenario-alpn');
        for (let i = 0; i < 2; i++) await page.click('#next-step');
        const label = await page.locator('.wizard-step:nth-child(3) .ws-label').textContent();
        expect(label).toMatch(/Alert|ALPN/i);
    });

    test('ALPN step 3: "Auth established" chip does not appear in wizard', async ({ page }) => {
        await page.goto('/');
        await page.click('#scenario-alpn');
        for (let i = 0; i < 2; i++) await page.click('#next-step');
        await expect(page.locator('.ws-chip-auth')).not.toBeVisible();
    });
});

test.describe('ALPN step content override', () => {
    // When ALPN alert fires at step 3, the server never sends a cert flight.
    // Auth and encryption pillars must NOT be active; step content must describe the alert, not the cert exchange.

    test('ALPN step 3: authentication pillar is NOT active (cert never sent)', async ({ page }) => {
        await page.goto('/');
        await page.click('#scenario-alpn');
        for (let i = 0; i < 2; i++) await page.click('#next-step');
        await expect(page.locator('#pillar-authentication')).not.toHaveClass(/active/);
    });

    test('ALPN step 3: encryption pillar IS active (fatal alert is itself encrypted under handshake key)', async ({ page }) => {
        await page.goto('/');
        await page.click('#scenario-alpn');
        for (let i = 0; i < 2; i++) await page.click('#next-step');
        await expect(page.locator('#pillar-encryption')).toHaveClass(/active/);
    });

    test('ALPN step 3: arrow text describes Alert, not cert flight', async ({ page }) => {
        await page.goto('/');
        await page.click('#scenario-alpn');
        for (let i = 0; i < 2; i++) await page.click('#next-step');
        const arrow = await page.locator('#arrow-label').textContent();
        expect(arrow).toMatch(/Alert|no_application_protocol/i);
        expect(arrow).not.toMatch(/Certificate|CertificateVerify/i);
    });

    test('ALPN step 3: step description does not mention cert exchange', async ({ page }) => {
        await page.goto('/');
        await page.click('#scenario-alpn');
        for (let i = 0; i < 2; i++) await page.click('#next-step');
        const desc = await page.locator('#step-description').textContent();
        expect(desc).not.toMatch(/EncryptedExtensions|CertificateVerify/i);
    });
});

test.describe('RFC reference accuracy', () => {
    // ECH extension 0xfe0d is registered under RFC 9849 ("TLS Encrypted Client Hello").
    // RFC 9258 is "Importing External PSKs for TLS 1.3" — completely unrelated.
    test('ECH protocol tree cites RFC 9849, not RFC 9258', async ({ page }) => {
        await page.goto('/');
        await page.click('#scenario-ech');
        const detail = await page.locator('#ws-detail').textContent();
        expect(detail).toContain('RFC 9849');
        expect(detail).not.toContain('RFC 9258');
    });

    // RFC 7469 is HTTP Public Key Pinning (HPKP) — a deprecated browser mechanism.
    // App-level SPKI pinning has no single RFC; citing RFC 7469 is misleading.
    test('cert-pin protocol tree does not cite deprecated RFC 7469 (HPKP)', async ({ page }) => {
        await page.goto('/');
        await page.click('#scenario-cert-pin');
        for (let i = 0; i < 2; i++) await page.click('#next-step');
        await expect(page.locator('#ws-detail')).not.toContainText('RFC 7469');
    });

    // RFC 8446 §4.4.3: if client Certificate message is empty, client MUST NOT send CertificateVerify.
    // The protocol tree header must not imply CertificateVerify is sent.
    test('client-auth-fail protocol tree header does not list CertificateVerify', async ({ page }) => {
        await page.goto('/');
        await page.click('#scenario-client-auth-fail');
        for (let i = 0; i < 3; i++) await page.click('#next-step');
        await expect(page.locator('#ws-detail')).not.toContainText('CertificateVerify');
    });

    // RFC 8446 §4.4.4: client always sends Finished, even when Certificate is empty.
    // Finished is NOT conditional on having a certificate — only CertificateVerify is skipped.
    test('client-auth-fail protocol tree includes client Finished message', async ({ page }) => {
        await page.goto('/');
        await page.click('#scenario-client-auth-fail');
        for (let i = 0; i < 3; i++) await page.click('#next-step');
        await expect(page.locator('#ws-detail')).toContainText('Finished');
    });
});

test.describe('Attacker node visibility', () => {
    // Scenarios that model an active on-path attacker must show the attacker endpoint in the diagram.
    async function attackerVisible(page) {
        return page.locator('#mitm-attacker').isVisible();
    }

    test('MITM: attacker node visible', async ({ page }) => {
        await page.goto('/');
        await page.click('#scenario-mitm');
        expect(await attackerVisible(page)).toBe(true);
    });

    test('FREAK: attacker node visible', async ({ page }) => {
        await page.goto('/');
        await page.click('#scenario-freak');
        expect(await attackerVisible(page)).toBe(true);
    });

    test('Logjam: attacker node visible', async ({ page }) => {
        await page.goto('/');
        await page.click('#scenario-logjam');
        expect(await attackerVisible(page)).toBe(true);
    });

    test('Renegotiation injection: attacker node visible', async ({ page }) => {
        await page.goto('/');
        await page.click('#scenario-renego');
        expect(await attackerVisible(page)).toBe(true);
    });

    test('Session ticket theft: attacker node visible', async ({ page }) => {
        await page.goto('/');
        await page.click('#scenario-ticket-theft');
        expect(await attackerVisible(page)).toBe(true);
    });

    test('Record tampering: attacker node visible', async ({ page }) => {
        await page.goto('/');
        await page.click('#scenario-record-tamper');
        expect(await attackerVisible(page)).toBe(true);
    });

    test('Baseline (no scenario): attacker node hidden', async ({ page }) => {
        await page.goto('/');
        expect(await attackerVisible(page)).toBe(false);
    });
});
