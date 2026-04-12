import { test, expect } from '@playwright/test';

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

    test('step 2: ServerHello — only key exchange pillar active (auth not yet established)', async ({ page }) => {
        await page.goto('/');
        await page.click('#next-step');
        await expect(page.locator('#step-indicator')).toContainText('Step 2');
        await expect(page.locator('#pillar-key-exchange')).toHaveClass(/active/);
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
