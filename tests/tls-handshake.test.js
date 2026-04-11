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

    test('step 2: ServerHello — authentication pillar also lights up', async ({ page }) => {
        await page.goto('/');
        await page.click('#next-step');
        await expect(page.locator('#step-indicator')).toContainText('Step 2');
        await expect(page.locator('#pillar-key-exchange')).toHaveClass(/active/);
        await expect(page.locator('#pillar-authentication')).toHaveClass(/active/);
    });

    test('step 3: Certificate Verify — shows certificate chain', async ({ page }) => {
        await page.goto('/');
        await page.click('#next-step');
        await page.click('#next-step');
        await expect(page.locator('#step-indicator')).toContainText('Step 3');
        await expect(page.locator('#cert-chain')).toBeVisible();
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
        await expect(page.locator('#toggle-expired-cert')).toBeVisible();
    });

    test('has toggle for no forward secrecy', async ({ page }) => {
        await page.goto('/');
        await expect(page.locator('#toggle-no-fs')).toBeVisible();
    });

    test('has toggle for MITM attempt', async ({ page }) => {
        await page.goto('/');
        await expect(page.locator('#toggle-mitm')).toBeVisible();
    });

    test('has toggle for CBC mode', async ({ page }) => {
        await page.goto('/');
        await expect(page.locator('#toggle-cbc')).toBeVisible();
    });

    test('expired cert: step 3 shows failure', async ({ page }) => {
        await page.goto('/');
        await page.click('#toggle-expired-cert');
        await page.click('#next-step');
        await page.click('#next-step');
        await expect(page.locator('#failure-message')).toBeVisible();
        await expect(page.locator('#failure-message')).toContainText('expired');
    });

    test('MITM: step 3 shows interception detected', async ({ page }) => {
        await page.goto('/');
        await page.click('#toggle-mitm');
        await page.click('#next-step');
        await page.click('#next-step');
        await expect(page.locator('#failure-message')).toBeVisible();
        await expect(page.locator('#failure-message')).toContainText(/MITM|intercept|mismatch/i);
    });

    test('no forward secrecy: shows warning at step 4', async ({ page }) => {
        await page.goto('/');
        await page.click('#toggle-no-fs');
        for (let i = 0; i < 3; i++) await page.click('#next-step');
        await expect(page.locator('#warning-message')).toBeVisible();
        await expect(page.locator('#warning-message')).toContainText(/forward secrecy|recorded traffic/i);
    });

    test('CBC mode: shows padding oracle warning', async ({ page }) => {
        await page.goto('/');
        await page.click('#toggle-cbc');
        for (let i = 0; i < 4; i++) await page.click('#next-step');
        await expect(page.locator('#warning-message')).toBeVisible();
        await expect(page.locator('#warning-message')).toContainText(/CBC|padding/i);
    });
});

test.describe('Reset', () => {
    test('reset returns to step 1', async ({ page }) => {
        await page.goto('/');
        for (let i = 0; i < 3; i++) await page.click('#next-step');
        await page.click('#reset');
        await expect(page.locator('#step-indicator')).toContainText('Step 1');
    });

    test('reset clears failure toggles', async ({ page }) => {
        await page.goto('/');
        await page.click('#toggle-expired-cert');
        await page.click('#reset');
        await expect(page.locator('#toggle-expired-cert')).not.toBeChecked();
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

    test('clicking a row highlights it', async ({ page }) => {
        await page.goto('/');
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
        await page.click('.ws-packet-row:nth-child(3)');
        await expect(page.locator('#ws-detail')).toContainText('Certificate');
    });

    test('before loading: selecting packet 3 shows encrypted message', async ({ page }) => {
        await page.goto('/');
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
        await page.click('.ws-packet-row:nth-child(3)');
        await expect(page.locator('.wizard-step:nth-child(3)')).toHaveClass(/active/);
    });
});
