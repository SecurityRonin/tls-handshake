import { defineConfig } from '@playwright/test';

export default defineConfig({
    testDir: './tests',
    use: {
        baseURL: 'http://localhost:3009',
        headless: true,
    },
    webServer: {
        command: 'node server.js 3009',
        port: 3009,
        reuseExistingServer: true,
        timeout: 10000,
    },
});
