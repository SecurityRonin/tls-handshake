import { defineConfig } from '@playwright/test';

export default defineConfig({
    testDir: './tests',
    use: {
        baseURL: 'http://localhost:3009',
        headless: true,
    },
    webServer: {
        command: 'python3 -m http.server 3009 --directory web',
        port: 3009,
        reuseExistingServer: true,
        timeout: 10000,
    },
});
