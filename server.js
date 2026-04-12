import { createServer } from 'http';
import { readFile } from 'fs/promises';
import { join, extname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = fileURLToPath(new URL('.', import.meta.url));
const webDir = join(__dirname, 'web');
const port = process.argv[2] || 3009;

const MIME = {
    '.html': 'text/html',
    '.css': 'text/css',
    '.js': 'application/javascript',
    '.json': 'application/json',
    '.xml': 'application/xml',
    '.txt': 'text/plain',
    '.ico': 'image/x-icon',
};

const SECURITY_HEADERS = {
    'X-Frame-Options': 'DENY',
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'no-referrer',
};

createServer(async (req, res) => {
    // Set security headers on every response
    for (const [k, v] of Object.entries(SECURITY_HEADERS)) {
        res.setHeader(k, v);
    }

    // Parse URL, strip query string and hash
    const urlPath = new URL(req.url, `http://localhost:${port}`).pathname;
    const safePath = urlPath === '/' ? '/index.html' : urlPath;
    const filePath = join(webDir, safePath);

    // Path traversal protection: resolved path must be inside webDir
    if (!filePath.startsWith(webDir)) {
        res.writeHead(403, { 'Content-Type': 'text/plain' });
        res.end('Forbidden');
        return;
    }

    try {
        const data = await readFile(filePath);
        const ext = extname(filePath);
        const mime = MIME[ext] || 'application/octet-stream';
        res.writeHead(200, { 'Content-Type': mime });
        res.end(data);
    } catch {
        res.writeHead(404, { 'Content-Type': 'text/plain' });
        res.end('Not found');
    }
}).listen(port, () => {
    console.log(`Server running at http://localhost:${port}`);
});
