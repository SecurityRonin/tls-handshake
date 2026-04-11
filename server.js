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
    let filePath = req.url === '/' ? '/index.html' : req.url;
    filePath = join(webDir, filePath);
    try {
        const data = await readFile(filePath);
        const ext = extname(filePath);
        const mime = MIME[ext] || 'application/octet-stream';
        for (const [k, v] of Object.entries(SECURITY_HEADERS)) {
            res.setHeader(k, v);
        }
        res.writeHead(200, { 'Content-Type': mime });
        res.end(data);
    } catch {
        for (const [k, v] of Object.entries(SECURITY_HEADERS)) {
            res.setHeader(k, v);
        }
        res.writeHead(404, { 'Content-Type': 'text/plain' });
        res.end('Not found');
    }
}).listen(port, () => {
    console.log(`Server running at http://localhost:${port}`);
});
