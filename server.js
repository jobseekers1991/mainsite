const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = 3004;
const ROOT = __dirname;

const MIME = {
  '.html': 'text/html',
  '.css':  'text/css',
  '.js':   'application/javascript',
  '.png':  'image/png',
  '.jpg':  'image/jpeg',
  '.svg':  'image/svg+xml',
  '.ico':  'image/x-icon',
  '.json': 'application/json',
  '.woff2':'font/woff2',
};

function notFound(res) {
  fs.readFile(path.join(ROOT, '404.html'), (err, data) => {
    res.writeHead(404, { 'Content-Type': 'text/html' });
    res.end(err ? '<h2>404 — Not Found</h2>' : data);
  });
}

function tryServe(res, filePath) {
  fs.readFile(filePath, (err, data) => {
    if (err) {
      notFound(res);
      return;
    }
    const ext = path.extname(filePath).toLowerCase();
    const mime = MIME[ext] || 'application/octet-stream';
    res.writeHead(200, { 'Content-Type': mime });
    res.end(data);
  });
}

// Speed test endpoints for setup-check.html
const SPEED_CHUNK = crypto.randomBytes(1024 * 1024); // random so it can't be compressed
const MAX_TEST_BYTES = 50 * 1024 * 1024;
const NO_CACHE = { 'Cache-Control': 'no-store, no-cache, must-revalidate' };

function handleSpeedTest(req, res, urlPath) {
  if (urlPath === '/api/ping') {
    res.writeHead(200, { 'Content-Type': 'text/plain', ...NO_CACHE });
    res.end('pong');
    return true;
  }

  if (urlPath === '/api/speedtest/download') {
    const requested = parseInt(new URL(req.url, 'http://localhost').searchParams.get('bytes'), 10) || 5 * 1024 * 1024;
    let remaining = Math.min(Math.max(requested, 1024), MAX_TEST_BYTES);
    res.writeHead(200, { 'Content-Type': 'application/octet-stream', 'Content-Length': remaining, ...NO_CACHE });
    const write = () => {
      while (remaining > 0) {
        const chunk = remaining >= SPEED_CHUNK.length ? SPEED_CHUNK : SPEED_CHUNK.subarray(0, remaining);
        remaining -= chunk.length;
        if (!res.write(chunk)) { res.once('drain', write); return; }
      }
      res.end();
    };
    write();
    return true;
  }

  if (urlPath === '/api/speedtest/upload' && req.method === 'POST') {
    let received = 0;
    req.on('data', (chunk) => {
      received += chunk.length;
      if (received > MAX_TEST_BYTES) req.destroy();
    });
    req.on('end', () => {
      res.writeHead(200, { 'Content-Type': 'application/json', ...NO_CACHE });
      res.end(JSON.stringify({ bytes: received }));
    });
    return true;
  }

  return false;
}

http.createServer((req, res) => {
  let urlPath = req.url.split('?')[0];
  if (handleSpeedTest(req, res, urlPath)) return;
  if (urlPath === '/') urlPath = '/index.html';

  const filePath = path.join(ROOT, urlPath);
  // Never serve files from outside the site folder (e.g. /../secret)
  if (!filePath.startsWith(ROOT + path.sep)) return notFound(res);

  // Try exact path first; if no extension, try appending .html
  fs.access(filePath, fs.constants.F_OK, (err) => {
    if (!err) {
      tryServe(res, filePath);
    } else if (path.extname(urlPath) === '') {
      tryServe(res, filePath + '.html');
    } else {
      notFound(res);
    }
  });
}).listen(PORT, () => {
  console.log(`\n  Jobseekers.ph running at http://localhost:${PORT}\n`);
});
