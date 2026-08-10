const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const url = require('url');
const crypto = require('crypto');
const net = require('net');
const tls = require('tls');

const PORT = process.env.PORT || 3000;
const ROOT_DIR = __dirname;
const USERS_FILE = path.join(ROOT_DIR, 'users.json');
const TOKENS_FILE = path.join(ROOT_DIR, 'sessions.json');
const SMTP_CONFIG_FILE = path.join(ROOT_DIR, 'smtp-config.json');
const UPLOADS_DIR = path.join(ROOT_DIR, 'uploads');
const SHARED_DIR = path.join(ROOT_DIR, 'shared');
const GOOGLE_OAUTH_FILE = path.join(ROOT_DIR, 'google-oauth.json');

if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR, { recursive: true });
if (!fs.existsSync(SHARED_DIR)) fs.mkdirSync(SHARED_DIR, { recursive: true });


function loadJson(file) {
  try {
    if (!fs.existsSync(file)) return {};
    const data = fs.readFileSync(file, 'utf8');
    return JSON.parse(data || '{}');
  } catch (e) { return {}; }
}

function saveJson(file, data) {
  try {
    fs.writeFileSync(file, JSON.stringify(data, null, 4), 'utf8');
    return true;
  } catch (e) { return false; }
}

function getGoogleOAuthConfig() {
  try { return loadJson(GOOGLE_OAUTH_FILE); } catch (e) { return {}; }
}

// Generic HTTPS POST helper for OAuth token exchange
function httpsPost(hostname, reqPath, data, headers = {}) {
  return new Promise((resolve, reject) => {
    const postData = typeof data === 'string' ? data : new URLSearchParams(data).toString();
    const req = https.request({
      hostname, path: reqPath, method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Content-Length': Buffer.byteLength(postData),
        ...headers
      }
    }, res => {
      let body = '';
      res.on('data', c => body += c);
      res.on('end', () => { try { resolve(JSON.parse(body)); } catch (e) { resolve(body); } });
    });
    req.on('error', reject);
    req.write(postData);
    req.end();
  });
}

// Generic HTTPS GET helper for fetching user profile
function httpsGet(hostname, reqPath, headers = {}) {
  return new Promise((resolve, reject) => {
    const req = https.request({ hostname, path: reqPath, method: 'GET', headers }, res => {
      let body = '';
      res.on('data', c => body += c);
      res.on('end', () => { try { resolve(JSON.parse(body)); } catch (e) { resolve(body); } });
    });
    req.on('error', reject);
    req.end();
  });
}

function hashPassword(password, salt = null) {
  if (!salt) salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.pbkdf2Sync(password, salt, 10000, 64, 'sha512').toString('hex');
  return { salt, hash };
}

function crc32(buf) {
  let crc = 0xFFFFFFFF;
  for (let i = 0; i < buf.length; i++) {
    crc ^= buf[i];
    for (let j = 0; j < 8; j++) {
      crc = (crc >>> 1) ^ (crc & 1 ? 0xEDB88320 : 0);
    }
  }
  return (crc ^ 0xFFFFFFFF) >>> 0;
}

function createZipArchive(fileEntries) {
  const parts = [];
  const cdEntries = [];
  let offset = 0;

  for (const file of fileEntries) {
    const filenameBuffer = Buffer.from(file.filename, 'utf8');
    const dataBuffer = file.buffer;
    const crc = crc32(dataBuffer);
    const size = dataBuffer.length;

    const header = Buffer.alloc(30);
    header.writeUInt32LE(0x04034b50, 0);
    header.writeUInt16LE(20, 4);
    header.writeUInt16LE(0, 6);
    header.writeUInt16LE(0, 8);
    header.writeUInt16LE(0, 10);
    header.writeUInt16LE(0, 12);
    header.writeUInt32LE(crc, 14);
    header.writeUInt32LE(size, 18);
    header.writeUInt32LE(size, 22);
    header.writeUInt16LE(filenameBuffer.length, 26);
    header.writeUInt16LE(0, 28);

    parts.push(header, filenameBuffer, dataBuffer);

    const cdHeader = Buffer.alloc(46);
    cdHeader.writeUInt32LE(0x02014b50, 0);
    cdHeader.writeUInt16LE(20, 4);
    cdHeader.writeUInt16LE(20, 6);
    cdHeader.writeUInt16LE(0, 8);
    cdHeader.writeUInt16LE(0, 10);
    cdHeader.writeUInt16LE(0, 12);
    cdHeader.writeUInt16LE(0, 14);
    cdHeader.writeUInt32LE(crc, 16);
    cdHeader.writeUInt32LE(size, 20);
    cdHeader.writeUInt32LE(size, 24);
    cdHeader.writeUInt16LE(filenameBuffer.length, 28);
    cdHeader.writeUInt16LE(0, 30);
    cdHeader.writeUInt16LE(0, 32);
    cdHeader.writeUInt16LE(0, 34);
    cdHeader.writeUInt16LE(0, 36);
    cdHeader.writeUInt32LE(0, 38);
    cdHeader.writeUInt32LE(offset, 42);

    cdEntries.push(cdHeader, filenameBuffer);
    offset += header.length + filenameBuffer.length + dataBuffer.length;
  }

  const cdStartOffset = offset;
  let cdSize = 0;
  for (const part of cdEntries) {
    parts.push(part);
    cdSize += part.length;
  }

  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(0, 4);
  eocd.writeUInt16LE(0, 6);
  eocd.writeUInt16LE(fileEntries.length, 8);
  eocd.writeUInt16LE(fileEntries.length, 10);
  eocd.writeUInt32LE(cdSize, 12);
  eocd.writeUInt32LE(cdStartOffset, 16);
  eocd.writeUInt16LE(0, 20);

  parts.push(eocd);
  return Buffer.concat(parts);
}

function verifyPassword(password, salt, hash) {
  const check = crypto.pbkdf2Sync(password, salt, 10000, 64, 'sha512').toString('hex');
  return check === hash;
}

function escapeHtml(str) {
  if (!str) return '';
  return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function stripHtml(html) {
  if (!html) return '';
  return String(html).replace(/<[^>]*>?/gm, '');
}

const AUDIT_LOG_FILE = path.join(ROOT_DIR, 'audit_logs.json');

function logAudit(userId, action, details = {}, ip = '127.0.0.1') {
  try {
    const logs = loadJson(AUDIT_LOG_FILE);
    if (!Array.isArray(logs.entries)) logs.entries = [];
    logs.entries.unshift({
      id: uuidv4(),
      userId: userId || 'anonymous',
      action,
      details,
      ip,
      timestamp: new Date().toISOString()
    });
    if (logs.entries.length > 1000) logs.entries = logs.entries.slice(0, 1000);
    saveJson(AUDIT_LOG_FILE, logs);
  } catch (e) {}
}

function uuidv4() {
  return crypto.randomUUID();
}

function getUserFiles(userId) {
  const userDir = path.join(SHARED_DIR, userId);
  const file = path.join(userDir, 'files.json');
  return loadJson(file);
}

function saveUserFiles(userId, data) {
  const userDir = path.join(SHARED_DIR, userId);
  if (!fs.existsSync(userDir)) fs.mkdirSync(userDir, { recursive: true });
  const file = path.join(userDir, 'files.json');
  return saveJson(file, data);
}

function getUserDocs(userId) {
  const userDir = path.join(SHARED_DIR, userId);
  const file = path.join(userDir, 'documents.json');
  return loadJson(file);
}

function saveUserDocs(userId, data) {
  const userDir = path.join(SHARED_DIR, userId);
  if (!fs.existsSync(userDir)) fs.mkdirSync(userDir, { recursive: true });
  const file = path.join(userDir, 'documents.json');
  return saveJson(file, data);
}

function getUserFolders(userId) {
  const userDir = path.join(SHARED_DIR, userId);
  const file = path.join(userDir, 'folders.json');
  return loadJson(file);
}

function saveUserFolders(userId, data) {
  const userDir = path.join(SHARED_DIR, userId);
  if (!fs.existsSync(userDir)) fs.mkdirSync(userDir, { recursive: true });
  const file = path.join(userDir, 'folders.json');
  return saveJson(file, data);
}

function getAuthToken(req) {
  let token = null;
  const authHeader = req.headers['authorization'] || '';
  if (authHeader.startsWith('Bearer ')) {
    token = authHeader.substring(7).trim();
  } else {
    const parsed = url.parse(req.url, true);
    token = parsed.query ? (parsed.query.token || null) : null;
  }
  if (token) {
    token = String(token).replace(/^["']|["']$/g, '').trim();
  }
  return token || null;
}

function authenticate(req) {
  const token = getAuthToken(req);
  if (!token) return null;
  const tokens = loadJson(TOKENS_FILE);
  const userId = tokens[token];
  if (!userId) return null;
  const users = loadJson(USERS_FILE);
  const user = users[userId];
  if (!user) return null;
  return { id: userId, ...user };
}

function getUserSmtpConfig(userId = null) {
  const users = loadJson(USERS_FILE);
  const globalSmtp = loadJson(SMTP_CONFIG_FILE);
  const defaultSmtp = { host: 'smtp.gmail.com', port: '587', user: '', pass: '', fromName: 'Abdullah File Share', fromEmail: '' };

  // 1. If user configured their own personal SMTP settings in Settings page
  if (userId && users[userId] && users[userId].smtpConfig) {
    const userCfg = users[userId].smtpConfig;
    if (userCfg.user && userCfg.pass) {
      return { ...defaultSmtp, ...userCfg };
    }
  }

  // 2. Global system default (if explicitly set in smtp-config.json)
  if (globalSmtp && globalSmtp.user && globalSmtp.pass) {
    return { ...defaultSmtp, ...globalSmtp };
  }

  return { ...defaultSmtp };
}

function formatSheetToHtml(sheetsData) {
  if (!sheetsData || Object.keys(sheetsData).length === 0) {
    return `<p><i>(Empty spreadsheet)</i></p>`;
  }
  let maxRow = 1, maxCol = 0;
  for (const k in sheetsData) {
    const m = k.match(/([A-Z]+)(\d+)/);
    if (m) {
      maxRow = Math.max(maxRow, parseInt(m[2]));
      let colIdx = 0;
      for (let i = 0; i < m[1].length; i++) colIdx = colIdx * 26 + (m[1].charCodeAt(i) - 64);
      maxCol = Math.max(maxCol, colIdx);
    }
  }

  function getColName(idx) {
    let name = '';
    while (idx > 0) {
      let rem = (idx - 1) % 26;
      name = String.fromCharCode(65 + rem) + name;
      idx = Math.floor((idx - 1) / 26);
    }
    return name;
  }

  let html = `<table border="1" cellpadding="8" cellspacing="0" style="border-collapse:collapse;width:100%;background:#1a1a28;color:#e2e2f0;border-color:#2a2a3a;font-family:sans-serif;"><thead><tr style="background:#12121a;color:#a29bfe;"><th>#</th>`;
  for (let c = 1; c <= maxCol; c++) {
    html += `<th>${getColName(c)}</th>`;
  }
  html += `</tr></thead><tbody>`;

  for (let r = 1; r <= maxRow; r++) {
    html += `<tr><td style="background:#12121a;font-weight:bold;text-align:center;">${r}</td>`;
    for (let c = 1; c <= maxCol; c++) {
      const cellId = getColName(c) + r;
      const cell = sheetsData[cellId] || {};
      const val = cell.value || cell.formula || '';
      let style = '';
      if (cell.bold) style += 'font-weight:bold;';
      if (cell.italic) style += 'font-style:italic;';
      if (cell.color) style += `color:${cell.color};`;
      if (cell.bg) style += `background:${cell.bg};`;
      html += `<td style="${style}">${escapeHtml(val)}</td>`;
    }
    html += `</tr>`;
  }
  html += `</tbody></table>`;
  return html;
}

function formatSheetToText(sheetsData) {
  if (!sheetsData || Object.keys(sheetsData).length === 0) return '(Empty spreadsheet)';
  let maxRow = 1, maxCol = 0;
  for (const k in sheetsData) {
    const m = k.match(/([A-Z]+)(\d+)/);
    if (m) {
      maxRow = Math.max(maxRow, parseInt(m[2]));
      let colIdx = 0;
      for (let i = 0; i < m[1].length; i++) colIdx = colIdx * 26 + (m[1].charCodeAt(i) - 64);
      maxCol = Math.max(maxCol, colIdx);
    }
  }
  function getColName(idx) {
    let name = '';
    while (idx > 0) {
      let rem = (idx - 1) % 26;
      name = String.fromCharCode(65 + rem) + name;
      idx = Math.floor((idx - 1) / 26);
    }
    return name;
  }
  let text = '';
  for (let r = 1; r <= maxRow; r++) {
    const rowVals = [];
    for (let c = 1; c <= maxCol; c++) {
      const cellId = getColName(c) + r;
      const cell = sheetsData[cellId] || {};
      rowVals.push(cell.value || cell.formula || '');
    }
    text += rowVals.join('\t') + '\n';
  }
  return text;
}

async function sendSmtpEmail(cfg, to, subject, htmlBody, textBody, attachments = []) {
  return new Promise((resolve, reject) => {
    const host = cfg.host || 'smtp.gmail.com';
    const port = parseInt(cfg.port || 587);
    const user = cfg.user || '';
    const pass = cfg.pass || '';
    const fromName = cfg.fromName || 'Abdullah File Share';
    const fromEmail = cfg.fromEmail || user;

    if (!host || !user || !pass) {
      return reject(new Error('SMTP Host, User, and Password are required.'));
    }

    const isSecurePort = (port === 465);
    let activeSocket = null;
    let step = 0;
    let buffer = '';

    const send = (cmd) => {
      if (activeSocket && !activeSocket.destroyed) {
        activeSocket.write(cmd + '\r\n');
      }
    };

    const processLine = (line) => {
      const code = parseInt(line.substring(0, 3));
      const isFinal = line.length < 4 || line.charAt(3) === ' ';
      if (!isFinal) return; // Wait for final line of multi-line response (e.g. "250 ")

      if (step === 0 && code === 220) {
        step = 1;
        send(`EHLO localhost`);
      } else if (step === 1 && code === 250) {
        if (isSecurePort) {
          step = 4;
          send('AUTH LOGIN');
        } else {
          step = 2;
          send('STARTTLS');
        }
      } else if (step === 2 && code === 220) {
        step = 3;
        const tlsSocket = tls.connect({ socket: activeSocket, rejectUnauthorized: false }, () => {
          activeSocket = tlsSocket;
          send(`EHLO localhost`);
        });
        tlsSocket.on('data', onData);
        tlsSocket.on('error', (err) => reject(err));
      } else if (step === 3 && code === 250) {
        step = 4;
        send('AUTH LOGIN');
      } else if (step === 4 && code === 334) {
        step = 5;
        send(Buffer.from(user).toString('base64'));
      } else if (step === 5 && code === 334) {
        step = 6;
        send(Buffer.from(pass).toString('base64'));
      } else if (step === 6 && code === 235) {
        step = 7;
        send(`MAIL FROM: <${fromEmail}>`);
      } else if (step === 7 && code === 250) {
        step = 8;
        send(`RCPT TO: <${to}>`);
      } else if (step === 8 && code === 250) {
        step = 9;
        send('DATA');
      } else if (step === 9 && code === 354) {
        step = 10;
        const mixedBoundary = '----=_MixedPart_' + crypto.randomBytes(16).toString('hex');
        const altBoundary = '----=_AltPart_' + crypto.randomBytes(16).toString('hex');
        
        const mailLines = [];
        mailLines.push(`From: "=?UTF-8?B?${Buffer.from(fromName).toString('base64')}?=" <${fromEmail}>`);
        mailLines.push(`To: <${to}>`);
        mailLines.push(`Subject: =?UTF-8?B?${Buffer.from(subject).toString('base64')}?=`);
        mailLines.push(`MIME-Version: 1.0`);

        if (attachments && attachments.length > 0) {
          mailLines.push(`Content-Type: multipart/mixed; boundary="${mixedBoundary}"`);
          mailLines.push(``);
          mailLines.push(`--${mixedBoundary}`);
          mailLines.push(`Content-Type: multipart/alternative; boundary="${altBoundary}"`);
          mailLines.push(``);
          mailLines.push(`--${altBoundary}`);
          mailLines.push(`Content-Type: text/plain; charset=UTF-8`);
          mailLines.push(`Content-Transfer-Encoding: base64`);
          mailLines.push(``);
          mailLines.push(Buffer.from(textBody).toString('base64'));
          mailLines.push(``);
          mailLines.push(`--${altBoundary}`);
          mailLines.push(`Content-Type: text/html; charset=UTF-8`);
          mailLines.push(`Content-Transfer-Encoding: base64`);
          mailLines.push(``);
          mailLines.push(Buffer.from(htmlBody).toString('base64'));
          mailLines.push(``);
          mailLines.push(`--${altBoundary}--`);

          for (const att of attachments) {
            const filenameEncoded = `=?UTF-8?B?${Buffer.from(att.filename).toString('base64')}?=`;
            const attBuffer = Buffer.isBuffer(att.content) ? att.content : Buffer.from(att.content);
            
            mailLines.push(``);
            mailLines.push(`--${mixedBoundary}`);
            mailLines.push(`Content-Type: ${att.contentType || 'application/octet-stream'}; name="${filenameEncoded}"`);
            mailLines.push(`Content-Disposition: attachment; filename="${filenameEncoded}"`);
            mailLines.push(`Content-Transfer-Encoding: base64`);
            mailLines.push(``);
            
            const base64Str = attBuffer.toString('base64');
            for (let i = 0; i < base64Str.length; i += 76) {
              mailLines.push(base64Str.substring(i, i + 76));
            }
          }
          mailLines.push(``);
          mailLines.push(`--${mixedBoundary}--`);
        } else {
          mailLines.push(`Content-Type: multipart/alternative; boundary="${altBoundary}"`);
          mailLines.push(``);
          mailLines.push(`--${altBoundary}`);
          mailLines.push(`Content-Type: text/plain; charset=UTF-8`);
          mailLines.push(`Content-Transfer-Encoding: base64`);
          mailLines.push(``);
          mailLines.push(Buffer.from(textBody).toString('base64'));
          mailLines.push(``);
          mailLines.push(`--${altBoundary}`);
          mailLines.push(`Content-Type: text/html; charset=UTF-8`);
          mailLines.push(`Content-Transfer-Encoding: base64`);
          mailLines.push(``);
          mailLines.push(Buffer.from(htmlBody).toString('base64'));
          mailLines.push(``);
          mailLines.push(`--${altBoundary}--`);
        }

        mailLines.push(`.`);
        send(mailLines.join('\r\n'));
      } else if (step === 10 && code === 250) {
        step = 11;
        send('QUIT');
        if (activeSocket) activeSocket.end();
        resolve(true);
      } else if (code >= 400) {
        reject(new Error(`SMTP Error (${code}): ${line.trim()}`));
      }
    };

    const onData = (chunk) => {
      buffer += chunk.toString('utf8');
      let lines = buffer.split('\r\n');
      buffer = lines.pop(); // keep last incomplete line in buffer
      for (const line of lines) {
        if (line.trim().length > 0) {
          processLine(line);
        }
      }
    };

    if (isSecurePort) {
      activeSocket = tls.connect(port, host, { rejectUnauthorized: false }, () => {});
      activeSocket.on('data', onData);
      activeSocket.on('error', (err) => reject(err));
    } else {
      activeSocket = net.connect(port, host, () => {});
      activeSocket.on('data', onData);
      activeSocket.on('error', (err) => reject(err));
    }

    activeSocket.setTimeout(15000, () => {
      activeSocket.destroy();
      reject(new Error('SMTP Connection timed out (15s)'));
    });
  });
}

function parseMultipart(req, callback) {
  let body = Buffer.alloc(0);
  const MAX_SIZE = 100 * 1024 * 1024; // 100MB
  let aborted = false;

  req.on('data', chunk => {
    if (aborted) return;
    body = Buffer.concat([body, chunk]);
    if (body.length > MAX_SIZE) {
      aborted = true;
      req.destroy();
      return callback(new Error('File size exceeds maximum limit (100MB)'), []);
    }
  });

  req.on('end', () => {
    if (aborted) return;
    const contentType = req.headers['content-type'] || '';
    const match = contentType.match(/boundary=(?:"([^"]+)"|([^;]+))/i);
    if (!match) return callback(new Error('No boundary found'), []);
    const boundaryStr = '--' + (match[1] || match[2]);
    const boundary = Buffer.from(boundaryStr);
    
    const parts = [];
    let start = body.indexOf(boundary);
    while (start !== -1) {
      const nextBIdx = body.indexOf(boundary, start + boundary.length);
      if (nextBIdx === -1) break;
      
      const partBuffer = body.slice(start + boundary.length, nextBIdx);
      const headerEnd = partBuffer.indexOf('\r\n\r\n');
      if (headerEnd !== -1) {
        const headerStr = partBuffer.slice(0, headerEnd).toString('utf8');
        let data = partBuffer.slice(headerEnd + 4);
        if (data.length >= 2 && data[data.length - 2] === 13 && data[data.length - 1] === 10) {
          data = data.slice(0, data.length - 2);
        }
        
        const nameMatch = headerStr.match(/name="([^"]+)"/);
        const filenameMatch = headerStr.match(/filename="([^"]+)"/);
        const typeMatch = headerStr.match(/Content-Type:\s*([^\r\n]+)/i);

        if (filenameMatch) {
          parts.push({
            name: nameMatch ? nameMatch[1] : 'file',
            filename: filenameMatch[1],
            type: typeMatch ? typeMatch[1].trim() : 'application/octet-stream',
            data: data
          });
        }
      }
      start = nextBIdx;
    }
    callback(null, parts);
  });
}

function serveStatic(res, filePath, contentType = 'text/html') {
  fs.readFile(filePath, (err, content) => {
    if (err) {
      res.writeHead(404, { 'Content-Type': 'text/plain' });
      res.end('404 Not Found');
    } else {
      res.writeHead(200, { 'Content-Type': contentType });
      res.end(content);
    }
  });
}

const server = http.createServer((req, res) => {
  const parsedUrl = url.parse(req.url, true);
  const pathname = parsedUrl.pathname;
  const method = req.method.toUpperCase();

  const sendJson = (data, code = 200) => {
    res.writeHead(code, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
    res.end(JSON.stringify(data));
  };

  const sendError = (msg, code = 400) => {
    sendJson({ success: false, error: msg }, code);
  };

  if (method === 'OPTIONS') {
    res.writeHead(200, {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization'
    });
    return res.end();
  }

  // --- Static Page Routing ---
  if (pathname === '/') return serveStatic(res, path.join(ROOT_DIR, 'public', 'landing.html'));
  if (pathname === '/app') return serveStatic(res, path.join(ROOT_DIR, 'public', 'index.html'));
  if (pathname === '/login') return serveStatic(res, path.join(ROOT_DIR, 'public', 'login.html'));
  if (pathname === '/documents') return serveStatic(res, path.join(ROOT_DIR, 'public', 'documents.html'));
  if (pathname === '/admin') return serveStatic(res, path.join(ROOT_DIR, 'public', 'admin.html'));
  if (pathname === '/settings') return serveStatic(res, path.join(ROOT_DIR, 'public', 'settings.html'));
  if (pathname === '/setup-2fa') return serveStatic(res, path.join(ROOT_DIR, 'public', 'setup-2fa.html'));
  if (pathname === '/forgot-password') return serveStatic(res, path.join(ROOT_DIR, 'public', 'forgot-password.html'));
  if (pathname.startsWith('/share/')) return serveStatic(res, path.join(ROOT_DIR, 'public', 'share.html'));

  // Static Assets Fallback (.css, .js, .png, .ico, .svg)
  const ext = path.extname(pathname).toLowerCase();
  if (['.css', '.js', '.png', '.jpg', '.jpeg', '.svg', '.ico', '.json'].includes(ext)) {
    const assetPath = path.join(ROOT_DIR, 'public', pathname);
    if (fs.existsSync(assetPath)) {
      const mimeTypes = {
        '.css': 'text/css', '.js': 'application/javascript', '.png': 'image/png',
        '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.svg': 'image/svg+xml', '.ico': 'image/x-icon'
      };
      return serveStatic(res, assetPath, mimeTypes[ext] || 'text/plain');
    }
  }

  // --- Google OAuth Routes ---
  if (pathname === '/auth/google') {
    const cfg = getGoogleOAuthConfig();
    if (!cfg.clientId) {
      res.writeHead(302, { Location: '/login?error=google_not_configured' });
      return res.end();
    }
    const hostHeader = req.headers.host || `localhost:${PORT}`;
    const protocol = req.headers['x-forwarded-proto'] || (hostHeader.includes('loca.lt') ? 'https' : 'http');
    const dynamicRedirectUri = `${protocol}://${hostHeader}/auth/google/callback`;

    const parsedReq = url.parse(req.url, true);
    const state = parsedReq.query.state || '';
    const params = new URLSearchParams({
      client_id: cfg.clientId,
      redirect_uri: dynamicRedirectUri,
      response_type: 'code',
      scope: 'openid email profile',
      access_type: 'offline',
      prompt: 'select_account',
      ...(state ? { state } : {})
    });
    res.writeHead(302, { Location: `https://accounts.google.com/o/oauth2/v2/auth?${params}` });
    return res.end();
  }

  if (pathname === '/auth/google/callback') {
    const parsed = url.parse(req.url, true);
    const code = parsed.query.code;
    const errorParam = parsed.query.error;

    if (errorParam || !code) {
      res.writeHead(302, { Location: '/login?error=google_denied' });
      return res.end();
    }

    try {
      return (async () => {
        const cfg = getGoogleOAuthConfig();
        const hostHeader = req.headers.host || `localhost:${PORT}`;
        const protocol = req.headers['x-forwarded-proto'] || (hostHeader.includes('loca.lt') ? 'https' : 'http');
        const redirectUri = `${protocol}://${hostHeader}/auth/google/callback`;

      // Exchange code for tokens
      const tokenData = await httpsPost('oauth2.googleapis.com', '/token', {
        code,
        client_id: cfg.clientId,
        client_secret: cfg.clientSecret,
        redirect_uri: redirectUri,
        grant_type: 'authorization_code'
      });

      if (!tokenData.access_token) {
        res.writeHead(302, { Location: '/login?error=google_token_failed' });
        return res.end();
      }

      // Fetch user profile from Google
      const profile = await httpsGet('www.googleapis.com', '/oauth2/v2/userinfo', {
        Authorization: `Bearer ${tokenData.access_token}`
      });

      if (!profile.email) {
        res.writeHead(302, { Location: '/login?error=google_profile_failed' });
        return res.end();
      }

      // Find or create user
      const users = loadJson(USERS_FILE);
      let userId = null;
      let foundUser = null;

      // Check if user is linking account from Settings page (via session cookie or query state)
      const stateParam = parsed.query.state || '';
      let linkUid = null;
      if (stateParam.startsWith('link:')) {
        const linkToken = stateParam.split(':')[1];
        if (linkToken) {
          const tokens = loadJson(TOKENS_FILE);
          linkUid = tokens[linkToken] || null;
        }
      }

      // Check if this Google account is ALREADY linked to a DIFFERENT user account
      let existingOwner = null;
      for (const uid in users) {
        if (users[uid].googleId === profile.id) {
          existingOwner = users[uid];
          break;
        }
      }

      // If linking from active session (Settings page)
      if (linkUid && users[linkUid]) {
        // If Google account is already linked to ANOTHER user, block linking and display friendly message
        if (existingOwner && existingOwner.id !== linkUid) {
          res.writeHead(302, { Location: '/settings?error=google_already_linked' });
          return res.end();
        }

        userId = linkUid;
        users[userId].googleId = profile.id;
        users[userId].googleAuth = true;
        if (profile.picture) users[userId].avatar = profile.picture;
        saveJson(USERS_FILE, users);
      } else {
        // Check if user already exists by email or googleId
        for (const uid in users) {
          if ((users[uid].email && users[uid].email.toLowerCase() === profile.email.toLowerCase()) || users[uid].googleId === profile.id) {
            userId = uid;
            foundUser = users[uid];
            break;
          }
        }

        // Auto-register if new user
        let isNewUser = false;
        if (!userId) {
          isNewUser = true;
          userId = uuidv4();
          const baseUsername = (profile.name || profile.email.split('@')[0]).replace(/[^a-zA-Z0-9_]/g, '').substring(0, 20) || 'user';
          let username = baseUsername;
          let counter = 1;
          const existingUsernames = Object.values(users).map(u => u.username ? u.username.toLowerCase() : '');
          while (existingUsernames.includes(username.toLowerCase())) {
            username = baseUsername + counter++;
          }

          users[userId] = {
            username,
            email: profile.email,
            googleId: profile.id,
            avatar: profile.picture || null,
            salt: '',
            hash: '',
            role: 'user',
            createdAt: new Date().toISOString(),
            googleAuth: true,
            needsOnboarding: true
          };
          saveJson(USERS_FILE, users);
        } else {
          // Link Google ID & update avatar for existing matching email user
          users[userId].googleId = profile.id;
          users[userId].googleAuth = true;
          if (profile.picture) users[userId].avatar = profile.picture;
          saveJson(USERS_FILE, users);
        }
      }

      // Create session token
      const sessionToken = crypto.randomBytes(32).toString('hex');
      const tokens = loadJson(TOKENS_FILE);
      tokens[sessionToken] = userId;
      saveJson(TOKENS_FILE, tokens);

      // Redirect to app (or settings page if new user onboarding)
      const userObj = JSON.stringify({ id: userId, username: users[userId].username, role: users[userId].role || 'user' });
      const targetUrl = users[userId].needsOnboarding ? '/settings?onboarding=true' : '/app';
      const html = `<!DOCTYPE html><html><head><title>Signing in...</title></head><body>
        <script>
          localStorage.setItem('token', ${JSON.stringify(sessionToken)});
          localStorage.setItem('user', JSON.stringify(${userObj}));
          window.location.href = '${targetUrl}';
        </script>
        <p style="font-family:sans-serif;color:#888;text-align:center;margin-top:40px">Signing you in...</p>
      </body></html>`;
      res.writeHead(200, { 'Content-Type': 'text/html' });
        return res.end(html);
      })();
    } catch (err) {
      console.error('Google OAuth callback error:', err.message);
      res.writeHead(302, { Location: '/login?error=google_server_error' });
      return res.end();
    }
  }


  if (method === 'POST' && pathname === '/api/upload') {
    const user = authenticate(req);
    if (!user) return sendError('Unauthorized', 401);
    return parseMultipart(req, (err, files) => {
      if (err || !files || !files.length) return sendError('No files uploaded', 400);
      const userFiles = getUserFiles(user.id);
      const userDir = path.join(UPLOADS_DIR, user.id);
      if (!fs.existsSync(userDir)) fs.mkdirSync(userDir, { recursive: true });

      const uploadedRecords = [];
      for (const fileObj of files) {
        const fileId = uuidv4();
        const safeName = path.basename(fileObj.filename || 'uploaded_file');
        const savedPath = path.join(userDir, `${fileId}_${safeName}`);
        fs.writeFileSync(savedPath, fileObj.data);

        const rec = {
          id: fileId,
          userId: user.id,
          originalName: safeName,
          savedPath: savedPath,
          mimeType: fileObj.type || 'application/octet-stream',
          size: fileObj.data.length,
          downloads: 0,
          uploadDate: new Date().toISOString(),
          isStarred: false
        };
        userFiles[fileId] = rec;
        uploadedRecords.push(rec);
      }
      saveUserFiles(user.id, userFiles);
      for (const r of uploadedRecords) {
        logAudit(user.id, 'FILE_UPLOADED', { fileId: r.id, name: r.originalName, size: r.size }, req.socket.remoteAddress);
      }
      return sendJson({ success: true, files: uploadedRecords });
    });
  }

  let bodyStr = '';
  let bodyTooLarge = false;
  req.on('data', chunk => {
    bodyStr += chunk.toString();
    if (bodyStr.length > 10 * 1024 * 1024) {
      bodyTooLarge = true;
      req.destroy();
    }
  });

  req.on('end', async () => {
    if (bodyTooLarge) return sendError('Request payload too large (max 10MB)', 413);
    let body = {};
    try { if (bodyStr) body = JSON.parse(bodyStr); } catch (e) {}

    // Auth Routes
    if (method === 'POST' && pathname === '/api/auth/register') {
      const { username, email, password } = body;
      if (!username || !email || !password) return sendError('All fields required');
      const users = loadJson(USERS_FILE);
      for (const id in users) {
        if (users[id].username && users[id].username.toLowerCase() === username.toLowerCase()) return sendError('Username already taken');
        if (users[id].email && users[id].email.toLowerCase() === email.toLowerCase()) return sendError('Email already registered');
      }
      const userId = uuidv4();
      const pw = hashPassword(password);
      users[userId] = { username, email, salt: pw.salt, hash: pw.hash, role: 'user', createdAt: new Date().toISOString() };
      saveJson(USERS_FILE, users);
      const token = crypto.randomBytes(32).toString('hex');
      const tokens = loadJson(TOKENS_FILE);
      tokens[token] = userId;
      saveJson(TOKENS_FILE, tokens);
      return sendJson({ success: true, token, user: { id: userId, username, email, role: 'user' } });
    }

    if (method === 'POST' && pathname === '/api/auth/login') {
      const { login, password } = body;
      if (!login || !password) return sendError('All fields required');
      const users = loadJson(USERS_FILE);
      let foundUser = null, foundId = null;
      for (const id in users) {
        const u = users[id];
        if ((u.username && u.username.toLowerCase() === login.toLowerCase()) || (u.email && u.email.toLowerCase() === login.toLowerCase())) {
          foundUser = u; foundId = id; break;
        }
      }
      if (!foundUser || !verifyPassword(password, foundUser.salt, foundUser.hash)) {
        return sendError('Invalid credentials', 401);
      }
      const token = crypto.randomBytes(32).toString('hex');
      const tokens = loadJson(TOKENS_FILE);
      tokens[token] = foundId;
      saveJson(TOKENS_FILE, tokens);
      return sendJson({ success: true, token, user: { id: foundId, username: foundUser.username, email: foundUser.email, role: foundUser.role || 'user', totpEnabled: !!foundUser.totpEnabled } });
    }

    if (method === 'POST' && pathname === '/api/auth/logout') {
      const token = getAuthToken(req);
      if (token) {
        const tokens = loadJson(TOKENS_FILE);
        delete tokens[token];
        saveJson(TOKENS_FILE, tokens);
      }
      return sendJson({ success: true });
    }

    if (method === 'GET' && pathname === '/api/auth/me') {
      const user = authenticate(req);
      if (!user) return sendError('Unauthorized', 401);
      const isGoogleUser = !!(user.googleAuth || user.googleId || (!user.hash && !user.salt));
      return sendJson({ success: true, user: { ...user, isGoogleUser } });
    }

    if (method === 'POST' && pathname === '/api/auth/update-username') {
      const user = authenticate(req);
      if (!user) return sendError('Unauthorized', 401);
      const { username } = body;
      if (!username || username.trim().length < 3) {
        return sendError('Username must be at least 3 characters', 400);
      }
      const cleanUsername = username.trim().replace(/[^a-zA-Z0-9_]/g, '').substring(0, 20);
      if (cleanUsername.length < 3) return sendError('Username contains invalid characters');

      const users = loadJson(USERS_FILE);
      for (const uid in users) {
        if (uid !== user.id && users[uid].username && users[uid].username.toLowerCase() === cleanUsername.toLowerCase()) {
          return sendError('Username is already taken by another user', 400);
        }
      }

      users[user.id].username = cleanUsername;
      delete users[user.id].needsOnboarding;
      saveJson(USERS_FILE, users);

      return sendJson({ success: true, message: 'Username updated successfully', username: cleanUsername });
    }

    if (method === 'POST' && pathname === '/api/auth/change-password') {
      const user = authenticate(req);
      if (!user) return sendError('Unauthorized', 401);
      const { currentPassword, newPassword } = body;
      if (!newPassword || newPassword.length < 6) return sendError('New password must be at least 6 characters');

      const users = loadJson(USERS_FILE);
      const u = users[user.id];
      if (!u) return sendError('User not found', 404);

      const hasPassword = !!(u.hash && u.salt);

      // If user has existing password, verify current password
      if (hasPassword) {
        if (!currentPassword) return sendError('Current password is required');
        if (!verifyPassword(currentPassword, u.salt, u.hash)) {
          return sendError('Current password is incorrect', 400);
        }
      }

      // Hash and set new password
      const pw = hashPassword(newPassword);
      u.salt = pw.salt;
      u.hash = pw.hash;
      saveJson(USERS_FILE, users);

      return sendJson({ success: true, message: 'Password updated successfully' });
    }

    if (method === 'POST' && pathname === '/api/auth/unlink-google') {
      const user = authenticate(req);
      if (!user) return sendError('Unauthorized', 401);

      const users = loadJson(USERS_FILE);
      const u = users[user.id];
      if (!u) return sendError('User not found', 404);

      // Enforce rule: Account must have a valid password set before unlinking Google
      if (!u.hash || !u.salt) {
        return sendError('You must set an account password first before unlinking your Google Account.', 400);
      }

      delete u.googleId;
      delete u.googleAuth;
      saveJson(USERS_FILE, users);

      return sendJson({ success: true, message: 'Google account unlinked successfully' });
    }

    // 2FA TOTP Management Endpoints
    if (method === 'POST' && pathname === '/api/2fa/setup') {
      const user = authenticate(req);
      if (!user) return sendError('Unauthorized', 401);
      const secret = crypto.randomBytes(16).toString('hex').toUpperCase();
      const users = loadJson(USERS_FILE);
      users[user.id].tempTotpSecret = secret;
      saveJson(USERS_FILE, users);

      const otpauthUrl = `otpauth://totp/AbdullahDrive:${encodeURIComponent(user.username)}?secret=${secret}&issuer=AbdullahDrive`;
      const qrCode = `https://api.qrserver.com/v1/create-qr-code/?size=200x200&data=${encodeURIComponent(otpauthUrl)}`;
      return sendJson({ success: true, secret, qrCode });
    }

    if (method === 'POST' && pathname === '/api/2fa/verify') {
      const user = authenticate(req);
      if (!user) return sendError('Unauthorized', 401);
      const { token } = body;
      if (!token || token.length < 6) return sendError('Valid 6-digit 2FA code required', 400);

      const users = loadJson(USERS_FILE);
      const u = users[user.id];
      const secret = u.tempTotpSecret || u.totpSecret;
      if (!secret) return sendError('No 2FA setup in progress', 400);

      u.totpSecret = secret;
      u.totpEnabled = true;
      delete u.tempTotpSecret;
      saveJson(USERS_FILE, users);

      logAudit(user.id, '2FA_ENABLED', {}, req.socket.remoteAddress);
      return sendJson({ success: true, message: '2FA enabled successfully' });
    }

    if (method === 'POST' && pathname === '/api/2fa/disable') {
      const user = authenticate(req);
      if (!user) return sendError('Unauthorized', 401);
      const users = loadJson(USERS_FILE);
      delete users[user.id].totpSecret;
      users[user.id].totpEnabled = false;
      saveJson(USERS_FILE, users);

      logAudit(user.id, '2FA_DISABLED', {}, req.socket.remoteAddress);
      return sendJson({ success: true, message: '2FA disabled successfully' });
    }

    if (method === 'GET' && (pathname === '/api/users/list' || pathname === '/api/users/search')) {
      const user = authenticate(req);
      if (!user) return sendError('Unauthorized', 401);
      const users = loadJson(USERS_FILE);
      const list = [];
      for (const uid in users) {
        if (uid !== user.id) {
          list.push({ id: uid, username: users[uid].username, email: users[uid].email });
        }
      }
      return sendJson({ success: true, users: list });
    }

    // System Security Audit Logs
    if (method === 'GET' && pathname === '/api/admin/audit-logs') {
      const user = authenticate(req);
      if (!user || user.role !== 'admin') return sendError('Unauthorized', 401);
      const logs = loadJson(AUDIT_LOG_FILE);
      return sendJson({ success: true, logs: logs.entries || [] });
    }

    // Google OAuth Admin Settings
    if (method === 'GET' && pathname === '/api/admin/google-oauth') {
      const user = authenticate(req);
      if (!user || user.role !== 'admin') return sendError('Unauthorized', 401);
      const cfg = getGoogleOAuthConfig();
      return sendJson({
        success: true,
        clientId: cfg.clientId || '',
        clientSecret: cfg.clientSecret ? '••••••••••••••••' : '',
        hasSecret: !!cfg.clientSecret,
        redirectUri: cfg.redirectUri || `http://localhost:${PORT}/auth/google/callback`
      });
    }

    if (method === 'POST' && pathname === '/api/admin/google-oauth') {
      const user = authenticate(req);
      if (!user || user.role !== 'admin') return sendError('Unauthorized', 401);
      const { clientId, clientSecret, redirectUri } = body;
      const currentCfg = getGoogleOAuthConfig();
      const newCfg = {
        clientId: clientId !== undefined ? clientId.trim() : (currentCfg.clientId || ''),
        clientSecret: (clientSecret && clientSecret !== '••••••••••••••••') ? clientSecret.trim() : (currentCfg.clientSecret || ''),
        redirectUri: redirectUri !== undefined ? redirectUri.trim() : (currentCfg.redirectUri || `http://localhost:${PORT}/auth/google/callback`)
      };
      saveJson(GOOGLE_OAUTH_FILE, newCfg);
      return sendJson({ success: true, message: 'Google OAuth settings saved successfully' });
    }

    // Admin Users Management & Stats APIs
    if (method === 'GET' && pathname === '/api/admin/users') {
      const user = authenticate(req);
      if (!user || user.role !== 'admin') return sendError('Unauthorized', 401);
      const users = loadJson(USERS_FILE);
      const userList = [];
      for (const uid in users) {
        const uFiles = getUserFiles(uid);
        const u = users[uid];
        userList.push({
          id: uid,
          username: u.username,
          email: u.email,
          role: u.role || 'user',
          authMethod: u.googleAuth || u.googleId ? 'Google Login' : 'Standard Auth',
          createdAt: u.createdAt || new Date().toISOString(),
          fileCount: Object.keys(uFiles).length
        });
      }
      return sendJson({ success: true, users: userList });
    }

    if (method === 'GET' && pathname === '/api/admin/stats') {
      const user = authenticate(req);
      if (!user || user.role !== 'admin') return sendError('Unauthorized', 401);
      const users = loadJson(USERS_FILE);
      let totalFiles = 0, totalSize = 0, totalDownloads = 0;
      for (const uid in users) {
        const uFiles = getUserFiles(uid);
        for (const fid in uFiles) {
          const f = uFiles[fid];
          totalFiles++;
          totalSize += (f.size || 0);
          totalDownloads += (f.downloads || 0);
        }
      }
      return sendJson({
        success: true,
        stats: {
          totalUsers: Object.keys(users).length,
          totalFiles,
          totalSize,
          totalDownloads
        }
      });
    }

    if (method === 'DELETE' && pathname.startsWith('/api/admin/users/')) {
      const user = authenticate(req);
      if (!user || user.role !== 'admin') return sendError('Unauthorized', 401);
      const targetUid = pathname.split('/')[4];
      if (!targetUid) return sendError('User ID required', 400);
      if (targetUid === user.id) return sendError('Cannot delete yourself', 400);

      const users = loadJson(USERS_FILE);
      if (!users[targetUid]) return sendError('User not found', 404);

      // Clean up user files on disk
      const userDir = path.join(UPLOADS_DIR, targetUid);
      if (fs.existsSync(userDir)) {
        try { fs.rmSync(userDir, { recursive: true, force: true }); } catch (e) {}
      }
      delete users[targetUid];
      saveJson(USERS_FILE, users);
      return sendJson({ success: true, message: 'User deleted successfully' });
    }

    if (method === 'GET' && pathname === '/api/admin/all-files') {
      const user = authenticate(req);
      if (!user || user.role !== 'admin') return sendError('Unauthorized', 401);
      const users = loadJson(USERS_FILE);
      const fileList = [];
      for (const uid in users) {
        const uFiles = getUserFiles(uid);
        for (const fid in uFiles) {
          fileList.push({
            ...uFiles[fid],
            uploadedBy: users[uid].username
          });
        }
      }
      return sendJson({ success: true, files: fileList });
    }

    // Documents Routes
    if (method === 'GET' && pathname === '/api/documents') {
      const user = authenticate(req);
      if (!user) return sendError('Unauthorized', 401);
      let docs = [];
      if (user.role === 'admin') {
        const users = loadJson(USERS_FILE);
        for (const uid in users) {
          const d = getUserDocs(uid);
          for (const k in d) { if (!d[k].trashedAt) docs.push(d[k]); }
        }
      } else {
        const d = getUserDocs(user.id);
        for (const k in d) { if (!d[k].trashedAt) docs.push(d[k]); }
      }
      docs.sort((a, b) => new Date(b.updatedAt) - new Date(a.updatedAt));
      return sendJson({ success: true, documents: docs, isAdmin: user.role === 'admin' });
    }

    if (method === 'GET' && pathname === '/api/documents/shared-with-me') {
      const user = authenticate(req);
      if (!user) return sendError('Unauthorized', 401);
      const users = loadJson(USERS_FILE);
      const sharedDocs = [];

      for (const uid in users) {
        if (uid === user.id) continue;
        const ownerDocs = getUserDocs(uid);
        for (const did in ownerDocs) {
          const d = ownerDocs[did];
          if (d.trashedAt) continue;
          if (Array.isArray(d.sharedWith)) {
            const match = d.sharedWith.find(s => s.userId === user.id || (s.email && s.email.toLowerCase() === (user.email || '').toLowerCase()));
            if (match) {
              sharedDocs.push({
                ...d,
                ownerUsername: users[uid].username,
                ownerEmail: users[uid].email,
                myRole: match.role || 'viewer'
              });
            }
          }
        }
      }

      sharedDocs.sort((a, b) => new Date(b.updatedAt) - new Date(a.updatedAt));
      return sendJson({ success: true, documents: sharedDocs });
    }

    if (method === 'POST' && pathname === '/api/documents') {
      const user = authenticate(req);
      if (!user) return sendError('Unauthorized', 401);
      const { title = 'Untitled', content = '', docType = 'doc', sheetsData = null, templateId = null } = body;
      
      let finalContent = content;
      let finalSheetsData = sheetsData;

      // Built-in Templates Engine
      if (templateId === 'meeting_notes') {
        finalContent = `<h2>📅 Meeting Notes</h2><p><strong>Date:</strong> ${new Date().toLocaleDateString()}</p><p><strong>Attendees:</strong> </p><h3>📌 Agenda</h3><ul><li>Topic 1</li><li>Topic 2</li></ul><h3>✅ Action Items</h3><ul><li>[ ] Task 1</li></ul>`;
      } else if (templateId === 'project_roadmap') {
        finalContent = `<h2>🚀 Project Roadmap</h2><p><strong>Project Name:</strong> </p><h3>Q1 Goals</h3><p>Detailed quarter 1 milestones...</p><h3>Q2 Goals</h3><p>Detailed quarter 2 milestones...</p>`;
      } else if (templateId === 'budget_sheet' && docType === 'sheet') {
        finalSheetsData = {
          "A1": "Category", "B1": "Estimated", "C1": "Actual",
          "A2": "Housing", "B2": "1200", "C2": "1200",
          "A3": "Utilities", "B3": "200", "C3": "180",
          "A4": "Groceries", "B4": "400", "C4": "450"
        };
      }

      const docs = getUserDocs(user.id);
      const id = uuidv4();
      const doc = { id, userId: user.id, title, content: finalContent, docType, sheetsData: finalSheetsData, isStarred: false, sharedWith: [], createdAt: new Date().toISOString(), updatedAt: new Date().toISOString() };
      docs[id] = doc;
      saveUserDocs(user.id, docs);

      logAudit(user.id, 'DOCUMENT_CREATED', { docId: id, title, docType, templateId }, req.socket.remoteAddress);

      return sendJson({ success: true, document: doc });
    }

    if (method === 'POST' && pathname.startsWith('/api/documents/') && pathname.endsWith('/star')) {
      const user = authenticate(req);
      if (!user) return sendError('Unauthorized', 401);
      const id = pathname.split('/')[3];
      const docs = getUserDocs(user.id);
      if (!docs[id]) return sendError('Document not found', 404);
      docs[id].isStarred = !docs[id].isStarred;
      docs[id].updatedAt = new Date().toISOString();
      saveUserDocs(user.id, docs);
      return sendJson({ success: true, document: docs[id] });
    }

    if (method === 'POST' && pathname.startsWith('/api/documents/') && pathname.endsWith('/share-user')) {
      const user = authenticate(req);
      if (!user) return sendError('Unauthorized', 401);
      const id = pathname.split('/')[3];
      const { targetUser, role = 'viewer' } = body;
      if (!targetUser) return sendError('Target user or email is required');

      let doc = null, docOwnerId = user.id;
      const userDocs = getUserDocs(user.id);
      doc = userDocs[id];

      if (!doc) {
        const users = loadJson(USERS_FILE);
        for (const uid in users) {
          const d = getUserDocs(uid);
          if (d[id]) { doc = d[id]; docOwnerId = uid; break; }
        }
      }
      if (!doc) return sendError('Document not found', 404);

      if (doc.userId !== user.id && user.role !== 'admin') {
        const isCoAdmin = Array.isArray(doc.sharedWith) && doc.sharedWith.some(s => s.userId === user.id && s.role === 'admin');
        if (!isCoAdmin) return sendError('Only owner or admin can share access', 403);
      }

      const users = loadJson(USERS_FILE);
      let targetObj = null, targetId = null;
      for (const uid in users) {
        const uName = users[uid].username ? users[uid].username.toLowerCase() : '';
        const uEmail = users[uid].email ? users[uid].email.toLowerCase() : '';
        if (uid === targetUser || (uName && uName === targetUser.toLowerCase()) || (uEmail && uEmail === targetUser.toLowerCase())) {
          targetObj = users[uid]; targetId = uid; break;
        }
      }
      if (!targetObj) return sendError('User not found on this website', 404);
      if (targetId === doc.userId) return sendError('Owner already has full access', 400);

      if (!Array.isArray(doc.sharedWith)) doc.sharedWith = [];
      const existingIdx = doc.sharedWith.findIndex(s => s.userId === targetId);
      const shareRecord = {
        userId: targetId,
        username: targetObj.username,
        email: targetObj.email,
        role: ['viewer', 'editor', 'admin'].includes(role) ? role : 'viewer',
        grantedAt: new Date().toISOString()
      };

      if (existingIdx >= 0) {
        doc.sharedWith[existingIdx] = shareRecord;
      } else {
        doc.sharedWith.push(shareRecord);
      }

      const ownerDocs = getUserDocs(docOwnerId);
      ownerDocs[id] = doc;
      saveUserDocs(docOwnerId, ownerDocs);

      return sendJson({ success: true, message: `Granted ${shareRecord.role} access to ${targetObj.username}`, sharedWith: doc.sharedWith });
    }

    if (method === 'POST' && pathname.startsWith('/api/documents/') && pathname.endsWith('/unshare-user')) {
      const user = authenticate(req);
      if (!user) return sendError('Unauthorized', 401);
      const id = pathname.split('/')[3];
      const { targetUserId } = body;
      if (!targetUserId) return sendError('Target user ID required');

      let doc = null, docOwnerId = user.id;
      const userDocs = getUserDocs(user.id);
      doc = userDocs[id];

      if (!doc) {
        const users = loadJson(USERS_FILE);
        for (const uid in users) {
          const d = getUserDocs(uid);
          if (d[id]) { doc = d[id]; docOwnerId = uid; break; }
        }
      }
      if (!doc) return sendError('Document not found', 404);

      if (doc.userId !== user.id && user.role !== 'admin') {
        const isCoAdmin = Array.isArray(doc.sharedWith) && doc.sharedWith.some(s => s.userId === user.id && s.role === 'admin');
        if (!isCoAdmin) return sendError('Only owner or admin can revoke access', 403);
      }

      if (Array.isArray(doc.sharedWith)) {
        doc.sharedWith = doc.sharedWith.filter(s => s.userId !== targetUserId);
      }

      const ownerDocs = getUserDocs(docOwnerId);
      ownerDocs[id] = doc;
      saveUserDocs(docOwnerId, ownerDocs);

      return sendJson({ success: true, message: 'Access revoked', sharedWith: doc.sharedWith || [] });
    }

    if (method === 'POST' && pathname.startsWith('/api/documents/') && pathname.endsWith('/transfer-ownership')) {
      const user = authenticate(req);
      if (!user) return sendError('Unauthorized', 401);
      const id = pathname.split('/')[3];
      const { targetUserId } = body;
      if (!targetUserId) return sendError('Target user ID is required');

      let doc = null, currentOwnerId = user.id;
      const userDocs = getUserDocs(user.id);
      if (userDocs[id]) {
        doc = userDocs[id];
      } else {
        const users = loadJson(USERS_FILE);
        for (const uid in users) {
          const d = getUserDocs(uid);
          if (d[id]) { doc = d[id]; currentOwnerId = uid; break; }
        }
      }

      if (!doc) return sendError('Document not found', 404);
      if (doc.userId !== user.id && user.role !== 'admin') {
        return sendError('Only the document owner or system admin can transfer ownership', 403);
      }

      const users = loadJson(USERS_FILE);
      if (!users[targetUserId]) return sendError('Target user not found', 404);
      if (targetUserId === doc.userId) return sendError('User is already the owner', 400);

      // Remove item from current owner docs
      const oldOwnerDocs = getUserDocs(currentOwnerId);
      delete oldOwnerDocs[id];
      saveUserDocs(currentOwnerId, oldOwnerDocs);

      // Change owner and add old owner as Co-Admin in sharedWith
      doc.userId = targetUserId;
      if (!Array.isArray(doc.sharedWith)) doc.sharedWith = [];
      doc.sharedWith = doc.sharedWith.filter(s => s.userId !== targetUserId);
      doc.sharedWith.push({
        userId: currentOwnerId,
        username: users[currentOwnerId] ? users[currentOwnerId].username : 'Former Owner',
        email: users[currentOwnerId] ? users[currentOwnerId].email : '',
        role: 'admin',
        grantedAt: new Date().toISOString()
      });

      // Add to new owner docs
      const newOwnerDocs = getUserDocs(targetUserId);
      newOwnerDocs[id] = doc;
      saveUserDocs(targetUserId, newOwnerDocs);

      return sendJson({ success: true, message: `Ownership transferred to ${users[targetUserId].username}`, document: doc });
    }

    if (method === 'GET' && pathname.startsWith('/api/documents/') && pathname !== '/api/documents/shared-with-me') {
      const user = authenticate(req);
      if (!user) return sendError('Unauthorized', 401);
      const parts = pathname.split('/');
      const id = parts[3];

      let doc = null;
      const userDocs = getUserDocs(user.id);
      if (userDocs[id]) {
        doc = userDocs[id];
      } else {
        const users = loadJson(USERS_FILE);
        for (const uid in users) {
          const d = getUserDocs(uid);
          if (d[id]) {
            const hasAccess = user.role === 'admin' || (Array.isArray(d[id].sharedWith) && d[id].sharedWith.some(s => s.userId === user.id || s.email === user.email));
            if (hasAccess) { doc = d[id]; break; }
          }
        }
      }

      if (!doc) return sendError('Document not found', 404);
      return sendJson({ success: true, document: doc });
    }

    if (method === 'PUT' && pathname.startsWith('/api/documents/')) {
      const user = authenticate(req);
      if (!user) return sendError('Unauthorized', 401);
      const id = pathname.split('/')[3];

      let doc = null, docOwnerId = user.id;
      const userDocs = getUserDocs(user.id);
      if (userDocs[id]) {
        doc = userDocs[id];
      } else {
        const users = loadJson(USERS_FILE);
        for (const uid in users) {
          const d = getUserDocs(uid);
          if (d[id]) {
            const match = Array.isArray(d[id].sharedWith) ? d[id].sharedWith.find(s => s.userId === user.id || s.email === user.email) : null;
            const canEdit = user.role === 'admin' || (match && (match.role === 'editor' || match.role === 'admin'));
            if (canEdit) { doc = d[id]; docOwnerId = uid; break; }
          }
        }
      }

      if (!doc) return sendError('Document not found or no edit permission', 403);

      const ownerDocs = getUserDocs(docOwnerId);
      if (body.title !== undefined) ownerDocs[id].title = body.title;
      if (body.content !== undefined) ownerDocs[id].content = body.content;
      if (body.docType !== undefined) ownerDocs[id].docType = body.docType;
      if (body.sheetsData !== undefined) ownerDocs[id].sheetsData = body.sheetsData;
      if (body.isStarred !== undefined) ownerDocs[id].isStarred = !!body.isStarred;
      if (body.folderId !== undefined) ownerDocs[id].folderId = body.folderId;
      if (body.color !== undefined) ownerDocs[id].color = body.color;
      
      // Save Version Snapshot
      if (!ownerDocs[id].versions) ownerDocs[id].versions = [];
      if (body.content !== undefined || body.sheetsData !== undefined) {
        ownerDocs[id].versions.push({
          timestamp: new Date().toISOString(),
          title: ownerDocs[id].title,
          content: ownerDocs[id].content,
          sheetsData: ownerDocs[id].sheetsData,
          editorUsername: user.username
        });
        if (ownerDocs[id].versions.length > 20) ownerDocs[id].versions.shift();
      }

      ownerDocs[id].updatedAt = new Date().toISOString();
      saveUserDocs(docOwnerId, ownerDocs);
      return sendJson({ success: true, document: ownerDocs[id] });
    }

    // --- File Management Routes ---
    if (method === 'GET' && pathname === '/api/files') {
      const user = authenticate(req);
      if (!user) return sendError('Unauthorized', 401);
      const filesObj = getUserFiles(user.id);
      const activeFiles = Object.values(filesObj).filter(f => !f.trashedAt);
      activeFiles.sort((a, b) => new Date(b.uploadDate) - new Date(a.uploadDate));
      return sendJson({ success: true, files: activeFiles });
    }

    if (method === 'GET' && pathname === '/api/files/shared-with-me') {
      const user = authenticate(req);
      if (!user) return sendError('Unauthorized', 401);
      const users = loadJson(USERS_FILE);
      const sharedList = [];

      for (const uid in users) {
        if (uid === user.id) continue;
        const ownerFiles = getUserFiles(uid);
        for (const fid in ownerFiles) {
          const f = ownerFiles[fid];
          if (f.trashedAt) continue;
          if (Array.isArray(f.sharedWith)) {
            const match = f.sharedWith.find(s => s.userId === user.id || (s.email && s.email.toLowerCase() === (user.email || '').toLowerCase()));
            if (match) {
              sharedList.push({
                ...f,
                ownerUsername: users[uid].username,
                ownerEmail: users[uid].email,
                myRole: match.role || 'viewer'
              });
            }
          }
        }
      }

      sharedList.sort((a, b) => new Date(b.uploadDate) - new Date(a.uploadDate));
      return sendJson({ success: true, files: sharedList });
    }

    if (method === 'POST' && pathname.startsWith('/api/files/') && pathname.endsWith('/share-user')) {
      const user = authenticate(req);
      if (!user) return sendError('Unauthorized', 401);
      const id = pathname.split('/')[3];
      const { targetUser, role = 'viewer' } = body;
      if (!targetUser) return sendError('Target user or email is required');

      const userFiles = getUserFiles(user.id);
      let file = userFiles[id];
      let fileOwnerId = user.id;

      if (!file) {
        const users = loadJson(USERS_FILE);
        for (const uid in users) {
          const f = getUserFiles(uid);
          if (f[id]) { file = f[id]; fileOwnerId = uid; break; }
        }
      }
      if (!file) return sendError('File not found', 404);

      if (file.userId !== user.id && user.role !== 'admin') {
        const isCoAdmin = Array.isArray(file.sharedWith) && file.sharedWith.some(s => s.userId === user.id && s.role === 'admin');
        if (!isCoAdmin) return sendError('Only owner or admin can share access', 403);
      }

      const users = loadJson(USERS_FILE);
      let targetObj = null, targetId = null;
      for (const uid in users) {
        const uName = users[uid].username ? users[uid].username.toLowerCase() : '';
        const uEmail = users[uid].email ? users[uid].email.toLowerCase() : '';
        if (uid === targetUser || (uName && uName === targetUser.toLowerCase()) || (uEmail && uEmail === targetUser.toLowerCase())) {
          targetObj = users[uid]; targetId = uid; break;
        }
      }
      if (!targetObj) return sendError('User not found on this website', 404);
      if (targetId === file.userId) return sendError('Owner already has full access', 400);

      if (!Array.isArray(file.sharedWith)) file.sharedWith = [];
      const existingIdx = file.sharedWith.findIndex(s => s.userId === targetId);
      const shareRecord = {
        userId: targetId,
        username: targetObj.username,
        email: targetObj.email,
        role: ['viewer', 'editor', 'admin'].includes(role) ? role : 'viewer',
        grantedAt: new Date().toISOString()
      };

      if (existingIdx >= 0) {
        file.sharedWith[existingIdx] = shareRecord;
      } else {
        file.sharedWith.push(shareRecord);
      }

      const ownerFiles = getUserFiles(fileOwnerId);
      ownerFiles[id] = file;
      saveUserFiles(fileOwnerId, ownerFiles);

      return sendJson({ success: true, message: `Granted ${shareRecord.role} access to ${targetObj.username}`, sharedWith: file.sharedWith });
    }

    if (method === 'POST' && pathname.startsWith('/api/files/') && pathname.endsWith('/unshare-user')) {
      const user = authenticate(req);
      if (!user) return sendError('Unauthorized', 401);
      const id = pathname.split('/')[3];
      const { targetUserId } = body;
      if (!targetUserId) return sendError('Target user ID required');

      const userFiles = getUserFiles(user.id);
      let file = userFiles[id];
      let fileOwnerId = user.id;

      if (!file) {
        const users = loadJson(USERS_FILE);
        for (const uid in users) {
          const f = getUserFiles(uid);
          if (f[id]) { file = f[id]; fileOwnerId = uid; break; }
        }
      }
      if (!file) return sendError('File not found', 404);

      if (file.userId !== user.id && user.role !== 'admin') {
        const isCoAdmin = Array.isArray(file.sharedWith) && file.sharedWith.some(s => s.userId === user.id && s.role === 'admin');
        if (!isCoAdmin) return sendError('Only owner or admin can revoke access', 403);
      }

      if (Array.isArray(file.sharedWith)) {
        file.sharedWith = file.sharedWith.filter(s => s.userId !== targetUserId);
      }

      const ownerFiles = getUserFiles(fileOwnerId);
      ownerFiles[id] = file;
      saveUserFiles(fileOwnerId, ownerFiles);

      return sendJson({ success: true, message: 'Access revoked', sharedWith: file.sharedWith || [] });
    }

    if (method === 'POST' && pathname.startsWith('/api/files/') && pathname.endsWith('/transfer-ownership')) {
      const user = authenticate(req);
      if (!user) return sendError('Unauthorized', 401);
      const id = pathname.split('/')[3];
      const { targetUserId } = body;
      if (!targetUserId) return sendError('Target user ID is required');

      let file = null, currentOwnerId = user.id;
      const userFiles = getUserFiles(user.id);
      if (userFiles[id]) {
        file = userFiles[id];
      } else {
        const users = loadJson(USERS_FILE);
        for (const uid in users) {
          const f = getUserFiles(uid);
          if (f[id]) { file = f[id]; currentOwnerId = uid; break; }
        }
      }

      if (!file) return sendError('File not found', 404);
      if (file.userId !== user.id && user.role !== 'admin') {
        return sendError('Only the file owner or system admin can transfer ownership', 403);
      }

      const users = loadJson(USERS_FILE);
      if (!users[targetUserId]) return sendError('Target user not found', 404);
      if (targetUserId === file.userId) return sendError('User is already the owner', 400);

      // Remove file from current owner
      const oldOwnerFiles = getUserFiles(currentOwnerId);
      delete oldOwnerFiles[id];
      saveUserFiles(currentOwnerId, oldOwnerFiles);

      // Transfer ownership & add old owner as Co-Admin in sharedWith
      file.userId = targetUserId;
      if (!Array.isArray(file.sharedWith)) file.sharedWith = [];
      file.sharedWith = file.sharedWith.filter(s => s.userId !== targetUserId);
      file.sharedWith.push({
        userId: currentOwnerId,
        username: users[currentOwnerId] ? users[currentOwnerId].username : 'Former Owner',
        email: users[currentOwnerId] ? users[currentOwnerId].email : '',
        role: 'admin',
        grantedAt: new Date().toISOString()
      });

      // Add to new owner files
      const newOwnerFiles = getUserFiles(targetUserId);
      newOwnerFiles[id] = file;
      saveUserFiles(targetUserId, newOwnerFiles);

      return sendJson({ success: true, message: `File ownership transferred to ${users[targetUserId].username}`, file });
    }

    // --- Bulk ZIP & Bulk Trash Endpoints ---
    if (method === 'POST' && pathname === '/api/files/bulk-zip') {
      const user = authenticate(req);
      if (!user) return sendError('Unauthorized', 401);
      const { ids } = body;
      if (!Array.isArray(ids) || !ids.length) return sendError('File IDs array required');

      const userFiles = getUserFiles(user.id);
      const zipEntries = [];

      for (const id of ids) {
        const fileRec = userFiles[id];
        if (fileRec && fileRec.savedPath && fs.existsSync(fileRec.savedPath)) {
          try {
            zipEntries.push({
              filename: fileRec.originalName,
              buffer: fs.readFileSync(fileRec.savedPath)
            });
          } catch (e) {}
        }
      }

      if (!zipEntries.length) return sendError('No valid files found to compress', 404);

      const zipBuffer = createZipArchive(zipEntries);
      res.writeHead(200, {
        'Content-Type': 'application/zip',
        'Content-Disposition': `attachment; filename="abdullah_drive_files_${Date.now()}.zip"`,
        'Content-Length': zipBuffer.length
      });
      return res.end(zipBuffer);
    }

    if (method === 'POST' && pathname === '/api/files/bulk-trash') {
      const user = authenticate(req);
      if (!user) return sendError('Unauthorized', 401);
      const { ids } = body;
      if (!Array.isArray(ids) || !ids.length) return sendError('File IDs required');

      const userFiles = getUserFiles(user.id);
      let count = 0;
      for (const id of ids) {
        if (userFiles[id]) {
          userFiles[id].trashedAt = new Date().toISOString();
          count++;
        }
      }
      saveUserFiles(user.id, userFiles);
      return sendJson({ success: true, message: `Moved ${count} file(s) to trash` });
    }

    if (method === 'PUT' && pathname.startsWith('/api/files/') && pathname.endsWith('/share-options')) {
      const user = authenticate(req);
      if (!user) return sendError('Unauthorized', 401);
      const id = pathname.split('/')[3];
      const { password, expireHours, maxDownloads } = body;

      const userFiles = getUserFiles(user.id);
      if (!userFiles[id]) return sendError('File not found', 404);

      if (password) {
        const { salt, hash } = hashPassword(password);
        userFiles[id].sharePassword = { salt, hash };
      } else if (password === '') {
        delete userFiles[id].sharePassword;
      }

      if (expireHours && Number(expireHours) > 0) {
        userFiles[id].expiresAt = new Date(Date.now() + Number(expireHours) * 3600 * 1000).toISOString();
      } else if (expireHours === 0) {
        delete userFiles[id].expiresAt;
      }

      if (maxDownloads && Number(maxDownloads) > 0) {
        userFiles[id].maxDownloads = Number(maxDownloads);
      } else if (maxDownloads === 0) {
        delete userFiles[id].maxDownloads;
      }

      saveUserFiles(user.id, userFiles);
      return sendJson({ success: true, message: 'Share link options updated successfully', file: userFiles[id] });
    }

    if (method === 'PUT' && pathname.startsWith('/api/files/') && pathname.endsWith('/share-password')) {
      const user = authenticate(req);
      if (!user) return sendError('Unauthorized', 401);
      const id = pathname.split('/')[3];
      const { password } = body;

      const userFiles = getUserFiles(user.id);
      if (!userFiles[id]) return sendError('File not found', 404);

      if (password) {
        const { salt, hash } = hashPassword(password);
        userFiles[id].sharePassword = { salt, hash };
      } else {
        delete userFiles[id].sharePassword;
      }
      saveUserFiles(user.id, userFiles);
      return sendJson({ success: true, isProtected: !!password, file: userFiles[id] });
    }

    if (method === 'GET' && pathname.startsWith('/api/share/')) {
      const token = pathname.split('/')[3];
      const users = loadJson(USERS_FILE);
      let file = null;

      for (const uid in users) {
        const m = getUserFiles(uid);
        for (const fid in m) {
          if (m[fid].shareToken === token && !m[fid].trashedAt) {
            file = m[fid]; break;
          }
        }
        if (file) break;
      }

      if (!file) return sendError('Link invalid or expired', 404);
      if (file.expiresAt && new Date(file.expiresAt).getTime() < Date.now()) {
        return sendError('Link expired', 410);
      }

      const isProtected = !!(file.sharePassword && file.sharePassword.hash);
      return sendJson({
        success: true,
        file: {
          id: file.id,
          originalName: file.originalName,
          size: file.size,
          mimeType: file.mimeType,
          uploadDate: file.uploadDate,
          downloads: file.downloads || 0,
          isProtected
        }
      });
    }

    if (method === 'POST' && pathname.startsWith('/api/share/') && pathname.endsWith('/verify-password')) {
      const token = pathname.split('/')[3];
      const { password } = body;
      const users = loadJson(USERS_FILE);
      let file = null;

      for (const uid in users) {
        const m = getUserFiles(uid);
        for (const fid in m) {
          if (m[fid].shareToken === token && !m[fid].trashedAt) {
            file = m[fid]; break;
          }
        }
        if (file) break;
      }

      if (!file) return sendError('Link invalid or expired', 404);
      if (!file.sharePassword || !file.sharePassword.hash) return sendJson({ success: true, valid: true });

      const valid = verifyPassword(password || '', file.sharePassword.salt, file.sharePassword.hash);
      if (!valid) return sendError('Incorrect password', 401);
      return sendJson({ success: true, valid: true });
    }

    if (method === 'GET' && pathname.startsWith('/api/share-download/')) {
      const token = pathname.split('/')[3];
      const parsed = url.parse(req.url, true);
      const password = parsed.query.password || '';

      const users = loadJson(USERS_FILE);
      let file = null, fileOwnerId = null;

      for (const uid in users) {
        const m = getUserFiles(uid);
        for (const fid in m) {
          if (m[fid].shareToken === token && !m[fid].trashedAt) {
            file = m[fid]; fileOwnerId = uid; break;
          }
        }
        if (file) break;
      }

      if (!file || !file.savedPath || !fs.existsSync(file.savedPath)) return sendError('File not found', 404);
      if (file.expiresAt && new Date(file.expiresAt).getTime() < Date.now()) return sendError('Link expired', 410);

      // Check max downloads limit
      if (file.maxDownloads && (file.downloads || 0) >= file.maxDownloads) {
        return sendError('Maximum download limit reached for this share link', 410);
      }

      if (file.sharePassword && file.sharePassword.hash) {
        const valid = verifyPassword(password, file.sharePassword.salt, file.sharePassword.hash);
        if (!valid) return sendError('Password required or incorrect', 401);
      }

      file.downloads = (file.downloads || 0) + 1;
      const ownerFiles = getUserFiles(fileOwnerId);
      if (ownerFiles[file.id]) {
        ownerFiles[file.id].downloads = file.downloads;
        saveUserFiles(fileOwnerId, ownerFiles);
      }

      logAudit(fileOwnerId, 'FILE_DOWNLOADED_VIA_LINK', { fileId: file.id, name: file.originalName, downloadCount: file.downloads }, req.socket.remoteAddress);

      res.writeHead(200, {
        'Content-Type': file.mimeType || 'application/octet-stream',
        'Content-Disposition': `attachment; filename="${encodeURIComponent(file.originalName)}"`
      });
      return fs.createReadStream(file.savedPath).pipe(res);
    }

    // --- Tags, Comments & Activity Engine ---
    if (method === 'PUT' && pathname.startsWith('/api/files/') && pathname.endsWith('/tags')) {
      const user = authenticate(req);
      if (!user) return sendError('Unauthorized', 401);
      const id = pathname.split('/')[3];
      const { tags = [], colorLabel = '' } = body;

      const userFiles = getUserFiles(user.id);
      if (!userFiles[id]) return sendError('File not found', 404);
      userFiles[id].tags = tags;
      userFiles[id].colorLabel = colorLabel;
      saveUserFiles(user.id, userFiles);
      return sendJson({ success: true, tags, colorLabel });
    }

    if (method === 'PUT' && pathname.startsWith('/api/documents/') && pathname.endsWith('/tags')) {
      const user = authenticate(req);
      if (!user) return sendError('Unauthorized', 401);
      const id = pathname.split('/')[3];
      const { tags = [], colorLabel = '' } = body;

      const userDocs = getUserDocs(user.id);
      if (!userDocs[id]) return sendError('Document not found', 404);
      userDocs[id].tags = tags;
      userDocs[id].colorLabel = colorLabel;
      saveUserDocs(user.id, userDocs);
      return sendJson({ success: true, tags, colorLabel });
    }

    if (method === 'GET' && pathname.startsWith('/api/files/') && pathname.endsWith('/comments')) {
      const user = authenticate(req);
      if (!user) return sendError('Unauthorized', 401);
      const id = pathname.split('/')[3];
      const userFiles = getUserFiles(user.id);
      const fileRec = userFiles[id];
      return sendJson({ success: true, comments: fileRec ? (fileRec.comments || []) : [] });
    }

    if (method === 'POST' && pathname.startsWith('/api/files/') && pathname.endsWith('/comments')) {
      const user = authenticate(req);
      if (!user) return sendError('Unauthorized', 401);
      const id = pathname.split('/')[3];
      const { text } = body;
      if (!text) return sendError('Comment text is required');

      const userFiles = getUserFiles(user.id);
      if (!userFiles[id]) return sendError('File not found', 404);
      if (!Array.isArray(userFiles[id].comments)) userFiles[id].comments = [];

      const commentObj = {
        id: uuidv4(),
        userId: user.id,
        username: user.username,
        text,
        timestamp: new Date().toISOString()
      };
      userFiles[id].comments.push(commentObj);
      saveUserFiles(user.id, userFiles);
      return sendJson({ success: true, comment: commentObj, comments: userFiles[id].comments });
    }

    if (method === 'GET' && pathname === '/api/files-trash') {
      const user = authenticate(req);
      if (!user) return sendError('Unauthorized', 401);
      const filesObj = getUserFiles(user.id);
      const trashedFiles = Object.values(filesObj).filter(f => f.trashedAt);
      return sendJson({ success: true, files: trashedFiles });
    }

    if (method === 'GET' && pathname === '/api/stats') {
      const user = authenticate(req);
      if (!user) return sendError('Unauthorized', 401);
      const filesObj = getUserFiles(user.id);
      const active = Object.values(filesObj).filter(f => !f.trashedAt);
      const totalSize = active.reduce((sum, f) => sum + (f.size || 0), 0);
      const totalDownloads = active.reduce((sum, f) => sum + (f.downloads || 0), 0);
      return sendJson({
        success: true,
        stats: {
          totalFiles: active.length,
          totalSize,
          totalDownloads,
          recentUploads: active.filter(f => Date.now() - new Date(f.uploadDate).getTime() < 86400000).length
        }
      });
    }

    if (method === 'GET' && pathname !== '/api/files/shared-with-me' && pathname !== '/api/files-trash' && (pathname.startsWith('/api/files/') || pathname.startsWith('/api/thumbnail/') || pathname.startsWith('/api/preview/') || pathname.startsWith('/api/download/'))) {
      const user = authenticate(req);
      if (!user) return sendError('Unauthorized', 401);
      const parts = pathname.split('/');
      const isDownloadAlias = pathname.startsWith('/api/download/');
      const id = isDownloadAlias ? parts[3] : parts[3];
      const isExplicitDownload = (parts[4] === 'download' || isDownloadAlias);

      let fileRec = null, fileOwnerId = user.id;
      const userFiles = getUserFiles(user.id);
      if (userFiles[id]) {
        fileRec = userFiles[id];
      } else {
        const users = loadJson(USERS_FILE);
        for (const uid in users) {
          const f = getUserFiles(uid);
          if (f[id]) {
            const hasAccess = user.role === 'admin' || (Array.isArray(f[id].sharedWith) && f[id].sharedWith.some(s => s.userId === user.id || s.email === user.email));
            if (hasAccess) { fileRec = f[id]; fileOwnerId = uid; break; }
          }
        }
      }

      if (!fileRec || !fileRec.savedPath || !fs.existsSync(fileRec.savedPath)) return sendError('File not found', 404);

      if (isExplicitDownload) {
        fileRec.downloads = (fileRec.downloads || 0) + 1;
        const ownerFiles = getUserFiles(fileOwnerId);
        if (ownerFiles[id]) {
          ownerFiles[id].downloads = fileRec.downloads;
          saveUserFiles(fileOwnerId, ownerFiles);
        }
        res.writeHead(200, {
          'Content-Type': fileRec.mimeType || 'application/octet-stream',
          'Content-Disposition': `attachment; filename="${encodeURIComponent(fileRec.originalName)}"`
        });
      } else {
        res.writeHead(200, { 'Content-Type': fileRec.mimeType || 'application/octet-stream' });
      }
      const stream = fs.createReadStream(fileRec.savedPath);
      stream.on('error', () => {
        if (!res.headersSent) sendError('Error reading file from disk', 500);
      });
      return stream.pipe(res);
    }

    if (method === 'POST' && pathname.startsWith('/api/files/') && pathname.endsWith('/restore')) {
      const user = authenticate(req);
      if (!user) return sendError('Unauthorized', 401);
      const id = pathname.split('/')[3];
      const filesObj = getUserFiles(user.id);
      if (!filesObj[id]) return sendError('File not found', 404);
      delete filesObj[id].trashedAt;
      saveUserFiles(user.id, filesObj);
      return sendJson({ success: true });
    }

    if (method === 'DELETE' && pathname.startsWith('/api/files/')) {
      const user = authenticate(req);
      if (!user) return sendError('Unauthorized', 401);
      const parts = pathname.split('/');
      const id = parts[3];
      const filesObj = getUserFiles(user.id);
      if (!filesObj[id]) return sendError('File not found', 404);

      if (parts[4] === 'permanent') {
        if (filesObj[id].savedPath && fs.existsSync(filesObj[id].savedPath)) {
          try { fs.unlinkSync(filesObj[id].savedPath); } catch (e) {}
        }
        delete filesObj[id];
        saveUserFiles(user.id, filesObj);
        return sendJson({ success: true });
      }

      filesObj[id].trashedAt = new Date().toISOString();
      saveUserFiles(user.id, filesObj);
      return sendJson({ success: true });
    }

    // --- Folder Routes ---
    if (method === 'GET' && pathname === '/api/folders') {
      const user = authenticate(req);
      if (!user) return sendError('Unauthorized', 401);
      const folders = getUserFolders(user.id);
      return sendJson({ success: true, folders: Object.values(folders) });
    }

    if (method === 'POST' && pathname === '/api/folders') {
      const user = authenticate(req);
      if (!user) return sendError('Unauthorized', 401);
      const { name = 'New Folder', color = '#6c5ce7', parentId = 'root' } = body;
      const folders = getUserFolders(user.id);
      const id = uuidv4();
      const folder = { id, userId: user.id, name, color, parentId, createdAt: new Date().toISOString() };
      folders[id] = folder;
      saveUserFolders(user.id, folders);
      return sendJson({ success: true, folder });
    }

    if (method === 'DELETE' && pathname.startsWith('/api/folders/')) {
      const user = authenticate(req);
      if (!user) return sendError('Unauthorized', 401);
      const id = pathname.split('/')[3];
      const folders = getUserFolders(user.id);
      if (!folders[id]) return sendError('Folder not found', 404);
      delete folders[id];
      saveUserFolders(user.id, folders);

      // Clean orphaned folderId references in files & docs
      const userFiles = getUserFiles(user.id);
      let filesChanged = false;
      for (const fid in userFiles) {
        if (userFiles[fid].folderId === id) {
          delete userFiles[fid].folderId;
          filesChanged = true;
        }
      }
      if (filesChanged) saveUserFiles(user.id, userFiles);

      const userDocs = getUserDocs(user.id);
      let docsChanged = false;
      for (const did in userDocs) {
        if (userDocs[did].folderId === id) {
          delete userDocs[did].folderId;
          docsChanged = true;
        }
      }
      if (docsChanged) saveUserDocs(user.id, userDocs);

      return sendJson({ success: true });
    }

    if (method === 'DELETE' && pathname.startsWith('/api/documents/')) {
      const user = authenticate(req);
      if (!user) return sendError('Unauthorized', 401);
      const parts = pathname.split('/');
      const id = parts[3];

      let targetUserId = user.id;
      let docs = getUserDocs(user.id);

      if (!docs[id] && user.role === 'admin') {
        const users = loadJson(USERS_FILE);
        for (const uid in users) {
          const uDocs = getUserDocs(uid);
          if (uDocs[id]) {
            targetUserId = uid;
            docs = uDocs;
            break;
          }
        }
      }

      if (!docs[id]) return sendError('Document not found', 404);

      if (parts[4] === 'permanent') {
        delete docs[id];
        saveUserDocs(targetUserId, docs);
        return sendJson({ success: true });
      }

      docs[id].trashedAt = new Date().toISOString();
      saveUserDocs(targetUserId, docs);
      return sendJson({ success: true });
    }

    if (method === 'GET' && pathname === '/api/documents-trash') {
      const user = authenticate(req);
      if (!user) return sendError('Unauthorized', 401);
      const docs = getUserDocs(user.id);
      const trashed = Object.values(docs).filter(d => d.trashedAt);
      return sendJson({ success: true, documents: trashed });
    }

    if (method === 'POST' && pathname.endsWith('/restore') && pathname.startsWith('/api/documents/')) {
      const user = authenticate(req);
      if (!user) return sendError('Unauthorized', 401);
      const id = pathname.split('/')[3];
      const docs = getUserDocs(user.id);
      if (!docs[id]) return sendError('Document not found', 404);
      delete docs[id].trashedAt;
      saveUserDocs(user.id, docs);
      return sendJson({ success: true });
    }

    if (method === 'POST' && pathname.startsWith('/api/files/') && pathname.endsWith('/share-email')) {
      const user = authenticate(req);
      if (!user) return sendError('Unauthorized', 401);
      const id = pathname.split('/')[3];
      const { to, message = '' } = body;
      if (!to) return sendError('Recipient email is required', 400);

      let file = null;
      if (user.role === 'admin') {
        const users = loadJson(USERS_FILE);
        for (const uid in users) {
          const m = getUserFiles(uid);
          if (m[id]) { file = m[id]; break; }
        }
      } else {
        const userFiles = getUserFiles(user.id);
        file = userFiles[id] || null;
      }
      if (!file) return sendError('File not found', 404);

      const sizeStr = file.size < 1024 ? file.size + ' B' : (file.size < 1048576 ? (file.size / 1024).toFixed(1) + ' KB' : (file.size / 1048576).toFixed(1) + ' MB');
      const config = getUserSmtpConfig(user.id);
      const subject = `📎 Shared File: ${file.originalName}`;

      const htmlBody = `
        <div style='font-family:-apple-system,sans-serif;max-width:700px;margin:0 auto;padding:30px;background:#12121a;color:#e2e2f0;border-radius:12px'>
          <h2 style='color:#a29bfe;border-bottom:1px solid #2a2a3a;padding-bottom:12px'>📎 ${escapeHtml(file.originalName)}</h2>
          ${message ? `<p style='color:#8888a0;font-style:italic;border-left:3px solid #6c5ce7;padding-left:12px;margin:16px 0'>${escapeHtml(message)}</p>` : ''}
          <div style='background:#1a1a28;padding:20px;border-radius:8px;border:1px solid #2a2a3a;margin:16px 0'>
            <p style='margin:0 0 8px 0'><strong style='color:#a29bfe'>File:</strong> ${escapeHtml(file.originalName)}</p>
            <p style='margin:0 0 8px 0'><strong style='color:#a29bfe'>Size:</strong> ${sizeStr}</p>
            <p style='margin:0 0 8px 0'><strong style='color:#a29bfe'>Type:</strong> ${escapeHtml(file.mimeType || 'application/octet-stream')}</p>
          </div>
          <p style='color:#8888a0;font-size:12px;margin-top:20px;border-top:1px solid #2a2a3a;padding-top:12px'>
            Shared by <strong>${escapeHtml(user.username)}</strong> via Abdullah File Share
          </p>
        </div>`;

      const textBody = `${file.originalName}\n\n${message ? message + '\n\n' : ''}---\nShared by ${user.username} via Abdullah File Share`;

      const attachments = [];
      if (file.savedPath && fs.existsSync(file.savedPath)) {
        try {
          attachments.push({
            filename: file.originalName,
            contentType: file.mimeType || 'application/octet-stream',
            content: fs.readFileSync(file.savedPath)
          });
        } catch (e) {}
      }

      try {
        await sendSmtpEmail(config, to, subject, htmlBody, textBody, attachments);
        return sendJson({ success: true, message: `File shared with ${to} successfully!` });
      } catch (err) {
        return sendError('Failed to send email: ' + err.message);
      }
    }

    if (method === 'POST' && pathname.startsWith('/api/documents/') && pathname.endsWith('/share-email')) {
      const user = authenticate(req);
      if (!user) return sendError('Unauthorized', 401);
      const id = pathname.split('/')[3];
      const { to, message = '' } = body;
      if (!to) return sendError('Recipient email is required', 400);

      let doc = null;
      if (user.role === 'admin') {
        const users = loadJson(USERS_FILE);
        for (const uid in users) {
          const d = getUserDocs(uid);
          if (d[id]) { doc = d[id]; break; }
        }
      } else {
        const docs = getUserDocs(user.id);
        doc = docs[id] || null;
      }
      if (!doc) return sendError('Document not found', 404);

      const config = getUserSmtpConfig(user.id);
      const isSheet = (doc.docType === 'sheet');
      const subject = `${isSheet ? '📊' : '📄'} Shared ${isSheet ? 'Spreadsheet' : 'Document'}: ${doc.title}`;

      let contentHtml = '';
      let contentText = '';
      const attachments = [];

      if (isSheet) {
        contentHtml = formatSheetToHtml(doc.sheetsData);
        contentText = formatSheetToText(doc.sheetsData);
        attachments.push({
          filename: `${doc.title || 'Spreadsheet'}.csv`,
          contentType: 'text/csv; charset=utf-8',
          content: Buffer.from(contentText, 'utf8')
        });
      } else {
        contentHtml = `<div style="background:#1a1a28;padding:20px;border-radius:8px;border:1px solid #2a2a3a">${doc.content || '<p><i>(Empty document)</i></p>'}</div>`;
        contentText = stripHtml(doc.content || '(Empty document)');
        const docFullHtml = `<!DOCTYPE html><html><head><meta charset="utf-8"><title>${escapeHtml(doc.title)}</title><style>body{font-family:sans-serif;max-width:800px;margin:40px auto;padding:20px;line-height:1.8;color:#111;background:#fff}</style></head><body><h1>${escapeHtml(doc.title)}</h1><div>${doc.content || ''}</div></body></html>`;
        attachments.push({
          filename: `${doc.title || 'Document'}.html`,
          contentType: 'text/html; charset=utf-8',
          content: Buffer.from(docFullHtml, 'utf8')
        });
      }

      const htmlBody = `
        <div style='font-family:-apple-system,sans-serif;max-width:800px;margin:0 auto;padding:30px;background:#12121a;color:#e2e2f0;border-radius:12px'>
          <h2 style='color:#a29bfe;border-bottom:1px solid #2a2a3a;padding-bottom:12px'>${isSheet ? '📊' : '📄'} ${escapeHtml(doc.title)}</h2>
          ${message ? `<p style='color:#8888a0;font-style:italic;border-left:3px solid #6c5ce7;padding-left:12px;margin:16px 0'>${escapeHtml(message)}</p>` : ''}
          ${contentHtml}
          <p style='color:#8888a0;font-size:12px;margin-top:20px;border-top:1px solid #2a2a3a;padding-top:12px'>
            Shared by <strong>${escapeHtml(user.username)}</strong> via Abdullah File Share
          </p>
        </div>`;

      const textBody = `${doc.title}\n\n${message ? message + '\n\n' : ''}${contentText}\n\n---\nShared by ${user.username} via Abdullah File Share`;

      try {
        await sendSmtpEmail(config, to, subject, htmlBody, textBody, attachments);
        return sendJson({ success: true, message: `${isSheet ? 'Spreadsheet' : 'Document'} shared with ${to} successfully!` });
      } catch (err) {
        return sendError('Failed to send email: ' + err.message);
      }
    }

    // SMTP Settings
    if (method === 'GET' && pathname === '/api/smtp-settings') {
      const user = authenticate(req);
      if (!user) return sendError('Unauthorized', 401);
      const config = getUserSmtpConfig(user.id);
      return sendJson({ success: true, config, configured: !!(config.user && config.pass) });
    }

    if (method === 'PUT' && pathname === '/api/smtp-settings') {
      const user = authenticate(req);
      if (!user) return sendError('Unauthorized', 401);
      const users = loadJson(USERS_FILE);
      users[user.id].smtpConfig = body;
      saveJson(USERS_FILE, users);
      return sendJson({ success: true, message: 'Settings saved', config: getUserSmtpConfig(user.id) });
    }

    if (method === 'POST' && pathname === '/api/smtp-test') {
      const user = authenticate(req);
      if (!user) return sendError('Unauthorized', 401);
      const to = body.to || user.email;
      const config = getUserSmtpConfig(user.id);
      try {
        await sendSmtpEmail(config, to, 'SMTP Connection Test', '<h2>SMTP Test Successful!</h2>', 'SMTP Test Successful!');
        return sendJson({ success: true, message: 'Test email sent successfully!' });
      } catch (err) {
        return sendError('SMTP Test failed: ' + err.message);
      }
    }

    // Session Devices Manager APIs
    if (method === 'GET' && pathname === '/api/sessions') {
      const user = authenticate(req);
      if (!user) return sendError('Unauthorized', 401);
      const tokens = loadJson(TOKENS_FILE);
      const userSessions = [];
      for (const t in tokens) {
        if (tokens[t] === user.id) {
          userSessions.push({
            token: t.substring(0, 8) + '...',
            isCurrent: (getAuthToken(req) === t),
            createdAt: new Date().toISOString()
          });
        }
      }
      return sendJson({ success: true, sessions: userSessions });
    }

    if (method === 'POST' && pathname === '/api/sessions/revoke') {
      const user = authenticate(req);
      if (!user) return sendError('Unauthorized', 401);
      const tokens = loadJson(TOKENS_FILE);
      const currentToken = getAuthToken(req);
      for (const t in tokens) {
        if (tokens[t] === user.id && t !== currentToken) {
          delete tokens[t];
        }
      }
      saveJson(TOKENS_FILE, tokens);
      return sendJson({ success: true, message: 'All other active sessions revoked' });
    }

    // Default 404 for unmatched API endpoints
    return sendError('Route not found', 404);
  });
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`=================================================`);
  console.log(`  🚀 Abdullah Drive & Docs Web Server Running!  `);
  console.log(`  🌐 Local Access: http://localhost:${PORT}`);
  console.log(`  📱 Mobile/Network Access: http://192.168.1.5:${PORT}`);
  console.log(`=================================================`);
});
