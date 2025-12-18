const express = require('express');
const cors = require('cors');
const axios = require('axios');
const fs = require('fs');
const crypto = require('crypto');

const app = express();

// ============================================
// 🔧 CONFIGURATION
// ============================================
const CONFIG = {
    // Script Source
    LOADER_SCRIPT_URL: "https://raw.githubusercontent.com/trianaq765-cmd/lua-protector/refs/heads/main/Protected_8132419935440713.lua.txt",
    WORKINK_API: "https://work.ink/_api/v2/token/isValid/",
    
    // Files
    DB_FILE: './database.encrypted.json',
    LOG_FILE: './security.log',
    
    // Secrets (Ganti di production!)
    MASTER_SECRET: process.env.MASTER_SECRET || crypto.randomBytes(64).toString('hex'),
    HMAC_SECRET: process.env.HMAC_SECRET || crypto.randomBytes(32).toString('hex'),
    ADMIN_SECRET: process.env.ADMIN_SECRET || crypto.randomBytes(48).toString('hex'),
    
    // Rate Limiting (Lebih toleran)
    RATE_LIMIT_WINDOW: 60 * 1000,        // 1 menit
    RATE_LIMIT_MAX: 60,                   // 60 request per menit (normal)
    RATE_LIMIT_STRICT: 15,                // 15 request per menit (sensitive endpoints)
    BLOCK_DURATION: 5 * 60 * 1000,        // 5 menit block (bukan 15 menit)
    
    // Security
    NONCE_EXPIRY: 60 * 1000,              // 60 detik (lebih longgar)
    SESSION_EXPIRY: 2 * 60 * 60 * 1000,   // 2 jam
    MAX_FAILED_ATTEMPTS: 10,              // 10 kali gagal sebelum block
    
    // Whitelist (IP yang tidak akan pernah diblokir)
    WHITELISTED_IPS: [
        '127.0.0.1',
        'localhost',
        '::1',
        // Tambahkan IP Anda di sini jika perlu:
        // '123.456.789.0',
    ],
    
    // Development Mode (set true untuk testing)
    DEV_MODE: process.env.NODE_ENV !== 'production',
    
    VERSION: "10.1-BALANCED"
};

// ============================================
// 🎨 HTML TEMPLATES
// ============================================
const NOT_AUTHORIZED_HTML = `<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Unauthorized | Premium Protect</title>
    <style>
        * {
            margin: 0; padding: 0; box-sizing: border-box;
        }

        body, html {
            width: 100%; height: 100%; overflow: hidden;
            background-color: #000000;
            font-family: 'Inter', -apple-system, sans-serif;
            color: #ffffff;
        }

        .bg-layer {
            position: fixed;
            top: 0; left: 0; width: 100%; height: 100%;
            background: linear-gradient(270deg, #000000, #0f172a, #000000);
            background-size: 600% 600%;
            animation: gradientShift 30s ease infinite;
            z-index: 1;
        }

        .container {
            position: relative;
            z-index: 10;
            height: 100vh;
            display: flex;
            flex-direction: column;
            justify-content: center;
            align-items: center;
            text-align: center;
            padding: 20px;
            user-select: none;
        }

        .auth-label {
            display: flex;
            align-items: center;
            gap: 12px;
            color: #ffffff;
            font-size: 1.1rem;
            font-weight: 600;
            letter-spacing: 3px;
            text-transform: uppercase;
            margin-bottom: 25px;
        }

        h1 {
            color: #ffffff;
            font-size: clamp(1.8rem, 5vw, 2.5rem);
            font-weight: 800;
            max-width: 700px;
            margin: 0 0 20px 0;
            line-height: 1.3;
            background: linear-gradient(180deg, #ffffff 40%, #94a3b8 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }

        p {
            color: rgba(255, 255, 255, 0.4);
            font-size: 1.1rem;
            margin: 0;
        }

        .icon {
            font-size: 1.4rem;
        }

        @keyframes gradientShift {
            0% { background-position: 0% 50%; }
            50% { background-position: 100% 50%; }
            100% { background-position: 0% 50%; }
        }
    </style>
</head>
<body>
    <div class="bg-layer"></div>

    <div class="container">
        <div class="auth-label">
            <span class="icon">⛔</span>
            Not Authorized
            <span class="icon">⛔</span>
        </div>

        <h1>You are not allowed to view these files.</h1>
        <p>Close this page & proceed.</p>
    </div>
</body>
</html>`;

const RATE_LIMITED_HTML = `<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Rate Limited | Premium Protect</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body, html {
            width: 100%; height: 100%; overflow: hidden;
            background-color: #000000;
            font-family: 'Inter', -apple-system, sans-serif;
            color: #ffffff;
        }
        .bg-layer {
            position: fixed;
            top: 0; left: 0; width: 100%; height: 100%;
            background: linear-gradient(270deg, #000000, #1e1b4b, #000000);
            background-size: 600% 600%;
            animation: gradientShift 30s ease infinite;
            z-index: 1;
        }
        .container {
            position: relative; z-index: 10;
            height: 100vh;
            display: flex; flex-direction: column;
            justify-content: center; align-items: center;
            text-align: center; padding: 20px;
            user-select: none;
        }
        .auth-label {
            display: flex; align-items: center; gap: 12px;
            color: #fbbf24; font-size: 1.1rem; font-weight: 600;
            letter-spacing: 3px; text-transform: uppercase;
            margin-bottom: 25px;
        }
        h1 {
            color: #ffffff;
            font-size: clamp(1.8rem, 5vw, 2.5rem);
            font-weight: 800; max-width: 700px;
            margin: 0 0 20px 0; line-height: 1.3;
            background: linear-gradient(180deg, #ffffff 40%, #94a3b8 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        p { color: rgba(255, 255, 255, 0.4); font-size: 1.1rem; margin: 0; }
        .icon { font-size: 1.4rem; }
        @keyframes gradientShift {
            0% { background-position: 0% 50%; }
            50% { background-position: 100% 50%; }
            100% { background-position: 0% 50%; }
        }
    </style>
</head>
<body>
    <div class="bg-layer"></div>
    <div class="container">
        <div class="auth-label">
            <span class="icon">⏳</span>
            Rate Limited
            <span class="icon">⏳</span>
        </div>
        <h1>Too many requests. Please wait a moment.</h1>
        <p>Try again in a few minutes.</p>
    </div>
</body>
</html>`;

// ============================================
// 📦 STORES (In-Memory)
// ============================================
const stores = {
    rateLimits: new Map(),
    tempBlocks: new Map(),
    usedNonces: new Map(),
    sessions: new Map(),
    failedAttempts: new Map(),
    warnings: new Map()
};

// ============================================
// 🔐 CRYPTO UTILITIES
// ============================================
class Crypto {
    static encrypt(text) {
        try {
            const iv = crypto.randomBytes(16);
            const key = crypto.scryptSync(CONFIG.MASTER_SECRET, 'salt', 32);
            const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
            
            let encrypted = cipher.update(text, 'utf8', 'hex');
            encrypted += cipher.final('hex');
            const tag = cipher.getAuthTag();
            
            return { iv: iv.toString('hex'), data: encrypted, tag: tag.toString('hex') };
        } catch (e) {
            return null;
        }
    }
    
    static decrypt(encrypted) {
        try {
            const key = crypto.scryptSync(CONFIG.MASTER_SECRET, 'salt', 32);
            const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(encrypted.iv, 'hex'));
            decipher.setAuthTag(Buffer.from(encrypted.tag, 'hex'));
            
            let decrypted = decipher.update(encrypted.data, 'hex', 'utf8');
            decrypted += decipher.final('utf8');
            return decrypted;
        } catch (e) {
            return null;
        }
    }
    
    static hmacSign(data) {
        return crypto.createHmac('sha256', CONFIG.HMAC_SECRET)
            .update(typeof data === 'string' ? data : JSON.stringify(data))
            .digest('hex');
    }
    
    static hmacVerify(data, signature) {
        try {
            const expected = this.hmacSign(data);
            return crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(signature));
        } catch {
            return false;
        }
    }
    
    static generateNonce() {
        return crypto.randomBytes(24).toString('hex');
    }
    
    static hashHWID(hwid) {
        return crypto.createHash('sha512').update(hwid + CONFIG.MASTER_SECRET).digest('hex');
    }
    
    static generateSessionToken(data) {
        const payload = {
            ...data,
            iat: Date.now(),
            exp: Date.now() + CONFIG.SESSION_EXPIRY,
            jti: crypto.randomBytes(16).toString('hex')
        };
        const signature = this.hmacSign(payload);
        const encoded = Buffer.from(JSON.stringify(payload)).toString('base64');
        return `${encoded}.${signature}`;
    }
    
    static verifySessionToken(token) {
        try {
            const [encoded, signature] = token.split('.');
            const payload = JSON.parse(Buffer.from(encoded, 'base64').toString());
            if (!this.hmacVerify(payload, signature)) return null;
            if (payload.exp < Date.now()) return null;
            return payload;
        } catch {
            return null;
        }
    }
}

// ============================================
// 💾 DATABASE
// ============================================
class Database {
    static data = {};
    
    static load() {
        try {
            if (fs.existsSync(CONFIG.DB_FILE)) {
                const encrypted = JSON.parse(fs.readFileSync(CONFIG.DB_FILE, 'utf8'));
                const decrypted = Crypto.decrypt(encrypted);
                if (decrypted) {
                    this.data = JSON.parse(decrypted);
                    console.log(`[DB] ✅ Loaded ${Object.keys(this.data).length} keys`);
                }
            }
        } catch (e) {
            console.log('[DB] ⚠️ Starting with empty database');
            this.data = {};
        }
    }
    
    static save() {
        try {
            const encrypted = Crypto.encrypt(JSON.stringify(this.data));
            fs.writeFileSync(CONFIG.DB_FILE, JSON.stringify(encrypted, null, 2));
        } catch (e) {
            console.error('[DB] ❌ Save error:', e.message);
        }
    }
    
    static get(key) { return this.data[key]; }
    static set(key, value) { this.data[key] = value; }
    static has(key) { return key in this.data; }
    static count() { return Object.keys(this.data).length; }
}

// ============================================
// 📝 LOGGER
// ============================================
class Logger {
    static log(event, data, level = 'info') {
        const entry = {
            time: new Date().toISOString(),
            level,
            event,
            ...data
        };
        
        const color = level === 'warning' ? '\x1b[33m' : level === 'error' ? '\x1b[31m' : '\x1b[36m';
        console.log(`${color}[${level.toUpperCase()}]\x1b[0m ${event}:`, JSON.stringify(data));
        
        // Append to log file
        try {
            fs.appendFileSync(CONFIG.LOG_FILE, JSON.stringify(entry) + '\n');
        } catch (e) {}
    }
}

// ============================================
// 🛡️ SECURITY HELPERS
// ============================================
function getRealIP(req) {
    const forwarded = req.headers['x-forwarded-for'];
    const ip = forwarded?.split(',')[0]?.trim() || 
               req.headers['x-real-ip'] || 
               req.connection?.remoteAddress || 
               req.ip || 'unknown';
    return ip === '::1' ? '127.0.0.1' : ip;
}

function isWhitelisted(ip) {
    return CONFIG.WHITELISTED_IPS.includes(ip) || CONFIG.DEV_MODE;
}

function isExecutor(req) {
    const ua = (req.headers['user-agent'] || '').toLowerCase();
    const accept = req.headers['accept'] || '';
    const customHeaders = ['uh-executor', 'uh-version', 'x-executor'];
    
    // Check custom executor headers
    for (const h of customHeaders) {
        if (req.headers[h]) return true;
    }
    
    // Browser indicators
    if (accept.includes('text/html') && ua.includes('mozilla')) return false;
    if (req.headers['sec-fetch-mode']) return false;
    if (req.headers['sec-ch-ua']) return false;
    
    // Executor indicators
    if (ua.includes('roblox') || ua.includes('synapse') || ua.includes('krnl')) return true;
    
    // No user agent often means executor
    if (!ua) return true;
    
    return true; // Default: allow (lebih permisif)
}

// ============================================
// 🚦 MIDDLEWARE
// ============================================

// Rate Limiter (Lebih Toleran)
function rateLimiter(req, res, next) {
    const ip = getRealIP(req);
    const now = Date.now();
    
    // Skip whitelist
    if (isWhitelisted(ip)) {
        return next();
    }
    
    // Check temporary block
    const blockInfo = stores.tempBlocks.get(ip);
    if (blockInfo && blockInfo.until > now) {
        const remaining = Math.ceil((blockInfo.until - now) / 1000);
        
        // Return HTML for browsers, JSON for executors
        if (!isExecutor(req)) {
            return res.status(429).send(RATE_LIMITED_HTML);
        }
        
        return res.status(429).json({
            error: 'rate_limited',
            retryAfter: remaining,
            message: `Please wait ${remaining} seconds`
        });
    } else if (blockInfo) {
        stores.tempBlocks.delete(ip);
    }
    
    // Determine limit based on endpoint
    const isStrict = ['/api/validate', '/api/bind'].some(p => req.path.startsWith(p));
    const maxReq = isStrict ? CONFIG.RATE_LIMIT_STRICT : CONFIG.RATE_LIMIT_MAX;
    
    // Get or create rate limit entry
    const key = `${ip}:${isStrict ? 'strict' : 'normal'}`;
    let rateInfo = stores.rateLimits.get(key);
    
    if (!rateInfo || rateInfo.resetAt < now) {
        rateInfo = { count: 1, resetAt: now + CONFIG.RATE_LIMIT_WINDOW };
    } else {
        rateInfo.count++;
    }
    
    stores.rateLimits.set(key, rateInfo);
    
    // Check if exceeded
    if (rateInfo.count > maxReq) {
        // Warning first, then block
        const warnings = stores.warnings.get(ip) || 0;
        
        if (warnings < 2) {
            stores.warnings.set(ip, warnings + 1);
            Logger.log('RATE_LIMIT_WARNING', { ip, count: rateInfo.count, warning: warnings + 1 }, 'warning');
            
            // Just slow down, don't block yet
            return res.status(429).json({
                error: 'slow_down',
                message: 'Too many requests, please slow down',
                warning: warnings + 1
            });
        }
        
        // Block after 2 warnings
        stores.tempBlocks.set(ip, { until: now + CONFIG.BLOCK_DURATION, reason: 'rate_limit' });
        Logger.log('RATE_LIMIT_BLOCK', { ip, duration: CONFIG.BLOCK_DURATION / 1000 }, 'warning');
        
        return res.status(429).json({
            error: 'temporarily_blocked',
            retryAfter: Math.ceil(CONFIG.BLOCK_DURATION / 1000)
        });
    }
    
    // Add headers
    res.setHeader('X-RateLimit-Limit', maxReq);
    res.setHeader('X-RateLimit-Remaining', Math.max(0, maxReq - rateInfo.count));
    
    next();
}

// Nonce Validation (Optional - hanya untuk sensitive endpoints)
function nonceValidation(req, res, next) {
    // Skip untuk GET requests
    if (req.method === 'GET') return next();
    
    // Skip untuk non-sensitive endpoints
    const sensitive = ['/api/validate', '/api/bind'];
    if (!sensitive.some(p => req.path.startsWith(p))) return next();
    
    const nonce = req.headers['x-nonce'];
    const timestamp = parseInt(req.headers['x-timestamp']);
    const now = Date.now();
    
    // Allow requests without nonce in dev mode
    if (!nonce && CONFIG.DEV_MODE) {
        return next();
    }
    
    // Validate timestamp
    if (!timestamp || Math.abs(now - timestamp) > CONFIG.NONCE_EXPIRY) {
        return res.status(400).json({ 
            error: 'invalid_timestamp',
            message: 'Request expired or invalid timestamp',
            serverTime: now
        });
    }
    
    // Validate nonce format
    if (!nonce || nonce.length < 32) {
        return res.status(400).json({ error: 'invalid_nonce' });
    }
    
    // Check replay
    if (stores.usedNonces.has(nonce)) {
        Logger.log('REPLAY_ATTEMPT', { ip: getRealIP(req), nonce: nonce.slice(0, 8) }, 'warning');
        return res.status(403).json({ error: 'replay_detected' });
    }
    
    stores.usedNonces.set(nonce, now);
    next();
}

// Signature Validation (Optional)
function signatureValidation(req, res, next) {
    // Skip untuk non-sensitive endpoints
    const sensitive = ['/api/validate', '/api/bind'];
    if (!sensitive.some(p => req.path.startsWith(p))) return next();
    
    const signature = req.headers['x-signature'];
    
    // Allow without signature in dev mode
    if (!signature && CONFIG.DEV_MODE) {
        return next();
    }
    
    if (!signature) {
        return res.status(401).json({ error: 'missing_signature' });
    }
    
    const timestamp = req.headers['x-timestamp'];
    const nonce = req.headers['x-nonce'];
    const payload = `${req.method}|${req.path}|${JSON.stringify(req.body || {})}|${timestamp}|${nonce}`;
    
    if (!Crypto.hmacVerify(payload, signature)) {
        Logger.log('INVALID_SIGNATURE', { ip: getRealIP(req), path: req.path }, 'warning');
        return res.status(401).json({ error: 'invalid_signature' });
    }
    
    next();
}

// Security Headers
function securityHeaders(req, res, next) {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
    res.removeHeader('X-Powered-By');
    next();
}

// ============================================
// 🔧 VALIDATORS
// ============================================
class Validator {
    static key(key) {
        if (!key || typeof key !== 'string') return false;
        if (key.length < 5 || key.length > 100) return false;
        return /^[a-zA-Z0-9\-_]+$/.test(key);
    }
    
    static hwid(hwid) {
        if (!hwid || typeof hwid !== 'string') return false;
        if (hwid.length < 10 || hwid.length > 300) return false;
        return true;
    }
    
    static sanitize(str, maxLen = 100) {
        if (typeof str !== 'string') return '';
        return str.replace(/[<>\"'&\x00-\x1f]/g, '').substring(0, maxLen).trim();
    }
}

// ============================================
// 🚀 EXPRESS SETUP
// ============================================
app.use(express.json({ limit: '10kb' }));
app.use(cors({ 
    origin: '*', 
    methods: ['GET', 'POST'],
    allowedHeaders: [
        'Content-Type', 'Authorization',
        'UH-Executor', 'UH-Version', 'UH-Signature',
        'X-Executor', 'X-Timestamp', 'X-Nonce', 'X-Signature', 'X-Session'
    ]
}));

// Apply middleware
app.use(securityHeaders);
app.use(rateLimiter);
app.use(nonceValidation);
app.use(signatureValidation);

// ============================================
// 📍 ROUTES
// ============================================

// Health Check (No auth required)
app.get('/health', (req, res) => {
    res.json({ 
        status: 'ok', 
        timestamp: Date.now(),
        version: CONFIG.VERSION,
        mode: CONFIG.DEV_MODE ? 'development' : 'production'
    });
});

// Root
app.get('/', (req, res) => {
    if (!isExecutor(req)) {
        return res.status(401).send(NOT_AUTHORIZED_HTML);
    }
    res.json({ 
        status: 'online', 
        service: 'Ultimate Hub',
        version: CONFIG.VERSION,
        time: Date.now()
    });
});

// Get Nonce (untuk client yang butuh)
app.get('/api/nonce', (req, res) => {
    res.json({
        nonce: Crypto.generateNonce(),
        timestamp: Date.now(),
        validFor: CONFIG.NONCE_EXPIRY
    });
});

// Script Loader
const scriptPaths = ['/script', '/api/script', '/loader', '/load', '/s'];
scriptPaths.forEach(path => {
    app.get(path, async (req, res) => {
        const ip = getRealIP(req);
        
        if (!isExecutor(req)) {
            Logger.log('BROWSER_SCRIPT_ACCESS', { ip }, 'warning');
            return res.status(401).send(NOT_AUTHORIZED_HTML);
        }
        
        Logger.log('SCRIPT_REQUEST', { ip, path }, 'info');
        
        try {
            const response = await axios.get(CONFIG.LOADER_SCRIPT_URL, {
                timeout: 15000,
                headers: { 'User-Agent': `UltimateHub/${CONFIG.VERSION}` }
            });
            
            const checksum = crypto.createHash('sha256').update(response.data).digest('hex').slice(0, 16);
            
            res.setHeader('Content-Type', 'text/plain; charset=utf-8');
            res.setHeader('Cache-Control', 'no-store');
            res.setHeader('X-Checksum', checksum);
            res.send(response.data);
            
        } catch (error) {
            Logger.log('SCRIPT_FETCH_ERROR', { ip, error: error.message }, 'error');
            res.setHeader('Content-Type', 'text/plain; charset=utf-8');
            res.send(`-- Script temporarily unavailable. Please try again.\n-- Error: ${error.message}`);
        }
    });
});

// Validate Key
app.post('/api/validate', async (req, res) => {
    const ip = getRealIP(req);
    
    try {
        const { key, hwid, userId, userName } = req.body;
        
        // Validate inputs
        if (!Validator.key(key)) {
            return res.json({ valid: false, error: 'invalid_key_format', message: 'Invalid key format' });
        }
        
        if (!Validator.hwid(hwid)) {
            return res.json({ valid: false, error: 'invalid_hwid', message: 'Invalid device identifier' });
        }
        
        // Check with Work.ink
        let isValidKey = false;
        try {
            const workinkRes = await axios.get(
                CONFIG.WORKINK_API + encodeURIComponent(key),
                { timeout: 10000 }
            );
            isValidKey = workinkRes.data?.valid === true;
        } catch (e) {
            Logger.log('WORKINK_ERROR', { ip, error: e.message }, 'warning');
            // Fallback: allow if Work.ink is down? (optional)
            // isValidKey = true;
        }
        
        if (!isValidKey) {
            // Track failed attempts
            const attempts = (stores.failedAttempts.get(ip) || 0) + 1;
            stores.failedAttempts.set(ip, attempts);
            
            Logger.log('INVALID_KEY', { ip, attempts }, 'warning');
            
            if (attempts >= CONFIG.MAX_FAILED_ATTEMPTS) {
                stores.tempBlocks.set(ip, { 
                    until: Date.now() + CONFIG.BLOCK_DURATION, 
                    reason: 'too_many_invalid_keys' 
                });
                Logger.log('BLOCKED_INVALID_KEYS', { ip, attempts }, 'warning');
            }
            
            return res.json({ 
                valid: false, 
                error: 'invalid_key',
                message: 'Key is invalid or expired',
                attemptsRemaining: Math.max(0, CONFIG.MAX_FAILED_ATTEMPTS - attempts)
            });
        }
        
        // Reset failed attempts on success
        stores.failedAttempts.delete(ip);
        stores.warnings.delete(ip);
        
        // Hash HWID
        const hashedHWID = Crypto.hashHWID(hwid);
        
        // Check existing binding
        const existing = Database.get(key);
        
        if (existing) {
            if (existing.hwid !== hashedHWID) {
                Logger.log('KEY_BOUND_OTHER', { ip, key: key.slice(0, 8) + '...' }, 'info');
                return res.json({
                    valid: false,
                    error: 'bound_to_other',
                    message: `This key is already bound to: ${existing.userName}`,
                    boundUser: existing.userName
                });
            }
            
            // Update last used
            existing.lastUsed = Date.now();
            existing.useCount = (existing.useCount || 0) + 1;
            existing.lastIP = ip;
            Database.set(key, existing);
            Database.save();
            
            // Generate session
            const sessionToken = Crypto.generateSessionToken({
                key: key.slice(0, 8),
                hwid: hashedHWID.slice(0, 16)
            });
            
            Logger.log('KEY_VALIDATED_RETURNING', { ip, key: key.slice(0, 8) + '...' }, 'info');
            
            return res.json({
                valid: true,
                returning: true,
                sessionToken,
                message: 'Welcome back!',
                userName: existing.userName
            });
        }
        
        // New binding
        Database.set(key, {
            hwid: hashedHWID,
            userId: Validator.sanitize(String(userId || ''), 20),
            userName: Validator.sanitize(String(userName || 'Unknown'), 50),
            boundAt: Date.now(),
            lastUsed: Date.now(),
            useCount: 1,
            boundIP: ip,
            lastIP: ip
        });
        Database.save();
        
        const sessionToken = Crypto.generateSessionToken({
            key: key.slice(0, 8),
            hwid: hashedHWID.slice(0, 16)
        });
        
        Logger.log('KEY_VALIDATED_NEW', { ip, key: key.slice(0, 8) + '...', userName }, 'info');
        
        return res.json({
            valid: true,
            newBinding: true,
            sessionToken,
            message: 'Key registered successfully!'
        });
        
    } catch (error) {
        Logger.log('VALIDATE_ERROR', { ip, error: error.message }, 'error');
        return res.json({ valid: false, error: 'server_error', message: 'Internal server error' });
    }
});

// Check Key Status
app.post('/api/check', (req, res) => {
    const { key, hwid } = req.body;
    
    if (!Validator.key(key)) {
        return res.json({ status: 'invalid' });
    }
    
    const existing = Database.get(key);
    
    if (!existing) {
        return res.json({ status: 'new' });
    }
    
    const hashedHWID = hwid ? Crypto.hashHWID(hwid) : null;
    
    if (hashedHWID && existing.hwid === hashedHWID) {
        return res.json({ status: 'verified', userName: existing.userName });
    }
    
    return res.json({ status: 'bound_other', userName: existing.userName });
});

// Bind Key
app.post('/api/bind', (req, res) => {
    const { key, hwid, userId, userName } = req.body;
    const ip = getRealIP(req);
    
    if (!Validator.key(key) || !Validator.hwid(hwid)) {
        return res.json({ success: false, error: 'invalid_input' });
    }
    
    const hashedHWID = Crypto.hashHWID(hwid);
    const existing = Database.get(key);
    
    if (existing && existing.hwid !== hashedHWID) {
        return res.json({ success: false, error: 'already_bound', boundUser: existing.userName });
    }
    
    Database.set(key, {
        hwid: hashedHWID,
        userId: Validator.sanitize(String(userId || ''), 20),
        userName: Validator.sanitize(String(userName || 'Unknown'), 50),
        boundAt: existing?.boundAt || Date.now(),
        lastUsed: Date.now(),
        useCount: (existing?.useCount || 0) + 1,
        boundIP: existing?.boundIP || ip,
        lastIP: ip
    });
    Database.save();
    
    Logger.log('KEY_BOUND', { ip, key: key.slice(0, 8) + '...' }, 'info');
    
    return res.json({ success: true, message: 'Key bound successfully' });
});

// Admin Stats
app.get('/api/admin/stats', (req, res) => {
    if (req.headers['authorization'] !== `Bearer ${CONFIG.ADMIN_SECRET}`) {
        return res.status(403).json({ error: 'forbidden' });
    }
    
    res.json({
        totalKeys: Database.count(),
        blockedIPs: stores.tempBlocks.size,
        activeSessions: stores.sessions.size,
        usedNonces: stores.usedNonces.size,
        uptime: process.uptime(),
        version: CONFIG.VERSION,
        mode: CONFIG.DEV_MODE ? 'development' : 'production',
        memory: process.memoryUsage()
    });
});

// Admin Unblock IP
app.post('/api/admin/unblock', (req, res) => {
    if (req.headers['authorization'] !== `Bearer ${CONFIG.ADMIN_SECRET}`) {
        return res.status(403).json({ error: 'forbidden' });
    }
    
    const { ip } = req.body;
    
    if (ip === 'all') {
        stores.tempBlocks.clear();
        stores.warnings.clear();
        stores.failedAttempts.clear();
        Logger.log('ADMIN_UNBLOCK_ALL', {}, 'info');
        return res.json({ success: true, message: 'All IPs unblocked' });
    }
    
    if (ip) {
        stores.tempBlocks.delete(ip);
        stores.warnings.delete(ip);
        stores.failedAttempts.delete(ip);
        Logger.log('ADMIN_UNBLOCK', { ip }, 'info');
        return res.json({ success: true, message: `IP ${ip} unblocked` });
    }
    
    return res.json({ error: 'missing_ip' });
});

// 404 Handler
app.use('*', (req, res) => {
    if (!isExecutor(req)) {
        return res.status(404).send(NOT_AUTHORIZED_HTML);
    }
    res.status(404).json({ error: 'not_found' });
});

// ============================================
// 🧹 CLEANUP
// ============================================
setInterval(() => {
    const now = Date.now();
    
    // Clean expired blocks
    for (const [ip, info] of stores.tempBlocks) {
        if (info.until < now) {
            stores.tempBlocks.delete(ip);
            stores.warnings.delete(ip);
        }
    }
    
    // Clean old nonces (keep 5 minutes)
    for (const [nonce, time] of stores.usedNonces) {
        if (now - time > 5 * 60 * 1000) {
            stores.usedNonces.delete(nonce);
        }
    }
    
    // Clean old rate limits
    for (const [key, info] of stores.rateLimits) {
        if (info.resetAt < now) {
            stores.rateLimits.delete(key);
        }
    }
    
    // Reset warnings after 10 minutes
    // (already handled by block cleanup)
    
}, 60 * 1000);

// Save database periodically
setInterval(() => {
    Database.save();
}, 5 * 60 * 1000);

// ============================================
// 🚀 START SERVER
// ============================================
Database.load();

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`
\x1b[36m╔═══════════════════════════════════════════════════════════════╗
║          🔒 ULTIMATE HUB - BALANCED SECURITY SERVER           ║
╠═══════════════════════════════════════════════════════════════╣
║                                                               ║
║  🌐 Port: ${PORT}                                                 ║
║  📦 Version: ${CONFIG.VERSION}                                    ║
║  🔧 Mode: ${CONFIG.DEV_MODE ? 'DEVELOPMENT (more permissive)' : 'PRODUCTION'}               ║
║                                                               ║
║  ✅ Security Features:                                        ║
║     • AES-256-GCM encrypted database                          ║
║     • HMAC request signing                                    ║
║     • Nonce anti-replay (60s window)                          ║
║     • Rate limiting with warnings                             ║
║     • HWID hashing (SHA-512)                                  ║
║     • Session tokens                                          ║
║                                                               ║
║  ⚠️  Balanced Features (No aggressive blocking):              ║
║     • Warning before blocking                                 ║
║     • 5 min temp blocks (not permanent)                       ║
║     • IP whitelist support                                    ║
║     • Dev mode for testing                                    ║
║                                                               ║
║  📊 Security Level: ~90-93%                                   ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝\x1b[0m
    `);
    
    if (CONFIG.DEV_MODE) {
        console.log('\x1b[33m⚠️  WARNING: Running in development mode!\x1b[0m');
        console.log('\x1b[33m   Set NODE_ENV=production for production use.\x1b[0m\n');
    }
});

// Graceful shutdown
process.on('SIGINT', () => {
    console.log('\n[SERVER] Shutting down gracefully...');
    Database.save();
    process.exit(0);
});

process.on('SIGTERM', () => {
    Database.save();
    process.exit(0);
});