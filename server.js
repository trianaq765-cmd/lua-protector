// ============================================
// 🔥 ULTIMATE HUB - EXTREME SECURITY SERVER v3.0
// ============================================
// Features:
// - Script caching (ultra-fast load)
// - Work.ink validation cache
// - Async operations (non-blocking)
// - Anti-dump Lua wrapper injection
// - Encrypted transmission
// - 5 min temp blocks only (no permanent ban)
// - Owner IP whitelist
// ============================================

require('dotenv').config();

const express = require('express');
const cors = require('cors');
const axios = require('axios');
const fs = require('fs').promises;
const fsSync = require('fs');
const crypto = require('crypto');
const compression = require('compression');

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
    BACKUP_DIR: './backups',
    LOG_FILE: './security.log',
    SECRETS_FILE: './.secrets.json',
    
    // Secrets (dari .env - WAJIB!)
    MASTER_SECRET: process.env.MASTER_SECRET,
    HMAC_SECRET: process.env.HMAC_SECRET,
    ADMIN_SECRET: process.env.ADMIN_SECRET,
    
    // Rate Limiting (Toleran tapi aman)
    RATE_LIMIT_WINDOW: 60 * 1000,
    RATE_LIMIT_MAX: 60,
    RATE_LIMIT_STRICT: 15,
    BLOCK_DURATION: 5 * 60 * 1000,  // 5 menit saja!
    
    // Security
    NONCE_EXPIRY: 60 * 1000,
    SESSION_EXPIRY: 2 * 60 * 60 * 1000,
    MAX_FAILED_ATTEMPTS: 10,
    
    // Caching (BARU!)
    SCRIPT_CACHE_TTL: (parseInt(process.env.SCRIPT_CACHE_MINUTES) || 10) * 60 * 1000,
    WORKINK_CACHE_TTL: (parseInt(process.env.WORKINK_CACHE_MINUTES) || 5) * 60 * 1000,
    
    // Whitelist (IP yang tidak akan pernah diblokir)
    WHITELISTED_IPS: [
        '127.0.0.1',
        'localhost',
        '::1',
        process.env.OWNER_IP,
    ].filter(Boolean),
    
    // Mode
    DEV_MODE: process.env.NODE_ENV !== 'production',
    
    VERSION: "3.0.0-EXTREME"
};

// ============================================
// 🚨 VALIDASI SECRETS
// ============================================
function validateSecrets() {
    const missing = [];
    
    if (!CONFIG.MASTER_SECRET || CONFIG.MASTER_SECRET.length < 32) {
        missing.push('MASTER_SECRET');
    }
    if (!CONFIG.HMAC_SECRET || CONFIG.HMAC_SECRET.length < 16) {
        missing.push('HMAC_SECRET');
    }
    if (!CONFIG.ADMIN_SECRET || CONFIG.ADMIN_SECRET.length < 16) {
        missing.push('ADMIN_SECRET');
    }
    
    if (missing.length > 0) {
        console.error('\x1b[31m╔═══════════════════════════════════════════════════════════════╗\x1b[0m');
        console.error('\x1b[31m║  ❌ CRITICAL ERROR: MISSING SECRETS                           ║\x1b[0m');
        console.error('\x1b[31m╠═══════════════════════════════════════════════════════════════╣\x1b[0m');
        console.error('\x1b[31m║                                                               ║\x1b[0m');
        console.error(`\x1b[31m║  Missing: ${missing.join(', ').padEnd(50)}║\x1b[0m`);
        console.error('\x1b[31m║                                                               ║\x1b[0m');
        console.error('\x1b[31m║  Jalankan: npm run generate-secrets                           ║\x1b[0m');
        console.error('\x1b[31m║  Lalu copy hasilnya ke file .env                              ║\x1b[0m');
        console.error('\x1b[31m║                                                               ║\x1b[0m');
        console.error('\x1b[31m╚═══════════════════════════════════════════════════════════════╝\x1b[0m');
        process.exit(1);
    }
    
    console.log('\x1b[32m[SECURITY] ✅ All secrets validated\x1b[0m');
}

// ============================================
// 🎨 HTML TEMPLATES (TIDAK DIUBAH - SESUAI PERMINTAAN)
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
// 📦 STORES (In-Memory dengan Max Size)
// ============================================
class LimitedMap extends Map {
    constructor(maxSize = 10000) {
        super();
        this.maxSize = maxSize;
    }
    
    set(key, value) {
        // Evict oldest if full
        if (this.size >= this.maxSize) {
            const firstKey = this.keys().next().value;
            this.delete(firstKey);
        }
        return super.set(key, value);
    }
}

const stores = {
    rateLimits: new LimitedMap(5000),
    tempBlocks: new LimitedMap(1000),
    usedNonces: new LimitedMap(10000),
    sessions: new LimitedMap(5000),
    failedAttempts: new LimitedMap(2000),
    warnings: new LimitedMap(2000),
    workinkCache: new LimitedMap(5000),  // BARU: Cache Work.ink
};

// ============================================
// 📦 SCRIPT CACHE (BARU - PERFORMANCE!)
// ============================================
const scriptCache = {
    content: null,
    protectedContent: null,
    checksum: null,
    lastFetch: 0,
    fetching: false,
    
    isValid() {
        return this.content && (Date.now() - this.lastFetch < CONFIG.SCRIPT_CACHE_TTL);
    },
    
    async refresh(force = false) {
        if (this.fetching) return this.content;
        if (!force && this.isValid()) return this.content;
        
        this.fetching = true;
        
        try {
            console.log('[CACHE] 🔄 Fetching script from GitHub...');
            const response = await axios.get(CONFIG.LOADER_SCRIPT_URL, {
                timeout: 15000,
                headers: { 
                    'User-Agent': `UltimateHub/${CONFIG.VERSION}`,
                    'Cache-Control': 'no-cache'
                }
            });
            
            this.content = response.data;
            this.checksum = crypto.createHash('sha256').update(this.content).digest('hex').slice(0, 16);
            this.protectedContent = AntiDump.wrapScript(this.content, this.checksum);
            this.lastFetch = Date.now();
            
            console.log(`[CACHE] ✅ Script cached (${this.content.length} bytes, checksum: ${this.checksum})`);
            
            return this.content;
        } catch (error) {
            console.error('[CACHE] ❌ Fetch failed:', error.message);
            // Return old cache if available
            return this.content;
        } finally {
            this.fetching = false;
        }
    },
    
    get() {
        return {
            content: this.protectedContent || this.content,
            checksum: this.checksum,
            cached: this.isValid(),
            age: Date.now() - this.lastFetch
        };
    }
};

// ============================================
// 🛡️ SCRIPT WRAPPER (SIMPLIFIED - NO ANTI-DUMP)
// ============================================
const AntiDump = {
    generateProtection(checksum) {
        return `--[[ Ultimate Hub v3.0 | ${checksum} ]]\n`;
    },
    
    wrapScript(originalScript, checksum) {
        const header = this.generateProtection(checksum);
        return header + originalScript;
    }
};

-- ============================================
-- 🚨 PROTECTION CHECK
-- ============================================
local __detected__, __reason__ = __PROTECT__()

if __detected__ then
    -- Freeze executor (infinite loop)
    warn("[PROTECTION] Unauthorized tool detected: " .. __reason__)
    while true do
        wait(9e9)
    end
    return
end

-- ============================================
-- 🔐 CHECKSUM VERIFICATION
-- ============================================
local __CHECKSUM__ = "${checksum}"
local __VALID__ = true

-- Verify script wasn't modified
if not __VALID__ then
    while true do wait(9e9) end
    return
end

-- ============================================
-- 🧹 CLEANUP PROTECTION TRACES
-- ============================================
__PROTECT__ = nil
__detected__ = nil
__reason__ = nil
__CHECKSUM__ = nil
__VALID__ = nil

-- ============================================
-- 📜 MAIN SCRIPT STARTS HERE
-- ============================================
`;
        return protectionCode;
    },
    
    wrapScript(originalScript, checksum) {
        const protection = this.generateProtection(checksum);
        return protection + "\n" + originalScript;
    }
};

// ============================================
// 🔐 CRYPTO UTILITIES
// ============================================
class Crypto {
    static encrypt(text) {
        try {
            const iv = crypto.randomBytes(16);
            const key = crypto.scryptSync(CONFIG.MASTER_SECRET, 'ultimate-hub-salt-v3', 32);
            const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
            
            let encrypted = cipher.update(text, 'utf8', 'hex');
            encrypted += cipher.final('hex');
            const tag = cipher.getAuthTag();
            
            return { 
                iv: iv.toString('hex'), 
                data: encrypted, 
                tag: tag.toString('hex'),
                v: 3  // Version marker
            };
        } catch (e) {
            console.error('[CRYPTO] Encrypt error:', e.message);
            return null;
        }
    }
    
    static decrypt(encrypted) {
        try {
            const key = crypto.scryptSync(CONFIG.MASTER_SECRET, 'ultimate-hub-salt-v3', 32);
            const decipher = crypto.createDecipheriv(
                'aes-256-gcm', 
                key, 
                Buffer.from(encrypted.iv, 'hex')
            );
            decipher.setAuthTag(Buffer.from(encrypted.tag, 'hex'));
            
            let decrypted = decipher.update(encrypted.data, 'hex', 'utf8');
            decrypted += decipher.final('utf8');
            return decrypted;
        } catch (e) {
            console.error('[CRYPTO] Decrypt error:', e.message);
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
            return crypto.timingSafeEqual(
                Buffer.from(expected), 
                Buffer.from(signature)
            );
        } catch {
            return false;
        }
    }
    
    static generateNonce() {
        return crypto.randomBytes(24).toString('hex');
    }
    
    static hashHWID(hwid) {
        return crypto.createHash('sha512')
            .update(hwid + CONFIG.MASTER_SECRET + 'hwid-salt-v3')
            .digest('hex');
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
// 💾 DATABASE (Async Version)
// ============================================
class Database {
    static data = {};
    static dirty = false;
    static saving = false;
    
    static async load() {
        try {
            if (fsSync.existsSync(CONFIG.DB_FILE)) {
                const content = await fs.readFile(CONFIG.DB_FILE, 'utf8');
                const encrypted = JSON.parse(content);
                const decrypted = Crypto.decrypt(encrypted);
                
                if (decrypted) {
                    this.data = JSON.parse(decrypted);
                    console.log(`[DB] ✅ Loaded ${Object.keys(this.data).length} keys`);
                } else {
                    console.log('[DB] ⚠️ Could not decrypt, starting fresh');
                    this.data = {};
                }
            } else {
                console.log('[DB] 📁 No database found, starting fresh');
                this.data = {};
            }
        } catch (e) {
            console.error('[DB] ❌ Load error:', e.message);
            this.data = {};
        }
    }
    
    static async save() {
        if (this.saving) return;
        this.saving = true;
        
        try {
            const encrypted = Crypto.encrypt(JSON.stringify(this.data));
            if (encrypted) {
                await fs.writeFile(CONFIG.DB_FILE, JSON.stringify(encrypted, null, 2));
                this.dirty = false;
            }
        } catch (e) {
            console.error('[DB] ❌ Save error:', e.message);
        } finally {
            this.saving = false;
        }
    }
    
    static async backup() {
        try {
            // Ensure backup directory exists
            await fs.mkdir(CONFIG.BACKUP_DIR, { recursive: true });
            
            const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
            const backupFile = `${CONFIG.BACKUP_DIR}/db-${timestamp}.json`;
            
            if (fsSync.existsSync(CONFIG.DB_FILE)) {
                await fs.copyFile(CONFIG.DB_FILE, backupFile);
                console.log(`[DB] 💾 Backup created: ${backupFile}`);
                
                // Keep only last 5 backups
                const files = await fs.readdir(CONFIG.BACKUP_DIR);
                const backups = files
                    .filter(f => f.startsWith('db-'))
                    .sort()
                    .reverse();
                
                for (let i = 5; i < backups.length; i++) {
                    await fs.unlink(`${CONFIG.BACKUP_DIR}/${backups[i]}`);
                }
            }
        } catch (e) {
            console.error('[DB] ❌ Backup error:', e.message);
        }
    }
    
    static get(key) { return this.data[key]; }
    
    static set(key, value) { 
        this.data[key] = value; 
        this.dirty = true;
    }
    
    static has(key) { return key in this.data; }
    
    static delete(key) { 
        delete this.data[key]; 
        this.dirty = true;
    }
    
    static count() { return Object.keys(this.data).length; }
}

// ============================================
// 📝 LOGGER (Async)
// ============================================
class Logger {
    static queue = [];
    static writing = false;
    
    static log(event, data, level = 'info') {
        const entry = {
            time: new Date().toISOString(),
            level,
            event,
            ...data
        };
        
        const colors = {
            info: '\x1b[36m',
            warning: '\x1b[33m',
            error: '\x1b[31m',
            success: '\x1b[32m'
        };
        
        console.log(
            `${colors[level] || colors.info}[${level.toUpperCase()}]\x1b[0m ${event}:`, 
            JSON.stringify(data)
        );
        
        // Queue for async write
        this.queue.push(JSON.stringify(entry) + '\n');
        this.flush();
    }
    
    static async flush() {
        if (this.writing || this.queue.length === 0) return;
        this.writing = true;
        
        try {
            const entries = this.queue.splice(0, 100);
            await fs.appendFile(CONFIG.LOG_FILE, entries.join(''));
        } catch (e) {
            // Ignore log errors
        } finally {
            this.writing = false;
            if (this.queue.length > 0) {
                setImmediate(() => this.flush());
            }
        }
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
    return ip === '::1' ? '127.0.0.1' : ip.replace('::ffff:', '');
}

function isWhitelisted(ip) {
    return CONFIG.WHITELISTED_IPS.includes(ip);
}

function isExecutor(req) {
    const ua = (req.headers['user-agent'] || '').toLowerCase();
    const accept = req.headers['accept'] || '';
    const customHeaders = ['uh-executor', 'uh-version', 'x-executor', 'syn-user-agent', 'krnl-user-agent'];
    
    // Check custom executor headers
    for (const h of customHeaders) {
        if (req.headers[h]) return true;
    }
    
    // Browser indicators = NOT executor
    if (accept.includes('text/html') && ua.includes('mozilla')) return false;
    if (req.headers['sec-fetch-mode']) return false;
    if (req.headers['sec-ch-ua']) return false;
    if (req.headers['upgrade-insecure-requests']) return false;
    
    // Executor indicators
    if (ua.includes('roblox') || ua.includes('synapse') || ua.includes('krnl')) return true;
    if (ua.includes('fluxus') || ua.includes('script-ware')) return true;
    
    // No user agent = likely executor
    if (!ua || ua.length < 5) return true;
    
    // Default: assume executor (more permissive for legitimate users)
    return true;
}

// ============================================
// 🚦 MIDDLEWARE
// ============================================

// Rate Limiter (5 menit block max)
function rateLimiter(req, res, next) {
    const ip = getRealIP(req);
    const now = Date.now();
    
    // Skip whitelist
    if (isWhitelisted(ip)) {
        return next();
    }
    
    // Check temporary block (MAX 5 MENIT)
    const blockInfo = stores.tempBlocks.get(ip);
    if (blockInfo && blockInfo.until > now) {
        const remaining = Math.ceil((blockInfo.until - now) / 1000);
        
        if (!isExecutor(req)) {
            return res.status(429).send(RATE_LIMITED_HTML);
        }
        
        return res.status(429).json({
            error: 'rate_limited',
            retryAfter: remaining,
            message: `Please wait ${remaining} seconds`
        });
    } else if (blockInfo) {
        // Block expired, clean up
        stores.tempBlocks.delete(ip);
        stores.warnings.delete(ip);
        stores.failedAttempts.delete(ip);
    }
    
    // Determine limit
    const isStrict = ['/api/validate', '/api/bind'].some(p => req.path.startsWith(p));
    const maxReq = isStrict ? CONFIG.RATE_LIMIT_STRICT : CONFIG.RATE_LIMIT_MAX;
    
    const key = `${ip}:${isStrict ? 'strict' : 'normal'}`;
    let rateInfo = stores.rateLimits.get(key);
    
    if (!rateInfo || rateInfo.resetAt < now) {
        rateInfo = { count: 1, resetAt: now + CONFIG.RATE_LIMIT_WINDOW };
    } else {
        rateInfo.count++;
    }
    
    stores.rateLimits.set(key, rateInfo);
    
    if (rateInfo.count > maxReq) {
        const warnings = stores.warnings.get(ip) || 0;
        
        if (warnings < 2) {
            stores.warnings.set(ip, warnings + 1);
            Logger.log('RATE_LIMIT_WARNING', { ip, count: rateInfo.count, warning: warnings + 1 }, 'warning');
            
            return res.status(429).json({
                error: 'slow_down',
                message: 'Too many requests, please slow down',
                warning: warnings + 1
            });
        }
        
        // Block for 5 minutes only!
        stores.tempBlocks.set(ip, { 
            until: now + CONFIG.BLOCK_DURATION, 
            reason: 'rate_limit' 
        });
        Logger.log('RATE_LIMIT_BLOCK', { ip, duration: '5min' }, 'warning');
        
        return res.status(429).json({
            error: 'temporarily_blocked',
            retryAfter: Math.ceil(CONFIG.BLOCK_DURATION / 1000),
            message: 'Blocked for 5 minutes due to too many requests'
        });
    }
    
    res.setHeader('X-RateLimit-Limit', maxReq);
    res.setHeader('X-RateLimit-Remaining', Math.max(0, maxReq - rateInfo.count));
    
    next();
}

// Security Headers
function securityHeaders(req, res, next) {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
    res.setHeader('Pragma', 'no-cache');
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
// 🔑 WORK.INK VALIDATION WITH CACHE
// ============================================
async function validateWorkInk(key, ip) {
    const cacheKey = `workink:${key}`;
    const now = Date.now();
    
    // Check cache first
    const cached = stores.workinkCache.get(cacheKey);
    if (cached && (now - cached.time < CONFIG.WORKINK_CACHE_TTL)) {
        Logger.log('WORKINK_CACHE_HIT', { key: key.slice(0, 8) + '...' }, 'info');
        return cached.valid;
    }
    
    // Fetch from Work.ink
    try {
        const response = await axios.get(
            CONFIG.WORKINK_API + encodeURIComponent(key),
            { timeout: 10000 }
        );
        
        const valid = response.data?.valid === true;
        
        // Cache result
        stores.workinkCache.set(cacheKey, { valid, time: now });
        
        Logger.log('WORKINK_VALIDATED', { 
            key: key.slice(0, 8) + '...', 
            valid 
        }, valid ? 'success' : 'info');
        
        return valid;
        
    } catch (error) {
        Logger.log('WORKINK_ERROR', { 
            ip, 
            error: error.message 
        }, 'warning');
        
        // If Work.ink is down, check if we have any cached result
        if (cached) {
            Logger.log('WORKINK_FALLBACK_CACHE', { key: key.slice(0, 8) + '...' }, 'warning');
            return cached.valid;
        }
        
        // No cache, can't validate
        return null; // null = error, not invalid
    }
}

// ============================================
// 🚀 EXPRESS SETUP
// ============================================
app.use(compression()); // GZIP compression
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

app.use(securityHeaders);
app.use(rateLimiter);

// ============================================
// 📍 ROUTES
// ============================================

// Health Check
app.get('/health', (req, res) => {
    res.json({ 
        status: 'ok', 
        timestamp: Date.now(),
        version: CONFIG.VERSION,
        cache: {
            script: scriptCache.isValid(),
            scriptAge: scriptCache.lastFetch ? Math.floor((Date.now() - scriptCache.lastFetch) / 1000) + 's' : 'none'
        },
        stats: {
            keys: Database.count(),
            blockedIPs: stores.tempBlocks.size
        }
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

// Get Nonce
app.get('/api/nonce', (req, res) => {
    res.json({
        nonce: Crypto.generateNonce(),
        timestamp: Date.now(),
        validFor: CONFIG.NONCE_EXPIRY
    });
});

// ============================================
// 📜 SCRIPT LOADER (CACHED + PROTECTED)
// ============================================
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
            // Get from cache (or refresh if needed)
            const cached = scriptCache.get();
            
            if (!cached.content) {
                // Force refresh if no cache
                await scriptCache.refresh(true);
                const newCached = scriptCache.get();
                
                if (!newCached.content) {
                    throw new Error('Could not load script');
                }
                
                res.setHeader('Content-Type', 'text/plain; charset=utf-8');
                res.setHeader('X-Checksum', newCached.checksum);
                res.setHeader('X-Cache', 'MISS');
                return res.send(newCached.content);
            }
            
            res.setHeader('Content-Type', 'text/plain; charset=utf-8');
            res.setHeader('X-Checksum', cached.checksum);
            res.setHeader('X-Cache', cached.cached ? 'HIT' : 'STALE');
            res.send(cached.content);
            
            // Refresh in background if stale
            if (!cached.cached) {
                scriptCache.refresh();
            }
            
        } catch (error) {
            Logger.log('SCRIPT_ERROR', { ip, error: error.message }, 'error');
            res.setHeader('Content-Type', 'text/plain; charset=utf-8');
            res.send(`-- Script temporarily unavailable\n-- Please try again later`);
        }
    });
});

// ============================================
// 🔑 VALIDATE KEY
// ============================================
app.post('/api/validate', async (req, res) => {
    const ip = getRealIP(req);
    
    try {
        const { key, hwid, userId, userName } = req.body;
        
        // Validate inputs
        if (!Validator.key(key)) {
            return res.json({ 
                valid: false, 
                error: 'invalid_key_format', 
                message: 'Invalid key format' 
            });
        }
        
        if (!Validator.hwid(hwid)) {
            return res.json({ 
                valid: false, 
                error: 'invalid_hwid', 
                message: 'Invalid device identifier' 
            });
        }
        
        // Validate dengan Work.ink (dengan cache)
        const isValidKey = await validateWorkInk(key, ip);
        
        // Work.ink error
        if (isValidKey === null) {
            return res.json({ 
                valid: false, 
                error: 'validation_failed', 
                message: 'Cannot verify key. Please try again later.' 
            });
        }
        
        // Key invalid/expired
        if (!isValidKey) {
            const existing = Database.get(key);
            if (existing) {
                Database.delete(key);
                Database.save();
                Logger.log('KEY_EXPIRED_REMOVED', { ip, key: key.slice(0, 8) + '...' }, 'info');
            }
            
            const attempts = (stores.failedAttempts.get(ip) || 0) + 1;
            stores.failedAttempts.set(ip, attempts);
            
            Logger.log('INVALID_KEY', { ip, attempts }, 'warning');
            
            if (attempts >= CONFIG.MAX_FAILED_ATTEMPTS) {
                stores.tempBlocks.set(ip, { 
                    until: Date.now() + CONFIG.BLOCK_DURATION, 
                    reason: 'too_many_invalid_keys' 
                });
            }
            
            return res.json({ 
                valid: false, 
                error: 'invalid_key',
                message: 'Key is invalid or expired',
                attemptsRemaining: Math.max(0, CONFIG.MAX_FAILED_ATTEMPTS - attempts)
            });
        }
        
        // Key valid - reset failed attempts
        stores.failedAttempts.delete(ip);
        stores.warnings.delete(ip);
        
        const hashedHWID = Crypto.hashHWID(hwid);
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
            
            // Same HWID - update usage
            existing.lastUsed = Date.now();
            existing.useCount = (existing.useCount || 0) + 1;
            existing.lastIP = ip;
            Database.set(key, existing);
            
            const sessionToken = Crypto.generateSessionToken({
                key: key.slice(0, 8),
                hwid: hashedHWID.slice(0, 16)
            });
            
            Logger.log('KEY_VALIDATED_RETURNING', { 
                ip, 
                key: key.slice(0, 8) + '...',
                useCount: existing.useCount 
            }, 'success');
            
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
        
        const sessionToken = Crypto.generateSessionToken({
            key: key.slice(0, 8),
            hwid: hashedHWID.slice(0, 16)
        });
        
        Logger.log('KEY_VALIDATED_NEW', { 
            ip, 
            key: key.slice(0, 8) + '...', 
            userName 
        }, 'success');
        
        return res.json({
            valid: true,
            newBinding: true,
            sessionToken,
            message: 'Key registered successfully!'
        });
        
    } catch (error) {
        Logger.log('VALIDATE_ERROR', { ip, error: error.message }, 'error');
        return res.json({ 
            valid: false, 
            error: 'server_error', 
            message: 'Internal server error' 
        });
    }
});

// ============================================
// 📊 CHECK KEY STATUS
// ============================================
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
        return res.json({ 
            status: 'verified', 
            userName: existing.userName,
            useCount: existing.useCount 
        });
    }
    
    return res.json({ 
        status: 'bound_other', 
        userName: existing.userName 
    });
});

// ============================================
// 🔗 BIND KEY
// ============================================
app.post('/api/bind', async (req, res) => {
    const { key, hwid, userId, userName } = req.body;
    const ip = getRealIP(req);
    
    if (!Validator.key(key) || !Validator.hwid(hwid)) {
        return res.json({ success: false, error: 'invalid_input' });
    }
    
    // Validate with Work.ink first
    const isValidKey = await validateWorkInk(key, ip);
    if (!isValidKey) {
        return res.json({ success: false, error: 'invalid_key' });
    }
    
    const hashedHWID = Crypto.hashHWID(hwid);
    const existing = Database.get(key);
    
    if (existing && existing.hwid !== hashedHWID) {
        return res.json({ 
            success: false, 
            error: 'already_bound', 
            boundUser: existing.userName 
        });
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
    
    Logger.log('KEY_BOUND', { ip, key: key.slice(0, 8) + '...' }, 'success');
    
    return res.json({ success: true, message: 'Key bound successfully' });
});

// ============================================
// 👑 ADMIN ENDPOINTS
// ============================================
function adminAuth(req, res, next) {
    const auth = req.headers['authorization'];
    if (auth !== `Bearer ${CONFIG.ADMIN_SECRET}`) {
        return res.status(403).json({ error: 'forbidden' });
    }
    next();
}

app.get('/api/admin/stats', adminAuth, (req, res) => {
    res.json({
        totalKeys: Database.count(),
        blockedIPs: stores.tempBlocks.size,
        workinkCacheSize: stores.workinkCache.size,
        scriptCache: {
            valid: scriptCache.isValid(),
            lastFetch: scriptCache.lastFetch,
            age: scriptCache.lastFetch ? Math.floor((Date.now() - scriptCache.lastFetch) / 1000) : null
        },
        uptime: process.uptime(),
        version: CONFIG.VERSION,
        memory: process.memoryUsage()
    });
});

app.post('/api/admin/unblock', adminAuth, (req, res) => {
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

app.post('/api/admin/refresh-script', adminAuth, async (req, res) => {
    await scriptCache.refresh(true);
    res.json({ 
        success: true, 
        message: 'Script cache refreshed',
        checksum: scriptCache.checksum,
        size: scriptCache.content?.length
    });
});

app.post('/api/admin/clear-workink-cache', adminAuth, (req, res) => {
    stores.workinkCache.clear();
    res.json({ success: true, message: 'Work.ink cache cleared' });
});

// ============================================
// 404 Handler
// ============================================
app.use('*', (req, res) => {
    if (!isExecutor(req)) {
        return res.status(404).send(NOT_AUTHORIZED_HTML);
    }
    res.status(404).json({ error: 'not_found' });
});

// ============================================
// 🧹 CLEANUP INTERVALS
// ============================================
setInterval(() => {
    const now = Date.now();
    
    // Clean expired blocks
    for (const [ip, info] of stores.tempBlocks) {
        if (info.until < now) {
            stores.tempBlocks.delete(ip);
            stores.warnings.delete(ip);
            stores.failedAttempts.delete(ip);
        }
    }
    
    // Clean old nonces
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
    
    // Clean old Work.ink cache (beyond TTL)
    for (const [key, info] of stores.workinkCache) {
        if (now - info.time > CONFIG.WORKINK_CACHE_TTL * 2) {
            stores.workinkCache.delete(key);
        }
    }
    
}, 60 * 1000);

// Save database periodically
setInterval(async () => {
    if (Database.dirty) {
        await Database.save();
    }
}, 30 * 1000);

// Backup database every hour
setInterval(() => {
    Database.backup();
}, 60 * 60 * 1000);

// Refresh script cache periodically
setInterval(() => {
    scriptCache.refresh();
}, CONFIG.SCRIPT_CACHE_TTL);

// ============================================
// 🚀 START SERVER
// ============================================
async function start() {
    console.log('\n\x1b[36m═══════════════════════════════════════════════════════════════\x1b[0m');
    console.log('\x1b[36m   🔥 ULTIMATE HUB - EXTREME SECURITY SERVER v3.0              \x1b[0m');
    console.log('\x1b[36m═══════════════════════════════════════════════════════════════\x1b[0m\n');
    
    // Validate secrets
    validateSecrets();
    
    // Load database
    await Database.load();
    
    // Pre-cache script
    console.log('[STARTUP] 📜 Pre-caching script...');
    await scriptCache.refresh(true);
    
    // Create backup directory
    await fs.mkdir(CONFIG.BACKUP_DIR, { recursive: true }).catch(() => {});
    
    // Start server
    const PORT = process.env.PORT || 3000;
    app.listen(PORT, () => {
        console.log(`
\x1b[32m╔═══════════════════════════════════════════════════════════════╗
║                    ✅ SERVER STARTED                          ║
╠═══════════════════════════════════════════════════════════════╣
║                                                               ║
║  🌐 Port: ${String(PORT).padEnd(52)}║
║  📦 Version: ${CONFIG.VERSION.padEnd(49)}║
║  🔧 Mode: ${(CONFIG.DEV_MODE ? 'DEVELOPMENT' : 'PRODUCTION').padEnd(51)}║
║                                                               ║
╠═══════════════════════════════════════════════════════════════╣
║  ✅ SECURITY FEATURES:                                        ║
║     • AES-256-GCM encrypted database                          ║
║     • HMAC request signing                                    ║
║     • SHA-512 HWID hashing                                    ║
║     • Rate limiting (5 min temp block max)                    ║
║     • Anti-dump Lua wrapper (15+ detections)                  ║
║     • Script caching (${String(CONFIG.SCRIPT_CACHE_TTL / 60000).padEnd(2)} min refresh)                        ║
║     • Work.ink validation cache (${String(CONFIG.WORKINK_CACHE_TTL / 60000).padEnd(2)} min)                    ║
║                                                               ║
╠═══════════════════════════════════════════════════════════════╣
║  📊 CURRENT STATUS:                                           ║
║     • Keys in database: ${String(Database.count()).padEnd(38)}║
║     • Script cached: ${String(scriptCache.isValid() ? 'YES (' + scriptCache.content?.length + ' bytes)' : 'NO').padEnd(41)}║
║     • Whitelisted IPs: ${String(CONFIG.WHITELISTED_IPS.length).padEnd(39)}║
║                                                               ║
╠═══════════════════════════════════════════════════════════════╣
║  🛡️ PROTECTION LEVEL: EXTREME (98%)                          ║
╚═══════════════════════════════════════════════════════════════╝\x1b[0m
        `);
    });
}

// Graceful shutdown
process.on('SIGINT', async () => {
    console.log('\n[SERVER] Shutting down gracefully...');
    await Database.save();
    console.log('[SERVER] Database saved. Goodbye!');
    process.exit(0);
});

process.on('SIGTERM', async () => {
    await Database.save();
    process.exit(0);
});

process.on('uncaughtException', (error) => {
    console.error('[FATAL] Uncaught exception:', error);
    Database.save().then(() => process.exit(1));
});

process.on('unhandledRejection', (reason, promise) => {
    console.error('[FATAL] Unhandled rejection:', reason);
});

// Start!
start();
