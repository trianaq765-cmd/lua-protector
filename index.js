const express = require('express');
const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// =============================================
// KONFIGURASI SCRIPT KAMU
// =============================================
const SCRIPTS = {
    "loader": `
        print("=================================")
        print("   Ultimate Hub Loaded!")
        print("   Welcome to the script!")
        print("=================================")
        
        -- Tambahkan script utama kamu di sini
        local player = game.Players.LocalPlayer
        print("Player: " .. player.Name)
        
        -- Contoh: Load script tambahan
        -- loadstring(game:HttpGet("URL_SCRIPT_LAIN"))()
    `,
    
    "main": `
        print("Main script loaded!")
        -- Script utama kamu di sini
    `,
    
    "esp": `
        print("ESP Script loaded!")
        -- Script ESP kamu di sini
    `
};

// License keys yang valid
const VALID_LICENSES = {
    "KEY-ABC123": { user: "Player1", expires: "2025-12-31" },
    "KEY-XYZ789": { user: "Player2", expires: "2025-12-31" },
    "ByToingDc": { user: "ToingDC", expires: "2099-12-31" }
};

// =============================================
// FUNGSI CEK APAKAH REQUEST DARI ROBLOX/EXECUTOR
// =============================================
function isFromRoblox(req) {
    const userAgent = req.headers['user-agent'] || '';
    const robloxSignatures = [
        'roblox',
        'synapse',
        'krnl', 
        'fluxus',
        'electron',
        'script-ware',
        'sentinel',
        'sirhurt',
        'delta',
        'hydrogen',
        'arceus',
        'evon',
        'comet'
    ];
    
    // Cek User-Agent
    const ua = userAgent.toLowerCase();
    for (const sig of robloxSignatures) {
        if (ua.includes(sig)) return true;
    }
    
    // Cek header khusus executor
    if (req.headers['syn-fingerprint']) return true;
    if (req.headers['krnl-fingerprint']) return true;
    if (req.headers['fluxus-fingerprint']) return true;
    if (req.headers['exploit-guid']) return true;
    if (req.headers['roblox-id']) return true;
    
    // Cek apakah request POST dengan body JSON (biasanya dari executor)
    if (req.method === 'POST' && req.body && Object.keys(req.body).length > 0) {
        return true;
    }
    
    return false;
}

// =============================================
// HALAMAN BLOCKED (SEPERTI LUARMOR)
// =============================================
const BLOCKED_HTML = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Access Denied</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        body {
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 50%, #0f0f23 100%);
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            overflow: hidden;
        }
        .container {
            text-align: center;
            padding: 60px 40px;
            background: rgba(255, 255, 255, 0.03);
            border-radius: 20px;
            border: 1px solid rgba(255, 255, 255, 0.1);
            backdrop-filter: blur(10px);
            box-shadow: 0 25px 50px rgba(0, 0, 0, 0.5);
            max-width: 500px;
            animation: fadeIn 0.5s ease-out;
        }
        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(-20px); }
            to { opacity: 1; transform: translateY(0); }
        }
        .icon {
            font-size: 80px;
            margin-bottom: 20px;
            animation: pulse 2s infinite;
        }
        @keyframes pulse {
            0%, 100% { transform: scale(1); }
            50% { transform: scale(1.1); }
        }
        h1 {
            color: #ff4757;
            font-size: 32px;
            margin-bottom: 20px;
            text-transform: uppercase;
            letter-spacing: 3px;
            text-shadow: 0 0 20px rgba(255, 71, 87, 0.5);
        }
        p {
            color: #a0a0a0;
            font-size: 16px;
            line-height: 1.8;
            margin-bottom: 15px;
        }
        .warning {
            color: #ffa502;
            font-weight: bold;
            font-size: 14px;
            margin-top: 30px;
            padding: 15px;
            background: rgba(255, 165, 2, 0.1);
            border-radius: 10px;
            border: 1px solid rgba(255, 165, 2, 0.3);
        }
        .close-btn {
            margin-top: 30px;
            padding: 15px 40px;
            background: linear-gradient(135deg, #ff4757, #ff3344);
            color: white;
            border: none;
            border-radius: 30px;
            font-size: 16px;
            font-weight: bold;
            cursor: pointer;
            transition: all 0.3s ease;
            text-transform: uppercase;
            letter-spacing: 2px;
        }
        .close-btn:hover {
            transform: translateY(-3px);
            box-shadow: 0 10px 30px rgba(255, 71, 87, 0.4);
        }
        .footer {
            margin-top: 40px;
            color: #555;
            font-size: 12px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="icon">⛔</div>
        <h1>Not Authorized</h1>
        <p>You are not allowed to view these files.</p>
        <p>This content is protected and can only be accessed through authorized channels.</p>
        <div class="warning">
            ⚠️ Close this page & proceed with the executor.
        </div>
        <button class="close-btn" onclick="window.close(); window.location.href='about:blank';">
            Close Page
        </button>
        <div class="footer">
            Protected by Lua Protector | ToingDC
        </div>
    </div>
    <script>
        // Auto redirect after 5 seconds
        setTimeout(() => {
            window.location.href = 'https://www.google.com';
        }, 10000);
    </script>
</body>
</html>
`;

// =============================================
// ROUTES
// =============================================

// Homepage - Block browser access
app.get('/', (req, res) => {
    if (isFromRoblox(req)) {
        res.send('Server Online | Lua Protector Active');
    } else {
        res.status(403).send(BLOCKED_HTML);
    }
});

// GET Script (Block browser, allow executor)
app.get('/script/:name', (req, res) => {
    if (!isFromRoblox(req)) {
        return res.status(403).send(BLOCKED_HTML);
    }
    
    const scriptName = req.params.name;
    const script = SCRIPTS[scriptName];
    
    if (script) {
        res.setHeader('Content-Type', 'text/plain');
        res.send(script);
    } else {
        res.status(404).send('-- Script not found');
    }
});

// POST Get Script with License Check
app.post('/getscript', (req, res) => {
    if (!isFromRoblox(req)) {
        return res.status(403).json({ success: false, message: "Unauthorized access" });
    }
    
    const { license, scriptId } = req.body;
    
    // Cek license
    if (!license) {
        return res.json({ success: false, message: "License key required!" });
    }
    
    if (!VALID_LICENSES[license]) {
        return res.json({ success: false, message: "Invalid license key!" });
    }
    
    // Cek expired
    const licenseData = VALID_LICENSES[license];
    const expireDate = new Date(licenseData.expires);
    if (new Date() > expireDate) {
        return res.json({ success: false, message: "License expired!" });
    }
    
    // Ambil script
    const script = SCRIPTS[scriptId || "loader"];
    if (!script) {
        return res.json({ success: false, message: "Script not found!" });
    }
    
    res.json({ 
        success: true, 
        script: script,
        user: licenseData.user,
        message: "Script loaded successfully!"
    });
});

// Verify License Only
app.post('/verify', (req, res) => {
    const { license } = req.body;
    
    if (!license || !VALID_LICENSES[license]) {
        return res.json({ success: false, message: "Invalid license!" });
    }
    
    const licenseData = VALID_LICENSES[license];
    res.json({ 
        success: true, 
        user: licenseData.user,
        expires: licenseData.expires
    });
});

// Health check for Railway
app.get('/health', (req, res) => {
    res.json({ status: 'online', timestamp: new Date().toISOString() });
});

// Block all other routes
app.use('*', (req, res) => {
    if (isFromRoblox(req)) {
        res.status(404).send('-- Route not found');
    } else {
        res.status(403).send(BLOCKED_HTML);
    }
});

// Start server
app.listen(PORT, '0.0.0.0', () => {
    console.log(`✅ Server running on port ${PORT}`);
    console.log(`🔒 Lua Protector Active`);
});
