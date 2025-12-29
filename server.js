const express = require('express');
const cors = require('cors');
const axios = require('axios');
const fs = require('fs');
const crypto = require('crypto');

const app = express();

// ============================================
// SECURITY: Rate Limiting Manual
// ============================================
const rateLimitStore = {};
const blockedIPs = {};
const RATE_LIMIT_WINDOW = 60 * 1000;
const RATE_LIMIT_MAX_REQUESTS = 30;
const BLOCK_DURATION = 5 * 60 * 1000;

function getRealIP(req) {
    return req.headers['x-forwarded-for']?.split(',')[0]?.trim() || 
           req.headers['x-real-ip'] || 
           req.connection?.remoteAddress || 
           req.ip || 
           'unknown';
}

function rateLimiter(req, res, next) {
    const ip = getRealIP(req);
    const now = Date.now();
    
    if (blockedIPs[ip] && blockedIPs[ip] > now) {
        const remainingTime = Math.ceil((blockedIPs[ip] - now) / 1000);
        return res.status(429).json({ 
            error: "Too many requests", 
            blocked: true,
            retryAfter: remainingTime 
        });
    } else if (blockedIPs[ip]) {
        delete blockedIPs[ip];
    }
    
    if (!rateLimitStore[ip] || rateLimitStore[ip].resetTime < now) {
        rateLimitStore[ip] = {
            count: 1,
            resetTime: now + RATE_LIMIT_WINDOW
        };
    } else {
        rateLimitStore[ip].count++;
    }
    
    if (rateLimitStore[ip].count > RATE_LIMIT_MAX_REQUESTS) {
        blockedIPs[ip] = now + BLOCK_DURATION;
        console.log(`[BLOCKED] IP ${ip} - Too many requests`);
        return res.status(429).json({ 
            error: "Rate limit exceeded", 
            blocked: true,
            retryAfter: Math.ceil(BLOCK_DURATION / 1000)
        });
    }
    
    next();
}

// ============================================
// SECURITY: CORS Configuration
// ============================================
const corsOptions = {
    origin: '*',
    methods: ['GET', 'POST'],
    allowedHeaders: ['Content-Type', 'UH-Executor', 'UH-Version', 'X-Executor', 'Authorization'],
    maxAge: 86400
};

app.use(cors(corsOptions));
app.use(express.json({ limit: '10kb' }));
app.use(rateLimiter);

// ============================================
// SECURITY: Security Headers Middleware
// ============================================
app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.removeHeader('X-Powered-By');
    next();
});

// ============================================
// DATABASE: Persistent File-Based
// ============================================
const DB_FILE = './keyDatabase.json';
const ADMIN_SECRET = process.env.ADMIN_SECRET || crypto.randomBytes(32).toString('hex');

let keyDatabase = {};

function loadDatabase() {
    try {
        if (fs.existsSync(DB_FILE)) {
            const data = fs.readFileSync(DB_FILE, 'utf8');
            keyDatabase = JSON.parse(data);
            console.log(`[DB] Loaded ${Object.keys(keyDatabase).length} keys`);
        }
    } catch (error) {
        console.error('[DB] Error loading database:', error.message);
        keyDatabase = {};
    }
}

function saveDatabase() {
    try {
        fs.writeFileSync(DB_FILE, JSON.stringify(keyDatabase, null, 2));
    } catch (error) {
        console.error('[DB] Error saving database:', error.message);
    }
}

setInterval(saveDatabase, 5 * 60 * 1000);
loadDatabase();

process.on('SIGINT', () => {
    console.log('[DB] Saving database before shutdown...');
    saveDatabase();
    process.exit(0);
});

process.on('SIGTERM', () => {
    console.log('[DB] Saving database before shutdown...');
    saveDatabase();
    process.exit(0);
});

const WORKINK_API = "https://work.ink/_api/v2/token/isValid/";

// ============================================
// SECURITY: Input Validation & Sanitization
// ============================================
function sanitizeString(str, maxLength = 100) {
    if (typeof str !== 'string') return '';
    return str.replace(/[<>\"'&]/g, '').substring(0, maxLength).trim();
}

function validateKey(key) {
    if (!key || typeof key !== 'string') return false;
    if (key.length < 5 || key.length > 100) return false;
    return /^[a-zA-Z0-9\-_]+$/.test(key);
}

function validateHWID(hwid) {
    if (!hwid || typeof hwid !== 'string') return false;
    if (hwid.length < 5 || hwid.length > 200) return false;
    return true;
}

function hashKey(key) {
    return crypto.createHash('sha256').update(key).digest('hex').substring(0, 16);
}

// ============================================
// HTML PAGE: Not Authorized
// ============================================
const NOT_AUTHORIZED_HTML = `<!DOCTYPE html>
<html lang="id">
<head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Unauthorized | Premium Protect</title>
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
            background: linear-gradient(270deg, #000000, #0f172a, #000000);
            background-size: 600% 600%;
            animation: gradientShift 30s ease infinite;
            z-index: 1;
        }
        .container {
            position: relative; z-index: 10; height: 100vh;
            display: flex; flex-direction: column;
            justify-content: center; align-items: center;
            text-align: center; padding: 20px; user-select: none;
        }
        .auth-label {
            display: flex; align-items: center; gap: 12px;
            color: #ffffff; font-size: 1.1rem; font-weight: 600;
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
            <span class="icon">⛔</span>
            Not Authorized
            <span class="icon">⛔</span>
        </div>
        <h1>You are not allowed to view these files.</h1>
        <p>Close this page & proceed.</p>
    </div>
</body>
</html>`;

// ============================================
// CORE SCRIPT URL (External)
// ============================================
const CORE_SCRIPT_URL = "https://api.junkie-development.de/api/v1/luascripts/public/8a56151af71ed4b56c346b2bef75d232f22d3ffb242e31d5ef79d12f69d974d6/download";

// Cache untuk core script
let cachedCoreScript = null;
let coreScriptLastFetch = 0;
const CORE_CACHE_TTL = 10 * 60 * 1000; // 10 menit

async function fetchCoreScript() {
    const now = Date.now();
    if (cachedCoreScript && (now - coreScriptLastFetch) < CORE_CACHE_TTL) {
        return cachedCoreScript;
    }
    
    try {
        const response = await axios.get(CORE_SCRIPT_URL, { timeout: 15000 });
        cachedCoreScript = response.data;
        coreScriptLastFetch = now;
        console.log('[CORE] Script cached successfully');
        return cachedCoreScript;
    } catch (error) {
        console.error('[CORE] Fetch error:', error.message);
        return cachedCoreScript || '-- Core script unavailable';
    }
}

// Pre-fetch core script saat startup
fetchCoreScript();

// ============================================
// MAIN LOADER SCRIPT (Single Loader - No Double Load)
// ============================================
const LOADER_SCRIPT = `--[[
    Ultimate Hub V9.3 - Loader
    Single Load System - No Double Loading
]]

-- Prevent double execution
if getgenv().UHLoading then return end
if getgenv().UHLoaded then
    pcall(function() getgenv().UHAdminMonitorActive = false end)
    pcall(function() getgenv().UH:Destroy() end)
    pcall(function() game:GetService("CoreGui"):FindFirstChild("UltimateHubKeySystem"):Destroy() end)
    pcall(function() game:GetService("CoreGui"):FindFirstChild("UltimateHubNotice"):Destroy() end)
    pcall(function() game:GetService("CoreGui"):FindFirstChild("Rayfield"):Destroy() end)
    
    if getgenv().UHConnections then
        for _, conn in pairs(getgenv().UHConnections) do
            pcall(function() conn:Disconnect() end)
        end
    end
    
    getgenv().UH = nil
    getgenv().UHCore = nil
    getgenv().UHLoaded = nil
    getgenv().UHConnections = nil
    task.wait(0.3)
end

getgenv().UHLoading = true
getgenv().UHConnections = {}
getgenv().UHAdminMonitorActive = true

local CFG = {
    SERVER = "https://lua-protector-production.up.railway.app",
    GET_KEY = "https://work.ink/29pu/key-sistem-3",
    SAVE_KEY = true,
    KEY_FILE = "UltimateHubKey.txt",
    USER_FILE = "UltimateHubUser.txt",
    MAX_ATTEMPTS = 5,
    COOLDOWN = 60,
    VERSION = "9.3",
    
    ADMIN_USERIDS = {
        9611823874,
        9282599330,
    },
    ADMIN_NAMES = {
        [9611823874] = "ToingDC",
        [9282599330] = "Admin2",
    },
    ADMIN_PROTECTION = true,
    BACKUP_CHECK_INTERVAL = 90,
}

local HttpService = game:GetService("HttpService")
local TweenService = game:GetService("TweenService")
local Players = game:GetService("Players")
local CoreGui = game:GetService("CoreGui")
local StarterGui = game:GetService("StarterGui")
local LocalPlayer = Players.LocalPlayer

local attempts = 0
local lastAttemptTime = 0
local isAdmin = false
local scriptDestroyed = false
local coreLoaded = false

-- Admin Detection
local function checkIfAdmin()
    for _, adminId in ipairs(CFG.ADMIN_USERIDS) do
        if LocalPlayer.UserId == adminId then return true end
    end
    return false
end

local function isPlayerAdmin(player)
    if not player then return false end
    for _, adminId in ipairs(CFG.ADMIN_USERIDS) do
        if player.UserId == adminId then return true end
    end
    return false
end

local function getAdminName(userId)
    return CFG.ADMIN_NAMES[userId] or "Admin"
end

local function checkAdminInServer()
    for _, player in ipairs(Players:GetPlayers()) do
        if player ~= LocalPlayer and isPlayerAdmin(player) then
            return true, player.Name, player.UserId
        end
    end
    return false, nil, nil
end

-- Notifications
local function showSmallNotice(title, message, duration, color)
    pcall(function()
        StarterGui:SetCore("SendNotification", {
            Title = title or "Ultimate Hub",
            Text = message or "",
            Duration = duration or 5,
        })
    end)
end

local function showTopNotice(adminName, isDestroy)
    pcall(function() CoreGui:FindFirstChild("UltimateHubNotice"):Destroy() end)
    
    local NoticeGui = Instance.new("ScreenGui")
    NoticeGui.Name = "UltimateHubNotice"
    NoticeGui.ResetOnSpawn = false
    NoticeGui.DisplayOrder = 999
    
    pcall(function() NoticeGui.Parent = CoreGui end)
    if not NoticeGui.Parent then
        pcall(function() NoticeGui.Parent = LocalPlayer:WaitForChild("PlayerGui") end)
    end
    
    local NoticeFrame = Instance.new("Frame")
    NoticeFrame.Name = "NoticeFrame"
    NoticeFrame.Size = UDim2.new(0, 320, 0, 70)
    NoticeFrame.Position = UDim2.new(0.5, -160, 0, -80)
    NoticeFrame.BackgroundColor3 = Color3.fromRGB(30, 25, 25)
    NoticeFrame.BorderSizePixel = 0
    NoticeFrame.Parent = NoticeGui
    
    Instance.new("UICorner", NoticeFrame).CornerRadius = UDim.new(0, 10)
    local Stroke = Instance.new("UIStroke", NoticeFrame)
    Stroke.Color = isDestroy and Color3.fromRGB(255, 80, 80) or Color3.fromRGB(255, 150, 50)
    Stroke.Thickness = 2
    
    local Icon = Instance.new("TextLabel")
    Icon.Size = UDim2.new(0, 40, 0, 40)
    Icon.Position = UDim2.new(0, 10, 0.5, -20)
    Icon.BackgroundTransparency = 1
    Icon.Text = isDestroy and "💥" or "⚠️"
    Icon.TextSize = 28
    Icon.Parent = NoticeFrame
    
    local Title = Instance.new("TextLabel")
    Title.Size = UDim2.new(1, -60, 0, 22)
    Title.Position = UDim2.new(0, 55, 0, 10)
    Title.BackgroundTransparency = 1
    Title.Text = isDestroy and "Script Dihancurkan!" or "Script Tidak Tersedia"
    Title.TextColor3 = isDestroy and Color3.fromRGB(255, 100, 100) or Color3.fromRGB(255, 180, 80)
    Title.TextSize = 14
    Title.Font = Enum.Font.GothamBold
    Title.TextXAlignment = Enum.TextXAlignment.Left
    Title.Parent = NoticeFrame
    
    local Message = Instance.new("TextLabel")
    Message.Size = UDim2.new(1, -60, 0, 20)
    Message.Position = UDim2.new(0, 55, 0, 32)
    Message.BackgroundTransparency = 1
    Message.Text = "👑 Ada " .. (adminName or "Admin") .. " disini"
    Message.TextColor3 = Color3.fromRGB(180, 180, 180)
    Message.TextSize = 12
    Message.Font = Enum.Font.Gotham
    Message.TextXAlignment = Enum.TextXAlignment.Left
    Message.Parent = NoticeFrame
    
    TweenService:Create(NoticeFrame, TweenInfo.new(0.4, Enum.EasingStyle.Back, Enum.EasingDirection.Out), {
        Position = UDim2.new(0.5, -160, 0, 15)
    }):Play()
    
    task.spawn(function()
        task.wait(8)
        if NoticeFrame and NoticeFrame.Parent then
            TweenService:Create(NoticeFrame, TweenInfo.new(0.3), {
                Position = UDim2.new(0.5, -160, 0, -80)
            }):Play()
            task.wait(0.3)
            if NoticeGui and NoticeGui.Parent then NoticeGui:Destroy() end
        end
    end)
    
    return NoticeGui
end

-- Destroy Script
local function destroyScript(adminName, adminId)
    if scriptDestroyed then return end
    scriptDestroyed = true
    getgenv().UHAdminMonitorActive = false
    
    showSmallNotice("💥 Script Terminated", "Admin " .. (adminName or "Unknown") .. " bergabung!", 5)
    showTopNotice(adminName, true)
    
    if getgenv().UHConnections then
        for i, conn in pairs(getgenv().UHConnections) do
            pcall(function() if conn and conn.Connected then conn:Disconnect() end end)
            getgenv().UHConnections[i] = nil
        end
    end
    
    pcall(function() if getgenv().UH then getgenv().UH:Destroy() end end)
    pcall(function() if getgenv().Rayfield then getgenv().Rayfield:Destroy() end end)
    
    getgenv().UH = nil
    getgenv().UHCore = nil
    getgenv().UHLoading = nil
    
    pcall(function()
        for _, gui in ipairs(CoreGui:GetChildren()) do
            if gui:IsA("ScreenGui") then
                local name = gui.Name:lower()
                if (name:find("ultimate") or name:find("rayfield") or name:find("hub")) and not name:find("notice") then
                    gui:Destroy()
                end
            end
        end
    end)
end

-- Admin Monitor
local function startAdminMonitor()
    if isAdmin or scriptDestroyed then return end
    
    local playerAddedConn = Players.PlayerAdded:Connect(function(player)
        if scriptDestroyed or not getgenv().UHAdminMonitorActive then return end
        task.defer(function()
            task.wait(0.5)
            if isPlayerAdmin(player) then
                destroyScript(getAdminName(player.UserId), player.UserId)
            end
        end)
    end)
    table.insert(getgenv().UHConnections, playerAddedConn)
    
    task.spawn(function()
        while true do
            task.wait(CFG.BACKUP_CHECK_INTERVAL)
            if scriptDestroyed or not getgenv().UHAdminMonitorActive or not getgenv().UHLoaded then break end
            local hasAdmin, playerName, adminId = checkAdminInServer()
            if hasAdmin then
                destroyScript(getAdminName(adminId), adminId)
                break
            end
        end
    end)
end

-- Init Admin Protection
local function initAdminProtection()
    if not CFG.ADMIN_PROTECTION then return true, nil end
    
    isAdmin = checkIfAdmin()
    
    if isAdmin then
        showSmallNotice("👑 Admin Mode", "Logged in sebagai Owner", 3)
        return true, nil
    end
    
    local hasAdmin, playerName, adminId = checkAdminInServer()
    if hasAdmin then
        local adminName = getAdminName(adminId)
        showTopNotice(adminName, false)
        showSmallNotice("⚠️ Script Disabled", "Ada " .. adminName .. " di server ini", 5)
        scriptDestroyed = true
        getgenv().UHLoading = nil
        return false, adminName
    end
    
    startAdminMonitor()
    return true, nil
end

-- Utility Functions
local function saveFile(name, content)
    if writefile then pcall(writefile, name, content) end
end

local function readFile(name)
    if isfile and readfile then
        local s, r = pcall(function() if isfile(name) then return readfile(name) end end)
        if s then return r end
    end
    return nil
end

local function deleteFile(name)
    if isfile and delfile then pcall(function() if isfile(name) then delfile(name) end end) end
end

local function setClipboard(text)
    if setclipboard then pcall(setclipboard, text) end
end

local function getHWID()
    local hwid
    local funcs = {
        function() return gethwid and gethwid() end,
        function() return getexecutorhwid and getexecutorhwid() end,
        function() return syn and syn.cache_hwid and syn.cache_hwid() end,
        function() return fluxus and fluxus.get_hwid and fluxus.get_hwid() end,
    }
    for _, f in ipairs(funcs) do
        local s, r = pcall(f)
        if s and r and r ~= "" then hwid = tostring(r) break end
    end
    return (hwid or "NOHWID") .. "_" .. LocalPlayer.UserId
end

local function doRequest(url, method, headers, body)
    headers = headers or {}
    headers["UH-Version"] = CFG.VERSION
    headers["UH-Executor"] = "true"
    
    local requestFunc = (syn and syn.request) or request or http_request or (fluxus and fluxus.request)
    if requestFunc then
        local s, r = pcall(function()
            return requestFunc({Url = url, Method = method or "GET", Headers = headers, Body = body})
        end)
        if s and r then return r end
    end
    
    if not method or method == "GET" then
        local s, r = pcall(function() return game:HttpGet(url) end)
        if s then return {Body = r, StatusCode = 200} end
    end
    return nil
end

local function openURL(url)
    if not url then return false end
    for _, n in ipairs({"openurl", "OpenURL", "open_url"}) do
        local f = getgenv()[n] or _G[n]
        if f and type(f) == "function" and pcall(f, url) then return true end
    end
    return false
end

-- Key Validation
local keyCache = {}

local function validateKey(key)
    if not key or key == "" then return false, "Please enter a key!" end
    key = key:gsub("^%s*(.-)%s*$", "%1")
    if #key < 5 then return false, "Key too short!" end
    
    if keyCache[key] and (os.time() - keyCache[key].time) < 300 then
        return keyCache[key].valid, keyCache[key].msg
    end
    
    local hwid = getHWID()
    
    local success, result = pcall(function()
        local response = doRequest(CFG.SERVER .. "/api/validate", "POST", {
            ["Content-Type"] = "application/json"
        }, HttpService:JSONEncode({
            key = key, hwid = hwid,
            userId = LocalPlayer.UserId,
            userName = LocalPlayer.Name
        }))
        if response and response.Body then
            return HttpService:JSONDecode(response.Body)
        end
    end)
    
    if success and result then
        if result.valid or result.success then
            if result.bound_to_other then
                keyCache[key] = {valid = false, msg = "Key bound to: " .. (result.bound_user or "Other"), time = os.time()}
                return false, keyCache[key].msg
            end
            keyCache[key] = {valid = true, msg = result.message or "Key Valid!", time = os.time()}
            return true, keyCache[key].msg
        else
            keyCache[key] = {valid = false, msg = result.message or "Invalid key!", time = os.time()}
            return false, keyCache[key].msg
        end
    end
    
    -- Fallback
    success, result = pcall(function()
        return HttpService:JSONDecode(game:HttpGet("https://work.ink/_api/v2/token/isValid/" .. key))
    end)
    if success and result and result.valid then
        keyCache[key] = {valid = true, msg = "Key Valid!", time = os.time()}
        return true, "Key Valid!"
    end
    
    keyCache[key] = {valid = false, msg = "Invalid key!", time = os.time()}
    return false, "Invalid key!"
end

-- Key System UI
local function createKeySystem()
    if scriptDestroyed then return false end
    
    pcall(function() CoreGui:FindFirstChild("UltimateHubKeySystem"):Destroy() end)
    task.wait(0.1)
    
    if CFG.SAVE_KEY then
        local savedKey = readFile(CFG.KEY_FILE)
        local savedUser = readFile(CFG.USER_FILE)
        local currentUser = getHWID()
        
        if savedKey and savedKey ~= "" then
            if savedUser and savedUser ~= currentUser then
                deleteFile(CFG.KEY_FILE)
                deleteFile(CFG.USER_FILE)
            else
                showSmallNotice("Ultimate Hub", "Checking saved key...", 2)
                if validateKey(savedKey) then
                    saveFile(CFG.USER_FILE, currentUser)
                    showSmallNotice("Ultimate Hub", "Key valid!", 2)
                    return true
                end
                deleteFile(CFG.KEY_FILE)
                deleteFile(CFG.USER_FILE)
            end
        end
    end
    
    local ScreenGui = Instance.new("ScreenGui")
    ScreenGui.Name = "UltimateHubKeySystem"
    ScreenGui.ResetOnSpawn = false
    pcall(function() ScreenGui.Parent = CoreGui end)
    if not ScreenGui.Parent then
        pcall(function() ScreenGui.Parent = LocalPlayer:WaitForChild("PlayerGui") end)
    end
    
    local Background = Instance.new("Frame")
    Background.Size = UDim2.new(1, 0, 1, 0)
    Background.BackgroundColor3 = Color3.fromRGB(0, 0, 0)
    Background.BackgroundTransparency = 0.5
    Background.BorderSizePixel = 0
    Background.Parent = ScreenGui
    
    local MainFrame = Instance.new("Frame")
    MainFrame.Size = UDim2.new(0, 360, 0, 220)
    MainFrame.BackgroundColor3 = Color3.fromRGB(25, 25, 35)
    MainFrame.BorderSizePixel = 0
    MainFrame.AnchorPoint = Vector2.new(0.5, 0.5)
    MainFrame.Position = UDim2.new(0.5, 0, 0.5, 0)
    MainFrame.Parent = ScreenGui
    Instance.new("UICorner", MainFrame).CornerRadius = UDim.new(0, 12)
    Instance.new("UIStroke", MainFrame).Color = Color3.fromRGB(100, 100, 255)
    
    local TitleBar = Instance.new("Frame")
    TitleBar.Size = UDim2.new(1, 0, 0, 45)
    TitleBar.BackgroundColor3 = Color3.fromRGB(30, 30, 45)
    TitleBar.BorderSizePixel = 0
    TitleBar.Parent = MainFrame
    Instance.new("UICorner", TitleBar).CornerRadius = UDim.new(0, 12)
    
    local TitleLabel = Instance.new("TextLabel")
    TitleLabel.Size = UDim2.new(1, 0, 0, 25)
    TitleLabel.Position = UDim2.new(0, 0, 0, 5)
    TitleLabel.BackgroundTransparency = 1
    TitleLabel.Text = "🔐 Ultimate Hub V" .. CFG.VERSION
    TitleLabel.TextColor3 = Color3.fromRGB(255, 255, 255)
    TitleLabel.TextSize = 18
    TitleLabel.Font = Enum.Font.GothamBold
    TitleLabel.Parent = TitleBar
    
    local StatusLabel = Instance.new("TextLabel")
    StatusLabel.Size = UDim2.new(1, 0, 0, 15)
    StatusLabel.Position = UDim2.new(0, 0, 0, 28)
    StatusLabel.BackgroundTransparency = 1
    StatusLabel.Text = isAdmin and "👑 Admin Mode" or "🔒 Protected"
    StatusLabel.TextColor3 = isAdmin and Color3.fromRGB(255, 215, 0) or Color3.fromRGB(100, 255, 100)
    StatusLabel.TextSize = 10
    StatusLabel.Font = Enum.Font.Gotham
    StatusLabel.Parent = TitleBar
    
    local UserInfo = Instance.new("TextLabel")
    UserInfo.Size = UDim2.new(1, 0, 0, 15)
    UserInfo.Position = UDim2.new(0, 0, 0, 50)
    UserInfo.BackgroundTransparency = 1
    UserInfo.Text = "👤 " .. LocalPlayer.Name .. " (" .. LocalPlayer.UserId .. ")"
    UserInfo.TextColor3 = Color3.fromRGB(120, 120, 140)
    UserInfo.TextSize = 10
    UserInfo.Font = Enum.Font.Gotham
    UserInfo.Parent = MainFrame
    
    local InputContainer = Instance.new("Frame")
    InputContainer.Size = UDim2.new(0, 320, 0, 40)
    InputContainer.Position = UDim2.new(0.5, -160, 0, 70)
    InputContainer.BackgroundColor3 = Color3.fromRGB(35, 35, 45)
    InputContainer.BorderSizePixel = 0
    InputContainer.Parent = MainFrame
    Instance.new("UICorner", InputContainer).CornerRadius = UDim.new(0, 8)
    local InputStroke = Instance.new("UIStroke", InputContainer)
    InputStroke.Color = Color3.fromRGB(60, 60, 80)
    
    local KeyInput = Instance.new("TextBox")
    KeyInput.Size = UDim2.new(1, -16, 1, 0)
    KeyInput.Position = UDim2.new(0, 8, 0, 0)
    KeyInput.BackgroundTransparency = 1
    KeyInput.PlaceholderText = "Paste your key here..."
    KeyInput.PlaceholderColor3 = Color3.fromRGB(100, 100, 100)
    KeyInput.TextColor3 = Color3.fromRGB(255, 255, 255)
    KeyInput.TextSize = 13
    KeyInput.Font = Enum.Font.Gotham
    KeyInput.ClearTextOnFocus = false
    KeyInput.Parent = InputContainer
    
    local StatusText = Instance.new("TextLabel")
    StatusText.Size = UDim2.new(1, -40, 0, 25)
    StatusText.Position = UDim2.new(0, 20, 0, 115)
    StatusText.BackgroundTransparency = 1
    StatusText.Text = ""
    StatusText.TextColor3 = Color3.fromRGB(255, 100, 100)
    StatusText.TextSize = 11
    StatusText.Font = Enum.Font.Gotham
    StatusText.TextWrapped = true
    StatusText.Parent = MainFrame
    
    local SubmitButton = Instance.new("TextButton")
    SubmitButton.Size = UDim2.new(0, 155, 0, 36)
    SubmitButton.Position = UDim2.new(0.5, -160, 0, 145)
    SubmitButton.BackgroundColor3 = Color3.fromRGB(80, 120, 255)
    SubmitButton.BorderSizePixel = 0
    SubmitButton.Text = "✓ Validate"
    SubmitButton.TextColor3 = Color3.fromRGB(255, 255, 255)
    SubmitButton.TextSize = 13
    SubmitButton.Font = Enum.Font.GothamBold
    SubmitButton.Parent = MainFrame
    Instance.new("UICorner", SubmitButton).CornerRadius = UDim.new(0, 8)
    
    local GetKeyButton = Instance.new("TextButton")
    GetKeyButton.Size = UDim2.new(0, 155, 0, 36)
    GetKeyButton.Position = UDim2.new(0.5, 5, 0, 145)
    GetKeyButton.BackgroundColor3 = Color3.fromRGB(88, 101, 242)
    GetKeyButton.BorderSizePixel = 0
    GetKeyButton.Text = "🔑 Get Key"
    GetKeyButton.TextColor3 = Color3.fromRGB(255, 255, 255)
    GetKeyButton.TextSize = 13
    GetKeyButton.Font = Enum.Font.GothamBold
    GetKeyButton.Parent = MainFrame
    Instance.new("UICorner", GetKeyButton).CornerRadius = UDim.new(0, 8)
    
    local AttemptsLabel = Instance.new("TextLabel")
    AttemptsLabel.Size = UDim2.new(1, -20, 0, 20)
    AttemptsLabel.Position = UDim2.new(0, 10, 1, -25)
    AttemptsLabel.BackgroundTransparency = 1
    AttemptsLabel.Text = "Attempts: 0/" .. CFG.MAX_ATTEMPTS .. " • by ToingDC"
    AttemptsLabel.TextColor3 = Color3.fromRGB(80, 80, 80)
    AttemptsLabel.TextSize = 10
    AttemptsLabel.Font = Enum.Font.Gotham
    AttemptsLabel.TextXAlignment = Enum.TextXAlignment.Left
    AttemptsLabel.Parent = MainFrame
    
    MainFrame.Size = UDim2.new(0, 0, 0, 0)
    TweenService:Create(MainFrame, TweenInfo.new(0.35, Enum.EasingStyle.Back), {
        Size = UDim2.new(0, 360, 0, 220)
    }):Play()
    
    local keyValid = false
    local validationComplete = Instance.new("BindableEvent")
    local isProcessing = false
    
    local function closeGUI()
        TweenService:Create(MainFrame, TweenInfo.new(0.2, Enum.EasingStyle.Back, Enum.EasingDirection.In), {
            Size = UDim2.new(0, 0, 0, 0)
        }):Play()
        task.wait(0.2)
        ScreenGui:Destroy()
    end
    
    local function submitKey()
        if isProcessing or scriptDestroyed then return end
        isProcessing = true
        
        local inputKey = KeyInput.Text:gsub("^%s*(.-)%s*$", "%1")
        
        if inputKey == "" then
            StatusText.Text = "⚠️ Enter a key!"
            StatusText.TextColor3 = Color3.fromRGB(255, 200, 100)
            isProcessing = false
            return
        end
        
        if attempts >= CFG.MAX_ATTEMPTS then
            local timeLeft = CFG.COOLDOWN - (os.time() - lastAttemptTime)
            if timeLeft > 0 then
                StatusText.Text = "⏳ Wait " .. timeLeft .. "s"
                isProcessing = false
                return
            end
            attempts = 0
        end
        
        StatusText.Text = "🔄 Checking..."
        StatusText.TextColor3 = Color3.fromRGB(255, 255, 100)
        SubmitButton.Text = "..."
        
        task.spawn(function()
            task.wait(0.2)
            
            local valid, message = validateKey(inputKey)
            
            if valid then
                StatusText.Text = "✅ " .. message
                StatusText.TextColor3 = Color3.fromRGB(100, 255, 100)
                SubmitButton.Text = "✓ Success!"
                SubmitButton.BackgroundColor3 = Color3.fromRGB(80, 200, 80)
                
                if CFG.SAVE_KEY then
                    saveFile(CFG.KEY_FILE, inputKey)
                    saveFile(CFG.USER_FILE, getHWID())
                end
                
                task.wait(1)
                closeGUI()
                keyValid = true
                validationComplete:Fire()
            else
                attempts = attempts + 1
                lastAttemptTime = os.time()
                StatusText.Text = "❌ " .. message
                StatusText.TextColor3 = Color3.fromRGB(255, 100, 100)
                SubmitButton.Text = "✓ Validate"
                SubmitButton.BackgroundColor3 = Color3.fromRGB(80, 120, 255)
                AttemptsLabel.Text = "Attempts: " .. attempts .. "/" .. CFG.MAX_ATTEMPTS .. " • by ToingDC"
                isProcessing = false
            end
        end)
    end
    
    local submitConn = SubmitButton.MouseButton1Click:Connect(submitKey)
    local enterConn = KeyInput.FocusLost:Connect(function(enter) if enter then submitKey() end end)
    local getKeyConn = GetKeyButton.MouseButton1Click:Connect(function()
        if openURL(CFG.GET_KEY) then
            StatusText.Text = "🌐 Browser opened!"
            StatusText.TextColor3 = Color3.fromRGB(100, 255, 100)
        else
            setClipboard(CFG.GET_KEY)
            StatusText.Text = "📋 Link copied!"
            StatusText.TextColor3 = Color3.fromRGB(100, 200, 255)
        end
    end)
    
    table.insert(getgenv().UHConnections, submitConn)
    table.insert(getgenv().UHConnections, enterConn)
    table.insert(getgenv().UHConnections, getKeyConn)
    
    validationComplete.Event:Wait()
    validationComplete:Destroy()
    return keyValid
end

-- Load Core (ONLY ONCE)
local function loadCore()
    if scriptDestroyed or coreLoaded then return false end
    
    showSmallNotice("Ultimate Hub", "Loading Core...", 2)
    
    local success = pcall(function()
        loadstring(game:HttpGet(CFG.SERVER .. "/core"))()
    end)
    
    if success then
        coreLoaded = true
        task.wait(0.3)
    end
    
    return success
end

-- Load Hub UI
local function loadHubUI()
    if scriptDestroyed then return end
    
    local C = getgenv().UHCore
    if not C then
        showSmallNotice("Error", "Core not loaded!", 3)
        return
    end
    
    showSmallNotice("Ultimate Hub", "Loading UI...", 2)
    
    local R
    local success = pcall(function()
        R = loadstring(game:HttpGet("https://sirius.menu/rayfield"))()
    end)
    
    if not success or not R then
        showSmallNotice("Error", "Failed to load UI!", 3)
        return
    end
    
    local S = C.Settings or {}
    
    R.Notify = function() end
    local W = R:CreateWindow({
        Name = "Ultimate Hub V" .. CFG.VERSION .. " | ToingDC",
        LoadingTitle = "Ultimate Hub",
        LoadingSubtitle = "by ToingDC",
        ConfigurationSaving = {Enabled = false},
        KeySystem = false
    })
    getgenv().UH = W
    
    -- ESP Tab
    local E = W:CreateTab("ESP", 4483362458)
    E:CreateSection("Player ESP")
    E:CreateToggle({Name = "Killer ESP", CurrentValue = false, Callback = function(v) if v then C.StartKillerESP() else C.StopKillerESP() end end})
    E:CreateToggle({Name = "Survivor ESP", CurrentValue = false, Callback = function(v) if v then C.StartSurvivorESP() else C.StopSurvivorESP() end end})
    E:CreateSection("Object ESP")
    E:CreateToggle({Name = "Generator ESP", CurrentValue = false, Callback = function(v) if v then C.StartGenESP() else C.StopGenESP() end end})
    E:CreateToggle({Name = "Pallet ESP", CurrentValue = false, Callback = function(v) if v then C.StartPalletESP() else C.StopPalletESP() end end})
    
    -- Survivor Tab
    local SV = W:CreateTab("Survivor", 4483362458)
    SV:CreateSection("Environment")
    SV:CreateToggle({Name = "No Fog", CurrentValue = false, Callback = function(v) if v then C.StartNoFog() else C.StopNoFog() end end})
    SV:CreateToggle({Name = "Fullbright", CurrentValue = false, Callback = function(v) C.SetFullbright(v) end})
    SV:CreateSection("Performance")
    SV:CreateToggle({Name = "Anti-Lag Mode", CurrentValue = false, Callback = function(v) if v then C.StartAntiLag() else C.StopAntiLag() end end})
    
    -- Killer Tab
    local K = W:CreateTab("Killer", 4483362458)
    K:CreateSection("Auto Attack")
    K:CreateToggle({Name = "Enable Auto Attack", CurrentValue = false, Callback = function(v) if v then C.StartAutoAttack() else C.StopAutoAttack() end end})
    K:CreateSlider({Name = "Attack Distance", Range = {5, 30}, Increment = 1, CurrentValue = 15, Callback = function(v) if S.Kil then S.Kil.AD = v end end})
    K:CreateSection("Protection")
    K:CreateToggle({Name = "Anti-Blind", CurrentValue = false, Callback = function(v) if v then C.StartAntiBlind() else C.StopAntiBlind() end end})
    
    -- Player Tab
    local P = W:CreateTab("Player", 4483362458)
    P:CreateSection("Speed Boost")
    local currentSpeed = (S.Plr and S.Plr.SP) or 16
    local SPL = P:CreateLabel("Speed: " .. currentSpeed)
    P:CreateButton({Name = "Speed -1", Callback = function() if S.Plr then S.Plr.SP = math.max(16, S.Plr.SP - 1) SPL:Set("Speed: " .. S.Plr.SP) end end})
    P:CreateButton({Name = "Speed +1", Callback = function() if S.Plr then S.Plr.SP = math.min(200, S.Plr.SP + 1) SPL:Set("Speed: " .. S.Plr.SP) end end})
    P:CreateToggle({Name = "Enable Speed", CurrentValue = false, Callback = function(v) 
        if C.WalkspeedSystem then if v then C.WalkspeedSystem:Start() else C.WalkspeedSystem:Stop() end end
    end})
    
    -- Aim Tab
    local A = W:CreateTab("Aim", 4483362458)
    A:CreateSection("Auto Aim")
    A:CreateToggle({Name = "Enable Auto Aim", CurrentValue = false, Callback = function(v) 
        if C.AimSystem then if v then C.AimSystem:Start() else C.AimSystem:Stop() end end
    end})
    A:CreateSection("Crosshair")
    A:CreateToggle({Name = "Enable Crosshair", CurrentValue = false, Callback = function(v) 
        if v then if C.StartCrosshair then C.StartCrosshair() end else if C.StopCrosshair then C.StopCrosshair() end end
    end})
    
    -- Settings Tab
    local STT = W:CreateTab("Settings", 4483362458)
    STT:CreateSection("Key System")
    STT:CreateButton({Name = "Clear Saved Key", Callback = function() 
        deleteFile(CFG.KEY_FILE) 
        deleteFile(CFG.USER_FILE) 
        showSmallNotice("Success", "Key cleared!", 2) 
    end})
    STT:CreateSection("Controls")
    STT:CreateButton({Name = "Stop All Features", Callback = function() if C.StopAll then C.StopAll() end end})
    STT:CreateButton({Name = "Destroy Hub", Callback = function() 
        if C.StopAll then C.StopAll() end 
        R:Destroy() 
        getgenv().UH = nil 
        getgenv().UHLoaded = nil 
        getgenv().UHLoading = nil
    end})
    
    getgenv().UHLoaded = true
    getgenv().UHLoading = nil
    
    showSmallNotice("Ultimate Hub", "Loaded! Welcome " .. LocalPlayer.Name, 3)
end

-- MAIN EXECUTION
local canContinue, adminName = initAdminProtection()

if not canContinue then
    print("[Ultimate Hub] Script disabled - Admin in server: " .. (adminName or "Unknown"))
    return
end

if createKeySystem() then
    if loadCore() then
        loadHubUI()
    end
end
`;

// ============================================
// DETECT ROBLOX EXECUTOR (FIXED)
// ============================================
function isRobloxExecutor(req) {
    const userAgent = (req.headers['user-agent'] || '').toLowerCase();
    const acceptHeader = req.headers['accept'] || '';
    const secFetchMode = req.headers['sec-fetch-mode'] || '';
    const secFetchDest = req.headers['sec-fetch-dest'] || '';
    
    const executorHeaders = [
        'uh-executor', 'uh-version', 'x-executor', 'roblox-id',
        'syn-fingerprint', 'exploitid', 'krnl-fingerprint',
        'fluxus-fingerprint', 'delta-fingerprint', 'script-ware-fingerprint'
    ];
    
    for (const header of executorHeaders) {
        if (req.headers[header]) {
            console.log(`[EXECUTOR] Detected via header: ${header}`);
            return true;
        }
    }
    
    const executorKeywords = ['roblox', 'syn', 'krnl', 'fluxus', 'delta', 'scriptware', 'sentinel', 'jjsploit', 'oxygen', 'electron', 'comet'];
    for (const keyword of executorKeywords) {
        if (userAgent.includes(keyword)) {
            console.log(`[EXECUTOR] Detected via UA: ${keyword}`);
            return true;
        }
    }
    
    if (secFetchMode === 'navigate' || secFetchDest === 'document') {
        console.log('[BROWSER] Detected via sec-fetch');
        return false;
    }
    
    const browserKeywords = ['mozilla', 'chrome', 'safari', 'firefox', 'edge', 'opera', 'msie', 'trident', 'webkit', 'gecko'];
    for (const keyword of browserKeywords) {
        if (userAgent.includes(keyword)) {
            console.log('[BROWSER] Detected via UA');
            return false;
        }
    }
    
    if (acceptHeader.includes('text/html')) {
        console.log('[BROWSER] Detected via Accept header');
        return false;
    }
    
    if (!userAgent || userAgent.length < 10) {
        console.log('[EXECUTOR] Empty/short UA');
        return true;
    }
    
    console.log('[EXECUTOR] Default');
    return true;
}

// ============================================
// ROUTES
// ============================================

app.get('/health', (req, res) => {
    res.json({ status: 'ok', timestamp: Date.now() });
});

app.get('/', (req, res) => {
    if (!isRobloxExecutor(req)) {
        return res.status(401).setHeader('Content-Type', 'text/html').send(NOT_AUTHORIZED_HTML);
    }
    res.json({ status: 'online', service: 'Ultimate Hub', version: '9.3' });
});

// Script endpoints - Return LOADER
const scriptPaths = ['/script', '/api/script', '/loader', '/load', '/run', '/execute', '/s'];
scriptPaths.forEach(path => {
    app.get(path, (req, res) => {
        if (!isRobloxExecutor(req)) {
            return res.status(401).setHeader('Content-Type', 'text/html').send(NOT_AUTHORIZED_HTML);
        }
        res.setHeader('Content-Type', 'text/plain; charset=utf-8');
        res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
        res.send(LOADER_SCRIPT);
    });
});

// Core endpoint - Return CORE SCRIPT (bukan loader)
app.get('/core', async (req, res) => {
    if (!isRobloxExecutor(req)) {
        return res.status(401).setHeader('Content-Type', 'text/html').send(NOT_AUTHORIZED_HTML);
    }
    
    try {
        const coreScript = await fetchCoreScript();
        res.setHeader('Content-Type', 'text/plain; charset=utf-8');
        res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
        res.send(coreScript);
    } catch (error) {
        console.error('[CORE] Error:', error.message);
        res.status(500).send('-- Core script error');
    }
});

// Validate Key
app.post('/api/validate', async (req, res) => {
    try {
        const { key, hwid, userId, userName } = req.body;

        if (!validateKey(key)) {
            return res.json({ valid: false, message: "Invalid key format!" });
        }
        
        if (!validateHWID(hwid)) {
            return res.json({ valid: false, message: "Invalid device identifier!" });
        }

        const sanitizedUserName = sanitizeString(userName, 50);
        const sanitizedUserId = sanitizeString(String(userId), 20);

        let isValidKey = false;
        try {
            const workinkResponse = await axios.get(WORKINK_API + encodeURIComponent(key), { 
                timeout: 10000,
                headers: { 'User-Agent': 'UltimateHub/9.3' }
            });
            if (workinkResponse.data && workinkResponse.data.valid === true) {
                isValidKey = true;
            }
        } catch (err) {
            console.log("[Work.ink] Error:", err.message);
        }

        if (!isValidKey) {
            return res.json({ valid: false, message: "Invalid key!" });
        }

        if (keyDatabase[key]) {
            const binding = keyDatabase[key];
            
            if (binding.hwid !== hwid) {
                return res.json({
                    valid: false,
                    bound_to_other: true,
                    bound_user: binding.userName,
                    message: "Key bound to: " + binding.userName
                });
            }

            binding.lastUsed = Date.now();
            binding.useCount = (binding.useCount || 0) + 1;
            saveDatabase();
            
            return res.json({
                valid: true,
                returning_user: true,
                message: "Welcome back!"
            });
        }

        keyDatabase[key] = {
            hwid: hwid,
            userId: sanitizedUserId,
            userName: sanitizedUserName,
            boundAt: Date.now(),
            lastUsed: Date.now(),
            useCount: 1,
            ip: getRealIP(req)
        };

        saveDatabase();
        console.log(`[NEW KEY] ${hashKey(key)} -> ${sanitizedUserName}`);
        
        return res.json({ valid: true, new_binding: true, message: "Key registered!" });

    } catch (error) {
        console.error("[Validate] Error:", error.message);
        return res.json({ valid: false, message: "Server error!" });
    }
});

app.post('/api/check', (req, res) => {
    const { key, hwid } = req.body;
    
    if (!validateKey(key)) {
        return res.json({ status: "error", message: "Invalid key format" });
    }

    if (keyDatabase[key]) {
        if (keyDatabase[key].hwid === hwid) {
            return res.json({ status: "verified", userName: keyDatabase[key].userName });
        }
        return res.json({ status: "bound_other", userName: keyDatabase[key].userName });
    }
    return res.json({ status: "new" });
});

app.post('/api/bind', (req, res) => {
    const { key, hwid, userId, userName } = req.body;
    
    if (!validateKey(key) || !validateHWID(hwid)) {
        return res.json({ success: false, message: "Invalid input" });
    }

    if (keyDatabase[key] && keyDatabase[key].hwid !== hwid) {
        return res.json({ success: false, message: "Already bound" });
    }

    keyDatabase[key] = { 
        hwid, 
        userId: sanitizeString(String(userId), 20), 
        userName: sanitizeString(userName, 50), 
        boundAt: Date.now(), 
        lastUsed: Date.now(), 
        useCount: 1,
        ip: getRealIP(req)
    };
    
    saveDatabase();
    return res.json({ success: true });
});

app.get('/api/stats', (req, res) => {
    const authHeader = req.headers['authorization'];
    if (!authHeader || authHeader !== `Bearer ${ADMIN_SECRET}`) {
        return res.status(403).json({ error: "Forbidden" });
    }
    res.json({ 
        totalKeys: Object.keys(keyDatabase).length, 
        uptime: process.uptime(),
        blockedIPs: Object.keys(blockedIPs).length
    });
});

app.use('*', (req, res) => {
    if (!isRobloxExecutor(req)) {
        return res.status(401).setHeader('Content-Type', 'text/html').send(NOT_AUTHORIZED_HTML);
    }
    res.status(404).json({ error: "Not found" });
});

app.use((err, req, res, next) => {
    console.error('[Error]', err.message);
    res.status(500).json({ error: "Internal server error" });
});

setInterval(() => {
    const now = Date.now();
    for (const ip in rateLimitStore) {
        if (rateLimitStore[ip].resetTime < now) delete rateLimitStore[ip];
    }
    for (const ip in blockedIPs) {
        if (blockedIPs[ip] < now) delete blockedIPs[ip];
    }
}, 10 * 60 * 1000);

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`🚀 Server running on port ${PORT}`);
    console.log(`🔐 Admin secret: ${ADMIN_SECRET.substring(0, 8)}...`);
});
