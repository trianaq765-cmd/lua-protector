--[[
    Ultimate Hub V9.3 - Loader
    Dengan Soft-Block System (Tidak Kick/Full Block)
    - Notifikasi saja tanpa menutupi game
    - Auto-destroy script saat admin join
]]

-- ============================================
-- CLEANUP PREVIOUS INSTANCE
-- ============================================
if getgenv().UHLoaded then
    pcall(function() 
        getgenv().UHAdminMonitorActive = false
    end)
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

getgenv().UHLoaded = true
getgenv().UHConnections = {}
getgenv().UHAdminMonitorActive = true

-- ============================================
-- ⚠️ KONFIGURASI
-- ============================================
local CFG = {
    SERVER = "https://lua-protector-production.up.railway.app",
    GET_KEY = "https://work.ink/29pu/key-sistem-3",
    SAVE_KEY = true,
    KEY_FILE = "UltimateHubKey.txt",
    USER_FILE = "UltimateHubUser.txt",
    MAX_ATTEMPTS = 5,
    COOLDOWN = 60,
    VERSION = "9.3",
    
    -- ⭐ ADMIN PROTECTION CONFIG
    ADMIN_USERIDS = {
        9611823874,  -- ToingDC (Admin 1)
        9282599330,  -- Admin 2
    },
    ADMIN_NAMES = {
        [9611823874] = "ToingDC",
        [9282599330] = "Admin2",
    },
    ADMIN_PROTECTION = true,
    BACKUP_CHECK_INTERVAL = 90,
}

-- Services
local HttpService = game:GetService("HttpService")
local TweenService = game:GetService("TweenService")
local Players = game:GetService("Players")
local CoreGui = game:GetService("CoreGui")
local StarterGui = game:GetService("StarterGui")
local LocalPlayer = Players.LocalPlayer

-- Variables
local attempts = 0
local lastAttemptTime = 0
local isAdmin = false
local scriptDestroyed = false

-- ============================================
-- 🛡️ ADMIN DETECTION FUNCTIONS
-- ============================================

local function checkIfAdmin()
    for _, adminId in ipairs(CFG.ADMIN_USERIDS) do
        if LocalPlayer.UserId == adminId then
            return true
        end
    end
    return false
end

local function isPlayerAdmin(player)
    if not player then return false end
    for _, adminId in ipairs(CFG.ADMIN_USERIDS) do
        if player.UserId == adminId then
            return true
        end
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

-- ============================================
-- 📢 NOTIFICATION SYSTEM (Non-Blocking)
-- ============================================

-- Notifikasi kecil di pojok (tidak menutupi game)
local function showSmallNotice(title, message, duration, color)
    color = color or Color3.fromRGB(255, 100, 100)
    duration = duration or 5
    
    pcall(function()
        StarterGui:SetCore("SendNotification", {
            Title = title or "Ultimate Hub",
            Text = message or "",
            Duration = duration,
        })
    end)
end

-- Notice panel kecil di atas (tidak full screen, bisa main game)
local function showTopNotice(adminName, isDestroy)
    -- Hapus notice lama jika ada
    pcall(function() CoreGui:FindFirstChild("UltimateHubNotice"):Destroy() end)
    
    local NoticeGui = Instance.new("ScreenGui")
    NoticeGui.Name = "UltimateHubNotice"
    NoticeGui.ResetOnSpawn = false
    NoticeGui.DisplayOrder = 999
    
    pcall(function() NoticeGui.Parent = CoreGui end)
    if not NoticeGui.Parent then
        pcall(function() NoticeGui.Parent = LocalPlayer:WaitForChild("PlayerGui") end)
    end
    
    -- Panel kecil di atas tengah (tidak menutupi game)
    local NoticeFrame = Instance.new("Frame")
    NoticeFrame.Name = "NoticeFrame"
    NoticeFrame.Size = UDim2.new(0, 320, 0, 70)
    NoticeFrame.Position = UDim2.new(0.5, -160, 0, -80) -- Mulai dari atas (hidden)
    NoticeFrame.BackgroundColor3 = Color3.fromRGB(30, 25, 25)
    NoticeFrame.BorderSizePixel = 0
    NoticeFrame.Parent = NoticeGui
    
    local Corner = Instance.new("UICorner", NoticeFrame)
    Corner.CornerRadius = UDim.new(0, 10)
    
    local Stroke = Instance.new("UIStroke", NoticeFrame)
    Stroke.Color = isDestroy and Color3.fromRGB(255, 80, 80) or Color3.fromRGB(255, 150, 50)
    Stroke.Thickness = 2
    
    -- Icon
    local Icon = Instance.new("TextLabel")
    Icon.Name = "Icon"
    Icon.Size = UDim2.new(0, 40, 0, 40)
    Icon.Position = UDim2.new(0, 10, 0.5, -20)
    Icon.BackgroundTransparency = 1
    Icon.Text = isDestroy and "💥" or "⚠️"
    Icon.TextSize = 28
    Icon.Parent = NoticeFrame
    
    -- Title
    local Title = Instance.new("TextLabel")
    Title.Name = "Title"
    Title.Size = UDim2.new(1, -60, 0, 22)
    Title.Position = UDim2.new(0, 55, 0, 10)
    Title.BackgroundTransparency = 1
    Title.Text = isDestroy and "Script Dihancurkan!" or "Script Tidak Tersedia"
    Title.TextColor3 = isDestroy and Color3.fromRGB(255, 100, 100) or Color3.fromRGB(255, 180, 80)
    Title.TextSize = 14
    Title.Font = Enum.Font.GothamBold
    Title.TextXAlignment = Enum.TextXAlignment.Left
    Title.Parent = NoticeFrame
    
    -- Message
    local Message = Instance.new("TextLabel")
    Message.Name = "Message"
    Message.Size = UDim2.new(1, -60, 0, 20)
    Message.Position = UDim2.new(0, 55, 0, 32)
    Message.BackgroundTransparency = 1
    Message.Text = "👑 Ada " .. (adminName or "Admin") .. " disini"
    Message.TextColor3 = Color3.fromRGB(180, 180, 180)
    Message.TextSize = 12
    Message.Font = Enum.Font.Gotham
    Message.TextXAlignment = Enum.TextXAlignment.Left
    Message.Parent = NoticeFrame
    
    -- Sub message
    local SubMessage = Instance.new("TextLabel")
    SubMessage.Name = "SubMessage"
    SubMessage.Size = UDim2.new(1, -60, 0, 15)
    SubMessage.Position = UDim2.new(0, 55, 0, 50)
    SubMessage.BackgroundTransparency = 1
    SubMessage.Text = isDestroy and "Coba lagi di server lain" or "Script dinonaktifkan"
    SubMessage.TextColor3 = Color3.fromRGB(100, 100, 100)
    SubMessage.TextSize = 10
    SubMessage.Font = Enum.Font.Gotham
    SubMessage.TextXAlignment = Enum.TextXAlignment.Left
    SubMessage.Parent = NoticeFrame
    
    -- Slide in animation
    TweenService:Create(NoticeFrame, TweenInfo.new(0.4, Enum.EasingStyle.Back, Enum.EasingDirection.Out), {
        Position = UDim2.new(0.5, -160, 0, 15)
    }):Play()
    
    -- Auto hide setelah 8 detik
    task.spawn(function()
        task.wait(8)
        if NoticeFrame and NoticeFrame.Parent then
            TweenService:Create(NoticeFrame, TweenInfo.new(0.3, Enum.EasingStyle.Quad, Enum.EasingDirection.In), {
                Position = UDim2.new(0.5, -160, 0, -80)
            }):Play()
            task.wait(0.3)
            if NoticeGui and NoticeGui.Parent then
                NoticeGui:Destroy()
            end
        end
    end)
    
    return NoticeGui
end

-- ============================================
-- 🔥 DESTROY SCRIPT FUNCTION (Soft Destroy)
-- ============================================
local function destroyScript(adminName, adminId)
    if scriptDestroyed then return end
    scriptDestroyed = true
    
    -- Stop monitor
    getgenv().UHAdminMonitorActive = false
    
    -- Tampilkan notifikasi kecil dulu
    showSmallNotice("💥 Script Terminated", "Admin " .. (adminName or "Unknown") .. " bergabung!", 5)
    
    -- Tampilkan notice panel kecil di atas
    showTopNotice(adminName, true)
    
    -- Disconnect semua connections
    if getgenv().UHConnections then
        for i, conn in pairs(getgenv().UHConnections) do
            pcall(function() 
                if conn and conn.Connected then
                    conn:Disconnect() 
                end
            end)
            getgenv().UHConnections[i] = nil
        end
    end
    
    -- Destroy main hub GUI
    pcall(function() 
        if getgenv().UH then 
            getgenv().UH:Destroy() 
        end
    end)
    
    -- Destroy Rayfield
    pcall(function()
        if getgenv().Rayfield then
            getgenv().Rayfield:Destroy()
        end
    end)
    
    -- Clear global variables
    getgenv().UH = nil
    getgenv().UHCore = nil
    
    -- Destroy GUI terkait (KECUALI Notice)
    pcall(function()
        for _, gui in ipairs(CoreGui:GetChildren()) do
            if gui:IsA("ScreenGui") then
                local name = gui.Name:lower()
                if (name:find("ultimate") or name:find("rayfield") or name:find("hub")) 
                   and not name:find("notice") then
                    gui:Destroy()
                end
            end
        end
    end)
    
    pcall(function()
        if LocalPlayer:FindFirstChild("PlayerGui") then
            for _, gui in ipairs(LocalPlayer.PlayerGui:GetChildren()) do
                if gui:IsA("ScreenGui") then
                    local name = gui.Name:lower()
                    if (name:find("ultimate") or name:find("rayfield") or name:find("hub"))
                       and not name:find("notice") then
                        gui:Destroy()
                    end
                end
            end
        end
    end)
    
    print("[Ultimate Hub] Script destroyed - Admin detected: " .. (adminName or "Unknown") .. " (" .. (adminId or "?") .. ")")
end

-- ============================================
-- 👁️ ADMIN MONITOR (Event + Backup Polling)
-- ============================================
local function startAdminMonitor()
    if isAdmin then return end
    if scriptDestroyed then return end
    
    -- ========================================
    -- 1️⃣ EVENT-BASED: PlayerAdded (Instant)
    -- ========================================
    local playerAddedConn = Players.PlayerAdded:Connect(function(player)
        if scriptDestroyed then return end
        if not getgenv().UHAdminMonitorActive then return end
        
        task.defer(function()
            task.wait(0.5) -- Delay kecil untuk memastikan data player loaded
            
            if isPlayerAdmin(player) then
                local adminName = getAdminName(player.UserId)
                destroyScript(adminName, player.UserId)
            end
        end)
    end)
    table.insert(getgenv().UHConnections, playerAddedConn)
    
    -- ========================================
    -- 2️⃣ BACKUP POLLING: Setiap 90 detik
    -- ========================================
    task.spawn(function()
        while true do
            task.wait(CFG.BACKUP_CHECK_INTERVAL)
            
            if scriptDestroyed then break end
            if not getgenv().UHAdminMonitorActive then break end
            if not getgenv().UHLoaded then break end
            
            local hasAdmin, playerName, adminId = checkAdminInServer()
            
            if hasAdmin then
                local adminName = getAdminName(adminId)
                destroyScript(adminName, adminId)
                break
            end
        end
    end)
end

-- ============================================
-- 🚀 INIT ADMIN PROTECTION
-- ============================================
local function initAdminProtection()
    if not CFG.ADMIN_PROTECTION then 
        return true, nil
    end
    
    isAdmin = checkIfAdmin()
    
    if isAdmin then
        -- Anda adalah admin
        showSmallNotice("👑 Admin Mode", "Logged in sebagai Owner", 3)
        
        -- Info player di server
        task.spawn(function()
            task.wait(2)
            local count = 0
            local names = {}
            for _, player in ipairs(Players:GetPlayers()) do
                if player ~= LocalPlayer then
                    count = count + 1
                    table.insert(names, player.Name)
                end
            end
            if count > 0 then
                showSmallNotice("👁️ Server Info", count .. " player: " .. table.concat(names, ", "):sub(1, 50), 4)
            end
        end)
        
        return true, nil
    end
    
    -- Bukan admin, cek apakah ada admin di server
    local hasAdmin, playerName, adminId = checkAdminInServer()
    
    if hasAdmin then
        local adminName = getAdminName(adminId)
        
        -- Tampilkan notice kecil (tidak full block)
        showTopNotice(adminName, false)
        showSmallNotice("⚠️ Script Disabled", "Ada " .. adminName .. " di server ini", 5)
        
        scriptDestroyed = true
        return false, adminName
    end
    
    -- Tidak ada admin, start monitoring
    startAdminMonitor()
    
    return true, nil
end

-- ============================================
-- UTILITY FUNCTIONS
-- ============================================
local function saveFile(name, content)
    if writefile then pcall(writefile, name, content) end
end

local function readFile(name)
    if isfile and readfile then
        local s, r = pcall(function()
            if isfile(name) then return readfile(name) end
        end)
        if s then return r end
    end
    return nil
end

local function deleteFile(name)
    if isfile and delfile then
        pcall(function() if isfile(name) then delfile(name) end end)
    end
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
    
    local requestFunc = (syn and syn.request) or request or http_request or 
                        (fluxus and fluxus.request)
    
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

local function notify(title, text, duration)
    pcall(function()
        StarterGui:SetCore("SendNotification", {
            Title = title or "Ultimate Hub", 
            Text = text or "", 
            Duration = duration or 5
        })
    end)
end

local function openURL(url)
    if not url then return false end
    for _, n in ipairs({"openurl", "OpenURL", "open_url"}) do
        local f = getgenv()[n] or _G[n]
        if f and type(f) == "function" and pcall(f, url) then return true end
    end
    return false
end

-- ============================================
-- KEY VALIDATION
-- ============================================
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
            local msg = result.message or "Key Valid!"
            keyCache[key] = {valid = true, msg = msg, time = os.time()}
            return true, msg
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

-- ============================================
-- KEY SYSTEM UI
-- ============================================
local function createKeySystem()
    if scriptDestroyed then return false end
    
    pcall(function() CoreGui:FindFirstChild("UltimateHubKeySystem"):Destroy() end)
    task.wait(0.1)
    
    -- Check saved key
    if CFG.SAVE_KEY then
        local savedKey = readFile(CFG.KEY_FILE)
        local savedUser = readFile(CFG.USER_FILE)
        local currentUser = getHWID()
        
        if savedKey and savedKey ~= "" then
            if savedUser and savedUser ~= currentUser then
                deleteFile(CFG.KEY_FILE)
                deleteFile(CFG.USER_FILE)
            else
                notify("Ultimate Hub", "Checking saved key...", 2)
                if validateKey(savedKey) then
                    saveFile(CFG.USER_FILE, currentUser)
                    notify("Ultimate Hub", "Key valid!", 2)
                    return true
                end
                deleteFile(CFG.KEY_FILE)
                deleteFile(CFG.USER_FILE)
            end
        end
    end
    
    -- Create GUI
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
    
    -- Title
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
    
    -- Input
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
    
    -- Buttons
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
    
    -- Animation
    MainFrame.Size = UDim2.new(0, 0, 0, 0)
    TweenService:Create(MainFrame, TweenInfo.new(0.35, Enum.EasingStyle.Back), {
        Size = UDim2.new(0, 360, 0, 220)
    }):Play()
    
    -- Logic
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
        if isProcessing then return end
        if scriptDestroyed then 
            closeGUI()
            return 
        end
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
            
            if scriptDestroyed then
                closeGUI()
                isProcessing = false
                return
            end
            
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
    local enterConn = KeyInput.FocusLost:Connect(function(enter) 
        if enter then submitKey() end 
    end)
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

-- ============================================
-- LOAD CORE
-- ============================================
local function loadCore()
    if scriptDestroyed then return false end
    
    notify("Ultimate Hub", "Loading...", 2)
    local success, err = pcall(function()
        loadstring(game:HttpGet(CFG.SERVER .. "/core"))()
    end)
    if not success then
        notify("Error", tostring(err), 5)
        return false
    end
    return true
end

-- ============================================
-- 🚀 MAIN EXECUTION
-- ============================================

-- Step 1: Admin Protection Check
local canContinue, adminName = initAdminProtection()

if not canContinue then
    -- Ada admin di server, script disabled tapi player bisa tetap main
    print("[Ultimate Hub] Script disabled - Admin in server: " .. (adminName or "Unknown"))
    return
end

-- Step 2: Key System
if createKeySystem() then
    -- Step 3: Load Core
    loadCore()
end
