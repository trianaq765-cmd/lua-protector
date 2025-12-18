--[[
    Ultimate Hub V9.3 - Loader & Key System
    OBFUSCATE FILE INI SEBELUM UPLOAD KE GITHUB!
]]

-- ============================================
-- ⚠️ GANTI URL INI SESUAI MILIKMU!
-- ============================================
local CFG = {
    -- URL Server Railway/Render kamu
    SERVER = "https://lua-protector-production.up.railway.app",
    
    -- URL GitHub Raw untuk core.lua (SETELAH DI-OBFUSCATE)
    CORE_URL = "https://raw.githubusercontent.com/trianaq765-cmd/ultimate-hub/main/core.lua",
    
    -- URL Get Key (Work.ink)
    GET_KEY = "https://work.ink/29pu/key-sistem-3",
    
    -- Settings
    SAVE_KEY = true,
    KEY_FILE = "UltimateHubKey.txt",
    USER_FILE = "UltimateHubUser.txt",
    MAX_ATTEMPTS = 5,
    COOLDOWN = 60,
    ONE_KEY_ONE_USER = true,
    VERSION = "9.3"
}

-- Anti-duplicate
if getgenv().UHLoaded then
    pcall(function() getgenv().UH:Destroy() end)
    pcall(function() game:GetService("CoreGui"):FindFirstChild("UltimateHubKeySystem"):Destroy() end)
    pcall(function() game:GetService("CoreGui"):FindFirstChild("Rayfield"):Destroy() end)
    getgenv().UH, getgenv().UHCore, getgenv().UHLoaded = nil, nil, nil
    task.wait(0.3)
end
getgenv().UHLoaded = true

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

-- File Functions
local function saveFile(name, content)
    if writefile then pcall(writefile, name, content) end
end

local function readFile(name)
    if isfile and readfile then
        local s, r = pcall(function()
            if isfile(name) then return readfile(name) end
            return nil
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

-- Get HWID
local function getHWID()
    local hwid
    local funcs = {
        function() return gethwid and gethwid() end,
        function() return getexecutorhwid and getexecutorhwid() end,
        function() return syn and syn.cache_hwid and syn.cache_hwid() end,
        function() return fluxus and fluxus.get_hwid and fluxus.get_hwid() end,
        function() return get_hwid and get_hwid() end,
        function() return HWID and HWID() end,
        function() return getexecutorname and getexecutorname() .. "_" .. LocalPlayer.UserId end
    }
    
    for _, f in ipairs(funcs) do
        local s, r = pcall(f)
        if s and r and r ~= "" then
            hwid = tostring(r)
            break
        end
    end
    
    if hwid then
        return hwid .. "_" .. LocalPlayer.UserId
    else
        return "NOHWID_" .. LocalPlayer.UserId .. "_" .. LocalPlayer.Name
    end
end

-- HTTP Request
local function doRequest(url, method, headers, body)
    headers = headers or {}
    headers["UH-Executor"] = "true"
    headers["UH-Version"] = CFG.VERSION
    
    local requestFunc = (syn and syn.request) or request or http_request or 
                        (fluxus and fluxus.request) or (delta and delta.request)
    
    if requestFunc then
        local s, r = pcall(function()
            return requestFunc({
                Url = url,
                Method = method or "GET",
                Headers = headers,
                Body = body
            })
        end)
        if s and r then return r end
    end
    
    if method == "GET" or not method then
        local s, r = pcall(function() return game:HttpGet(url) end)
        if s then return {Body = r, StatusCode = 200} end
    end
    
    return nil
end

-- Notification
local function notify(title, text, duration)
    pcall(function()
        StarterGui:SetCore("SendNotification", {
            Title = title or "Ultimate Hub",
            Text = text or "",
            Duration = duration or 5
        })
    end)
end

-- Open URL
local function openURL(url)
    if not url or url == "" then return false end
    local funcs = {"openurl", "OpenURL", "open_url", "browseurl", "BrowseURL", "browse_url"}
    for _, n in ipairs(funcs) do
        local f = getgenv()[n] or getfenv()[n] or _G[n]
        if f and type(f) == "function" and pcall(f, url) then return true end
    end
    pcall(function() if syn and syn.open_browser then syn.open_browser(url) end end)
    pcall(function() if fluxus and fluxus.open_browser then fluxus.open_browser(url) end end)
    return false
end

-- Key Cache
local keyCache = {}

-- ============================================
-- 🔑 VALIDATE KEY - PANGGIL SERVER API
-- ============================================
local function validateKey(key)
    if not key or key == "" then
        return false, "Please enter a key!"
    end
    
    key = key:gsub("^%s*(.-)%s*$", "%1")
    
    if #key < 5 then
        return false, "Key too short!"
    end
    
    -- Check cache (5 menit)
    if keyCache[key] and (os.time() - keyCache[key].time) < 300 then
        return keyCache[key].valid, keyCache[key].msg
    end
    
    local hwid = getHWID()
    
    -- ============================================
    -- 🚀 REQUEST KE SERVER /api/validate
    -- ============================================
    local success, result = pcall(function()
        local response = doRequest(CFG.SERVER .. "/api/validate", "POST", {
            ["Content-Type"] = "application/json"
        }, HttpService:JSONEncode({
            key = key,
            hwid = hwid,
            userId = LocalPlayer.UserId,
            userName = LocalPlayer.Name
        }))
        
        if response and response.Body then
            return HttpService:JSONDecode(response.Body)
        end
        return nil
    end)
    
    if success and result then
        if result.valid == true or result.success == true then
            -- Key bound to other user
            if result.bound_to_other then
                local boundName = result.bound_user or "Unknown"
                keyCache[key] = {valid = false, msg = "Key bound to: " .. boundName, time = os.time()}
                return false, "Key bound to: " .. boundName
            end
            
            -- Success
            local msg = result.message or "Key Valid!"
            if result.new_binding then 
                msg = "Key Registered!"
            elseif result.returning_user then 
                msg = "Welcome back!" 
            end
            
            keyCache[key] = {valid = true, msg = msg, time = os.time()}
            return true, msg
        else
            -- Invalid
            local errMsg = result.message or "Invalid key!"
            keyCache[key] = {valid = false, msg = errMsg, time = os.time()}
            return false, errMsg
        end
    end
    
    -- ============================================
    -- FALLBACK: Direct ke Work.ink jika server error
    -- ============================================
    local fallbackValid = false
    success, result = pcall(function()
        return HttpService:JSONDecode(game:HttpGet("https://work.ink/_api/v2/token/isValid/" .. key))
    end)
    
    if success and result and result.valid == true then
        fallbackValid = true
        
        -- Try to bind via server
        pcall(function()
            doRequest(CFG.SERVER .. "/api/bind", "POST", {
                ["Content-Type"] = "application/json"
            }, HttpService:JSONEncode({
                key = key,
                hwid = hwid,
                userId = LocalPlayer.UserId,
                userName = LocalPlayer.Name
            }))
        end)
    end
    
    if fallbackValid then
        keyCache[key] = {valid = true, msg = "Key Valid!", time = os.time()}
        return true, "Key Valid!"
    end
    
    keyCache[key] = {valid = false, msg = "Invalid key!", time = os.time()}
    return false, "Invalid key!"
end

-- ============================================
-- 🖼️ CREATE KEY SYSTEM UI
-- ============================================
local function createKeySystem()
    -- Cleanup
    pcall(function() if getgenv().UH then getgenv().UH:Destroy() end end)
    pcall(function()
        local k = CoreGui:FindFirstChild("UltimateHubKeySystem")
        if k then k:Destroy() end
    end)
    getgenv().UH = nil
    task.wait(0.1)
    
    -- Check saved key
    if CFG.SAVE_KEY then
        local savedKey = readFile(CFG.KEY_FILE)
        local savedUser = readFile(CFG.USER_FILE)
        local currentUser = getHWID()
        
        if savedKey and savedKey ~= "" then
            if CFG.ONE_KEY_ONE_USER and savedUser and savedUser ~= currentUser then
                deleteFile(CFG.KEY_FILE)
                deleteFile(CFG.USER_FILE)
                notify("Ultimate Hub", "Key reset: Different device", 3)
            else
                notify("Ultimate Hub", "Checking saved key...", 2)
                local valid = validateKey(savedKey)
                if valid then
                    saveFile(CFG.USER_FILE, currentUser)
                    notify("Ultimate Hub", "Key valid! Loading...", 2)
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
    ScreenGui.ZIndexBehavior = Enum.ZIndexBehavior.Sibling
    
    pcall(function() ScreenGui.Parent = CoreGui end)
    if not ScreenGui.Parent then
        pcall(function() ScreenGui.Parent = LocalPlayer:WaitForChild("PlayerGui") end)
    end
    
    -- Background
    local Background = Instance.new("Frame")
    Background.Size = UDim2.new(1, 0, 1, 0)
    Background.BackgroundColor3 = Color3.fromRGB(0, 0, 0)
    Background.BackgroundTransparency = 0.5
    Background.BorderSizePixel = 0
    Background.Parent = ScreenGui
    
    -- Main Frame
    local MainFrame = Instance.new("Frame")
    MainFrame.Size = UDim2.new(0, 360, 0, 220)
    MainFrame.BackgroundColor3 = Color3.fromRGB(25, 25, 35)
    MainFrame.BorderSizePixel = 0
    MainFrame.AnchorPoint = Vector2.new(0.5, 0.5)
    MainFrame.Position = UDim2.new(0.5, 0, 0.5, 0)
    MainFrame.Parent = ScreenGui
    
    Instance.new("UICorner", MainFrame).CornerRadius = UDim.new(0, 12)
    local MainStroke = Instance.new("UIStroke", MainFrame)
    MainStroke.Color = Color3.fromRGB(100, 100, 255)
    MainStroke.Thickness = 2
    
    -- Title Bar
    local TitleBar = Instance.new("Frame")
    TitleBar.Size = UDim2.new(1, 0, 0, 45)
    TitleBar.BackgroundColor3 = Color3.fromRGB(30, 30, 45)
    TitleBar.BorderSizePixel = 0
    TitleBar.Parent = MainFrame
    Instance.new("UICorner", TitleBar).CornerRadius = UDim.new(0, 12)
    
    local TitleFix = Instance.new("Frame")
    TitleFix.Size = UDim2.new(1, 0, 0, 15)
    TitleFix.Position = UDim2.new(0, 0, 1, -15)
    TitleFix.BackgroundColor3 = Color3.fromRGB(30, 30, 45)
    TitleFix.BorderSizePixel = 0
    TitleFix.Parent = TitleBar
    
    local TitleLabel = Instance.new("TextLabel")
    TitleLabel.Size = UDim2.new(1, -20, 0, 25)
    TitleLabel.Position = UDim2.new(0, 10, 0, 5)
    TitleLabel.BackgroundTransparency = 1
    TitleLabel.Text = "🔐 Ultimate Hub V" .. CFG.VERSION
    TitleLabel.TextColor3 = Color3.fromRGB(255, 255, 255)
    TitleLabel.TextSize = 18
    TitleLabel.Font = Enum.Font.GothamBold
    TitleLabel.TextXAlignment = Enum.TextXAlignment.Center
    TitleLabel.Parent = TitleBar
    
    local StatusLabel = Instance.new("TextLabel")
    StatusLabel.Size = UDim2.new(1, -20, 0, 15)
    StatusLabel.Position = UDim2.new(0, 10, 0, 28)
    StatusLabel.BackgroundTransparency = 1
    StatusLabel.Text = "🔒 Secure Server (Active)"
    StatusLabel.TextColor3 = Color3.fromRGB(100, 255, 100)
    StatusLabel.TextSize = 10
    StatusLabel.Font = Enum.Font.Gotham
    StatusLabel.TextXAlignment = Enum.TextXAlignment.Center
    StatusLabel.Parent = TitleBar
    
    -- User Info
    local UserInfo = Instance.new("TextLabel")
    UserInfo.Size = UDim2.new(1, 0, 0, 15)
    UserInfo.Position = UDim2.new(0, 0, 0, 50)
    UserInfo.BackgroundTransparency = 1
    UserInfo.Text = "👤 " .. LocalPlayer.Name .. " (ID: " .. LocalPlayer.UserId .. ")"
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
    InputStroke.Thickness = 1
    
    local KeyInput = Instance.new("TextBox")
    KeyInput.Size = UDim2.new(1, -16, 1, 0)
    KeyInput.Position = UDim2.new(0, 8, 0, 0)
    KeyInput.BackgroundTransparency = 1
    KeyInput.Text = ""
    KeyInput.PlaceholderText = "Paste your key here..."
    KeyInput.PlaceholderColor3 = Color3.fromRGB(100, 100, 100)
    KeyInput.TextColor3 = Color3.fromRGB(255, 255, 255)
    KeyInput.TextSize = 13
    KeyInput.Font = Enum.Font.Gotham
    KeyInput.ClearTextOnFocus = false
    KeyInput.Parent = InputContainer
    
    -- Status
    local StatusText = Instance.new("TextLabel")
    StatusText.Size = UDim2.new(1, -40, 0, 25)
    StatusText.Position = UDim2.new(0, 20, 0, 115)
    StatusText.BackgroundTransparency = 1
    StatusText.Text = ""
    StatusText.TextColor3 = Color3.fromRGB(255, 100, 100)
    StatusText.TextSize = 11
    StatusText.Font = Enum.Font.Gotham
    StatusText.TextXAlignment = Enum.TextXAlignment.Center
    StatusText.TextWrapped = true
    StatusText.Parent = MainFrame
    
    -- Submit Button
    local SubmitButton = Instance.new("TextButton")
    SubmitButton.Size = UDim2.new(0, 155, 0, 36)
    SubmitButton.Position = UDim2.new(0.5, -160, 0, 145)
    SubmitButton.BackgroundColor3 = Color3.fromRGB(80, 120, 255)
    SubmitButton.BorderSizePixel = 0
    SubmitButton.Text = "✓ Validate Key"
    SubmitButton.TextColor3 = Color3.fromRGB(255, 255, 255)
    SubmitButton.TextSize = 13
    SubmitButton.Font = Enum.Font.GothamBold
    SubmitButton.Parent = MainFrame
    Instance.new("UICorner", SubmitButton).CornerRadius = UDim.new(0, 8)
    
    -- Get Key Button
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
    
    -- Bottom
    local BottomContainer = Instance.new("Frame")
    BottomContainer.Size = UDim2.new(1, -20, 0, 20)
    BottomContainer.Position = UDim2.new(0, 10, 1, -25)
    BottomContainer.BackgroundTransparency = 1
    BottomContainer.Parent = MainFrame
    
    local AttemptsLabel = Instance.new("TextLabel")
    AttemptsLabel.Size = UDim2.new(0.5, 0, 1, 0)
    AttemptsLabel.BackgroundTransparency = 1
    AttemptsLabel.Text = "Attempts: 0/" .. CFG.MAX_ATTEMPTS
    AttemptsLabel.TextColor3 = Color3.fromRGB(100, 100, 100)
    AttemptsLabel.TextSize = 10
    AttemptsLabel.Font = Enum.Font.Gotham
    AttemptsLabel.TextXAlignment = Enum.TextXAlignment.Left
    AttemptsLabel.Parent = BottomContainer
    
    local CreditLabel = Instance.new("TextLabel")
    CreditLabel.Size = UDim2.new(0.5, 0, 1, 0)
    CreditLabel.Position = UDim2.new(0.5, 0, 0, 0)
    CreditLabel.BackgroundTransparency = 1
    CreditLabel.Text = "by ToingDC"
    CreditLabel.TextColor3 = Color3.fromRGB(70, 70, 80)
    CreditLabel.TextSize = 10
    CreditLabel.Font = Enum.Font.Gotham
    CreditLabel.TextXAlignment = Enum.TextXAlignment.Right
    CreditLabel.Parent = BottomContainer
    
    -- Animation
    MainFrame.Size = UDim2.new(0, 0, 0, 0)
    TweenService:Create(MainFrame, TweenInfo.new(0.35, Enum.EasingStyle.Back, Enum.EasingDirection.Out), {Size = UDim2.new(0, 360, 0, 220)}):Play()
    
    -- Logic
    local keyValid = false
    local validationComplete = Instance.new("BindableEvent")
    local isProcessing = false
    
    local function closeGUI()
        TweenService:Create(MainFrame, TweenInfo.new(0.25, Enum.EasingStyle.Back, Enum.EasingDirection.In), {Size = UDim2.new(0, 0, 0, 0)}):Play()
        TweenService:Create(Background, TweenInfo.new(0.25), {BackgroundTransparency = 1}):Play()
        task.wait(0.25)
        ScreenGui:Destroy()
    end
    
    local function submitKey()
        if isProcessing then return end
        isProcessing = true
        
        local inputKey = KeyInput.Text:gsub("^%s*(.-)%s*$", "%1")
        
        if inputKey == "" then
            StatusText.Text = "⚠️ Please enter a key!"
            StatusText.TextColor3 = Color3.fromRGB(255, 200, 100)
            isProcessing = false
            return
        end
        
        if attempts >= CFG.MAX_ATTEMPTS then
            local timeLeft = CFG.COOLDOWN - (os.time() - lastAttemptTime)
            if timeLeft > 0 then
                StatusText.Text = "⏳ Wait " .. timeLeft .. " seconds..."
                StatusText.TextColor3 = Color3.fromRGB(255, 100, 100)
                isProcessing = false
                return
            else
                attempts = 0
            end
        end
        
        StatusText.Text = "🔄 Connecting to server..."
        StatusText.TextColor3 = Color3.fromRGB(255, 255, 100)
        SubmitButton.Text = "..."
        SubmitButton.BackgroundColor3 = Color3.fromRGB(100, 100, 100)
        
        task.spawn(function()
            task.wait(0.3)
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
                
                task.wait(1.2)
                closeGUI()
                keyValid = true
                validationComplete:Fire()
            else
                attempts = attempts + 1
                lastAttemptTime = os.time()
                
                StatusText.Text = "❌ " .. message
                StatusText.TextColor3 = Color3.fromRGB(255, 100, 100)
                SubmitButton.Text = "✓ Validate Key"
                SubmitButton.BackgroundColor3 = Color3.fromRGB(80, 120, 255)
                AttemptsLabel.Text = "Attempts: " .. attempts .. "/" .. CFG.MAX_ATTEMPTS
                
                -- Shake
                local originalPos = InputContainer.Position
                for i = 1, 4 do
                    InputContainer.Position = originalPos + UDim2.new(0, i % 2 == 0 and 6 or -6, 0, 0)
                    task.wait(0.04)
                end
                InputContainer.Position = originalPos
                
                InputStroke.Color = Color3.fromRGB(255, 80, 80)
                task.wait(0.5)
                InputStroke.Color = Color3.fromRGB(60, 60, 80)
                
                isProcessing = false
            end
        end)
    end
    
    -- Events
    SubmitButton.MouseEnter:Connect(function()
        TweenService:Create(SubmitButton, TweenInfo.new(0.15), {BackgroundColor3 = Color3.fromRGB(100, 140, 255)}):Play()
    end)
    SubmitButton.MouseLeave:Connect(function()
        TweenService:Create(SubmitButton, TweenInfo.new(0.15), {BackgroundColor3 = Color3.fromRGB(80, 120, 255)}):Play()
    end)
    GetKeyButton.MouseEnter:Connect(function()
        TweenService:Create(GetKeyButton, TweenInfo.new(0.15), {BackgroundColor3 = Color3.fromRGB(108, 121, 255)}):Play()
    end)
    GetKeyButton.MouseLeave:Connect(function()
        TweenService:Create(GetKeyButton, TweenInfo.new(0.15), {BackgroundColor3 = Color3.fromRGB(88, 101, 242)}):Play()
    end)
    
    SubmitButton.MouseButton1Click:Connect(submitKey)
    KeyInput.FocusLost:Connect(function(enterPressed)
        if enterPressed then submitKey() end
    end)
    GetKeyButton.MouseButton1Click:Connect(function()
        if openURL(CFG.GET_KEY) then
            StatusText.Text = "🌐 Browser opened!"
            StatusText.TextColor3 = Color3.fromRGB(100, 255, 100)
        else
            setClipboard(CFG.GET_KEY)
            StatusText.Text = "📋 Link copied!"
            StatusText.TextColor3 = Color3.fromRGB(100, 200, 255)
        end
    end)
    
    validationComplete.Event:Wait()
    validationComplete:Destroy()
    return keyValid
end

-- ============================================
-- 🚀 LOAD CORE SCRIPT
-- ============================================
local function loadCore()
    notify("Ultimate Hub", "Loading core script...", 2)
    
    local success, err = pcall(function()
        loadstring(game:HttpGet(CFG.CORE_URL))()
    end)
    
    if not success then
        notify("Ultimate Hub", "Failed to load: " .. tostring(err), 5)
        return false
    end
    
    return true
end

-- Main
if createKeySystem() then
    loadCore()
end
