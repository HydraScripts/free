--[[
    Whitelist loader (Luarmor-style).

    Distribute this small snippet to users. It computes a hardware ID,
    sends it along with the user's key to your whitelist service, and
    runs the protected script only if the key is valid and the HWID matches.

    Usage in an executor:
        _G.Key = "XXXX-XXXX-XXXX-XXXX"
        loadstring(game:HttpGet("https://your-domain.com/loader/myproject"))()

    Replace ENDPOINT and PROJECT below (or serve this file per-project
    from your own backend with the values already filled in).
]]

local ENDPOINT = "http://localhost:3000/api/v1/auth"
local PROJECT  = "myproject"

-- Resolve an HTTP request function across common executors.
local request = (syn and syn.request)
    or (http and http.request)
    or http_request
    or request

-- Compute a stable per-machine hardware ID.
-- RbxAnalyticsService:GetClientId() is available on every executor and is
-- stable per install; gethwid() is used as a fallback where exposed.
local function getHWID()
    local ok, id = pcall(function()
        return game:GetService("RbxAnalyticsService"):GetClientId()
    end)
    if ok and id and id ~= "" then return id end
    if gethwid then
        local ok2, id2 = pcall(gethwid)
        if ok2 and id2 and id2 ~= "" then return id2 end
    end
    return "unknown-hwid"
end

local function httpJson(url, bodyTable)
    local body = game:GetService("HttpService"):JSONEncode(bodyTable)
    if request then
        local res = request({
            Url = url,
            Method = "POST",
            Headers = { ["Content-Type"] = "application/json" },
            Body = body,
        })
        return res.StatusCode, res.Body
    end
    -- Fallback: GET-only executors can't POST; surface a clear error.
    error("This executor does not support HTTP POST (needed for key auth).")
end

local key = _G.Key or (getgenv and getgenv().Key)
if not key or key == "" then
    warn("[whitelist] No key set. Set _G.Key = \"YOUR-KEY\" before loading.")
    return
end

local status, raw = httpJson(ENDPOINT, {
    key = key,
    hwid = getHWID(),
    project = PROJECT,
})

local ok, data = pcall(function()
    return game:GetService("HttpService"):JSONDecode(raw)
end)

if not ok or type(data) ~= "table" then
    warn("[whitelist] Unexpected response from server.")
    return
end

if status ~= 200 or not data.ok then
    warn("[whitelist] Authentication failed: " .. tostring(data and data.error or status))
    return
end

-- Success: run the protected script returned by the server.
local fn, err = loadstring(data.script)
if not fn then
    warn("[whitelist] Failed to compile protected script: " .. tostring(err))
    return
end
return fn()
