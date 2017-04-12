-- database class

module(..., package.seeall)

local Collection = require("resty.mongo.collection")
local Cursor     = require("resty.mongo.cursor")
local protocol   = require("resty.mongo.protocol")
local NS         = protocol.NS
local t_ordered  = require("resty.mongo.orderedtable")
local util       = require("resty.mongo.util")

local database = {}
local database_mt = { __index = database }

-- -------------------------
-- attributes
-- -------------------------
database.name = nil
database.conn = nil

-- -------------------------
-- instance methods
-- -------------------------

function database:collection_names() end

function database:get_collection(name)
    return Collection.new(name,self)
end

--[[ todo

function database:get_gridfs(prefix)
end
--]]

function database:auth(username,password,ver)
    local ver = ver or "3.x"
    --2.x authenticate
    if ver == "2.x" then
        local ok = self:run_command({getnonce = true})
        if ok.ok ~= 1 and ok.ok ~= true then
            return 0,"err"
        end
        local digest = ngx.md5(ok.nonce..username..ngx.md5(username..":mongo:"..password))
        local cmd = t_ordered({"authenticate",true,"user",username,"nonce",ok.nonce,"key",digest})
        ok = self:run_command(cmd)
        if ok.ok == 1 or ok.ok == true then
            return 1
        end
        return ok.ok,ok.errmsg
    --3.x authenticate
    elseif ver == "3.x" then
        local user = string.gsub(string.gsub(username,'=','=3D'),',','=2C')
        local nonce = ngx.encode_base64(string.sub(tostring(math.random()),3,14))
        local first_bare = "n="..user..",r="..nonce
        local sasl_start_payload = ngx.encode_base64("n,,"..first_bare)
        local cmd = t_ordered({"saslStart",1,"mechanism","SCRAM-SHA-1","autoAuthorize",1,"payload",sasl_start_payload})
        local ok = self:run_command(cmd)
        if ok.ok ~= 1 and ok.ok ~= true then
            return 0,ok.errmsg
        end
        local conversation_id = ok.conversationId
        local server_first = ok.payload
        local parsed_s = ngx.decode_base64(server_first)
        local parsed_t = {}
        for k,v in string.gmatch(parsed_s,"(%w+)=([^,]*)") do
            parsed_t[k] = v
            --ngx.log(ngx.ERR,k.."->"..v)
        end

        local iterations = tonumber(parsed_t["i"])
        local salt = parsed_t["s"]
        local rnonce = parsed_t["r"]

        --error("iterations->"..iterations.." r->"..parsed_t["r"])
        if not string.sub(rnonce,1,12) == nonce then
            return nil,'Server returned an invalid nonce.'
        end
        local without_proof = "c=biws,r="..rnonce
        local pbkdf2_key = ngx.md5(username..":mongo:"..password)
        local salted_pass = util.pbkdf2_hmac_sha1(pbkdf2_key,iterations,ngx.decode_base64(salt),20)
        local client_key = ngx.hmac_sha1(salted_pass,"Client Key")
        local stored_key = ngx.sha1_bin(client_key)
        local auth_msg = first_bare..","..parsed_s..","..without_proof
        local client_sig = ngx.hmac_sha1(stored_key,auth_msg)
        local client_key_xor_sig = util.xor_bytestr(client_key,client_sig)
        local client_proof = "p="..ngx.encode_base64(client_key_xor_sig)
        local client_final = ngx.encode_base64(without_proof..","..client_proof)
        local server_key = ngx.hmac_sha1(salted_pass,"Server Key")
        local server_sig = ngx.encode_base64(ngx.hmac_sha1(server_key,auth_msg))

        cmd = t_ordered({"saslContinue",1,"conversationId",conversation_id,"payload",client_final})
        ok = self:run_command(cmd)
        if ok.ok ~= 1 and ok.ok ~= true then
            return 0,ok.errmsg
        end
        parsed_s = ngx.decode_base64(ok["payload"])
        parsed_t = {}
        for k,v in string.gmatch(parsed_s,"(%w+)=([^,]*)") do
            parsed_t[k] = v
        end
        if parsed_t['v'] ~= server_sig then
            return 0,"Server returned an invalid signature."
        end

        if not ok['done'] then
            cmd = t_ordered({"saslContinue",1,"conversationId",conversation_id,"payload",ngx.encode_base64("")})
            ok = self:run_command(cmd)
            if ok.ok ~= 1 and ok.ok ~= true then
                return 0,ok.errmsg
            end
            if not ok["done"] then 
                return 0,"SASL conversation failed to complete."
            end
            return 1
        end
        return 1
    end
    --error("auth error -> "..ok.errmsg)
end

function database:drop()
    return self:run_command({ dropDatabase = true })
end

function database:drop_collection( name )
    local ok =  self:run_command({ drop = name })
    return ok.ok == 1 or ok.ok == true
end

function database:get_last_error(options)
    options = options or {}
    local w = options.w or self.conn.w
    local wtimeout = options.wtimeout or self.conn.wtimeout
    local cmd = t_ordered({"getlasterror",true, "w",w,"wtimeout",wtimeout})
    if options.fsync then cmd.fsync = true end
    if options.j then cmd.j = true end
    return self:run_command(cmd)
end

function database:run_command(cmd)
    local cursor = Cursor.new(self, NS.SYSTEM_COMMAND_COLLECTION,cmd)
    local result = cursor:limit(-1):all()
    if not result[1] then
        -- raise error?
        -- return nil,cursor.last_error_msg
        return { ok = 0, errmsg = cursor.last_error_msg }
    end
    return result[1]
end

--[[ todo

function database:eval(code,args)
end
--]]

-----------------------------
-- consturctor
-----------------------------

local function new(name,conn)
    assert(name,"Database name not provide")
    assert(conn,"Connection is nil")
    local obj = { name = name, conn = conn }
    return setmetatable(obj, database_mt)
end

return {
    new = new,
}
