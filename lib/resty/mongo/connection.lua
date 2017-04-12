-- connection class

module(...,package.seeall)

-- import

local util = require("resty.mongo.util")
local tcp = util.socket.tcp
local split  = util.split
--local bson = require("resty.mongo.bson")
local substr = string.sub
local Database = require("resty.mongo.database")



-- class body

local connection = {}
local connection_mt = { __index = connection }

-- -------------------------
-- attributes
-- -------------------------
connection.host = "127.0.0.1"
connection.port = 27017
connection.w = 1
connection.wtimeout = 1000
connection.auto_connect = true
connection.user_name = nil
connection.password = nil
connection.db_name = 'base'
connection.query_timeout = 1000
connection.max_bson_size = 4*1024*1024
connection.find_master = false;
connection.sock = nil
connection.connected = false

-- dynmatic find master
connection.hosts = {}
connection.arbiters = {}
connection.passives = {}

-- -------------------------
-- instance methods
-- -------------------------

function connection:connect(...)
    local host,port = ...
    host = host or self.host
    port = port or self.port
    local sock = self.sock
    assert(sock:connect(host,port),"connect failed")
    self.connected = true
end

function connection:database_names()
    local r = self:get_database("admin"):run_command({ listDatabases = true })
    if r.ok == 1 then
        return r.databases
    end
    error("failed to get database names:"..r.errmsg)
end

--[[ todo

function connection:get_master()
end
--]]


function connection:get_database(name)
    --return Database.new(name,self)
    local db = Database.new(name,self)

    --error("username->"..self.user_name.." password->"..self.password)
    if self.user_name ~= nil and self.password ~= nil then
        if db:auth(self.user_name,self.password) then
            return db
        end
        error("auth failed.")
    end
    return db
end

function connection:get_max_bson_size()
    local buildinfo =  self:get_database("admin"):run_command({buildinfo = true})
    if buildinfo then
        return buildinfo.maxBsonObjectSize or 4194304
    end
    return 4194304
end

function connection:init(host,port)
    self.sock = tcp()
    if self.auto_connect then
        self:connect(host,port)
    end
end
-----------------------------
-- consturctor
-----------------------------
function connection:new(option)
    option = option or {}
    local host = option.host or self.host
    local port = option.port or self.port

    self.user_name = option.user_name or nil
    self.password = option.password or nil

    local obj = setmetatable(option, connection_mt)
    obj:init(host,port)
    return obj;
end

return connection
