
local mongo = {}
function mongo:new_connection(option)
    module('resty.mongo',package.seeall)
    require("resty.mongo.support")
    local Connection = require('resty.mongo.connection')
    return Connection:new(option) 
end

return mongo

