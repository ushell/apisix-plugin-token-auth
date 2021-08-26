local core = require("apisix.core")
local consumer_mod = require("apisix.consumer")
local ngx = ngx
local ngx_time = ngx.time
local ipairs = ipairs
local plugin_name = "token-auth"

local lrucache = core.lrucache.new({
    type = "plugin",
})

local schema = {
    type = "object",
    properties = {
        header = {
            type = "string",
            default = "Authorization",
        }
    },
}

local consumer_schema = {
    type = "object",
    properties = {
        key = { type = "string" },
        exp = { type = "number" },
        uid = { type = "string" },
        -- 应用账户类型
        t = {
            type = "string",
            enum = { "app", "user" },
            default = "user",
        },
        header_prefix = {
            type = "string",
            default = "X-GW-Auth-",
        },
    },
    required = { "key", "exp", "uid" },
}

local _M = {
    version = 0.1,
    priority = 2501,
    type = 'auth',
    name = plugin_name,
    schema = schema,
    consumer_schema = consumer_schema,
}

local create_consume_cache
do
    local consumer_names = {}

    function create_consume_cache(consumers)
        core.table.clear(consumer_names)

        for _, consumer in ipairs(consumers.nodes) do
            core.log.info("consumer node: ", core.json.delay_encode(consumer))
            consumer_names[consumer.auth_conf.key] = consumer
        end

        return consumer_names
    end

end

function _M.check_schema(conf, schema_type)
    if schema_type == core.schema.TYPE_CONSUMER then
        return core.schema.check(consumer_schema, conf)
    else
        return core.schema.check(schema, conf)
    end
end

function _M.rewrite(conf, ctx)
    local key = core.request.header(ctx, conf.header)

    if not key then
        return 200, { code = "50000", message = "Missing API Token found in request" }
    end

    -- load consumer
    local consumer_conf = consumer_mod.plugin(plugin_name)
    if not consumer_conf then
        return 200, { code = "50001", message = "Missing Token consumer" }
    end

    local consumers = lrucache("consumers_key", consumer_conf.conf_version, create_consume_cache, consumer_conf)

    -- check token
    local consumer = consumers[key]
    if not consumer then
        return 200, { code = "50002", message = "Invalid API Token" }
    end

    -- check expire
    if consumer.auth_conf.exp < ngx_time() then
        return 200, { code = "50003", message = "API Token expire" }
    end

    core.log.info("consumer: ", core.json.delay_encode(consumer))

    -- set custom header
    local header_prefix = consumer.auth_conf.header_prefix or ''
    core.request.set_header(ctx, header_prefix .. "UserId", consumer.auth_conf.uid)
    core.request.set_header(ctx, header_prefix .. "Type", consumer.auth_conf.t)

    consumer_mod.attach_consumer(ctx, consumer, consumer_conf)
    core.log.info("hit token-auth rewrite")
end

return _M

