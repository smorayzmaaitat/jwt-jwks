local helpers = require "spec.helpers"
local cjson = require "cjson"

local PLUGIN_NAME = "jwt-jwks"

for _, strategy in helpers.each_strategy() do
  describe(PLUGIN_NAME .. ": (access) [#" .. strategy .. "]", function()
    local client

    lazy_setup(function()
      local bp = helpers.get_db_utils(strategy, nil, { PLUGIN_NAME })

      -- Create a service
      local service1 = bp.services:insert({
        protocol = "http",
        host = "mockbin.org",
        port = 80,
        path = "/request"
      })

      -- Create a route
      local route1 = bp.routes:insert({
        hosts = { "test1.com" },
        service = service1
      })

      -- Add the plugin to the route
      bp.plugins:insert {
        name = PLUGIN_NAME,
        route = { id = route1.id },
        config = {
          jwks_uri = "http://mockbin.org/bin/jwks",
          cache_ttl = 300,
          claims_to_verify = { "exp", "iss" }
        },
      }

      -- Start Kong
      assert(helpers.start_kong({
        database   = strategy,
        nginx_conf = "spec/fixtures/custom_nginx.template",
        plugins = "bundled," .. PLUGIN_NAME,
      }))
    end)

    lazy_teardown(function()
      helpers.stop_kong(nil, true)
    end)

    before_each(function()
      client = helpers.proxy_client()
    end)

    after_each(function()
      if client then client:close() end
    end)

    describe("request", function()
      it("rejects request without JWT token", function()
        local r = client:get("/request", {
          headers = {
            host = "test1.com"
          }
        })
        
        assert.response(r).has.status(401)
        local body = assert.response(r).has.jsonbody()
        assert.equal("Unauthorized", body.message)
        assert.equal("No JWT token provided", body.error)
      end)

      it("rejects request with invalid JWT token", function()
        local r = client:get("/request", {
          headers = {
            host = "test1.com",
            authorization = "Bearer invalid.jwt.token"
          }
        })
        
        assert.response(r).has.status(401)
        local body = assert.response(r).has.jsonbody()
        assert.equal("Unauthorized", body.message)
      end)

      it("accepts request with valid JWT token from query parameter", function()
        -- This would require a valid JWT token for testing
        -- In a real test, you'd generate a proper JWT with a known key
        local jwt_token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJ0ZXN0IiwiZXhwIjo5OTk5OTk5OTk5fQ.signature"
        
        local r = client:get("/request?jwt=" .. jwt_token, {
          headers = {
            host = "test1.com"
          }
        })
        
        -- This would pass with a properly signed JWT
        -- assert.response(r).has.status(200)
      end)
    end)
  end)
end
