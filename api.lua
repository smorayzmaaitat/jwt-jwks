-- kong/plugins/jwt-jwks/api.lua

local cache_manager = require "kong.plugins.jwt-jwks.cache_manager"
local kong          = kong

return {
  ["/jwt-jwks/cache/info"] = {
    GET = function(self)
      kong.log.info("[jwt-jwks] Admin API: Fetching JWKS cache stats")
      local stats = cache_manager.get_cache_stats()
      return kong.response.exit(200, {
        message   = "JWKS cache info",
        stats     = stats,
        timestamp = os.date("%Y-%m-%d %H:%M:%S"),
      })
    end,
  },

  ["/jwt-jwks/cache/clear"] = {
    POST = function(self)
      kong.log.info("[jwt-jwks] Admin API: Clearing JWKS cache")
      local ok, err = pcall(cache_manager.clear_cache)
      if not ok then
        kong.log.err("[jwt-jwks] clear_cache error: ", err)
        return kong.response.exit(500, {
          message = "Failed to clear JWKS cache",
          error   = err,
        })
      end

      return kong.response.exit(200, {
        message   = "JWKS cache cleared successfully",
        timestamp = os.date("%Y-%m-%d %H:%M:%S"),
      })
    end,
  },

  ["/jwt-jwks/cache/clear/:key_id"] = {
    POST = function(self)
      local key_id = self.params.key_id
      if not key_id or key_id == "" then
        return kong.response.exit(400, {
          message = "Key ID is required",
        })
      end

      kong.log.info("[jwt-jwks] Admin API: Clearing cache for key ID: ", key_id)
      local ok, err = pcall(cache_manager.delete_key, key_id)
      if not ok then
        kong.log.err("[jwt-jwks] delete_key error: ", err)
        return kong.response.exit(500, {
          message = "Failed to clear cache for key ID: " .. key_id,
          error   = err,
        })
      end

      return kong.response.exit(200, {
        message   = "JWKS cache cleared for key ID: " .. key_id,
        timestamp = os.date("%Y-%m-%d %H:%M:%S"),
      })
    end,
  },
}
