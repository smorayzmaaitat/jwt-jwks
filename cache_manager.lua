local kong = kong
local ngx = ngx
local type = type
local pairs = pairs
local tonumber = tonumber
local os_time = os.time
local cjson = require "cjson.safe"

local _M = {}

-- Use Kong's shared dictionary for caching
local CACHE_NAME = "jwt_jwks_cache"
local cache = ngx.shared[CACHE_NAME]

-- If shared dict doesn't exist, create a fallback table
if not cache then
  kong.log.warn("Shared dictionary 'jwt_jwks_cache' not found, using fallback cache")
  cache = {}
  cache.get = function(self, key) return self[key] end
  cache.set = function(self, key, value, ttl) self[key] = value end
  cache.delete = function(self, key) self[key] = nil end
end

local function get_cache_key(key_id)
  return "jwks_key:" .. key_id
end

local function get_metadata_key(key_id)
  return "jwks_meta:" .. key_id
end

function _M.get_key(key_id)
  local cache_key = get_cache_key(key_id)
  local meta_key = get_metadata_key(key_id)
  
  local key_data = cache:get(cache_key)
  local metadata_str = cache:get(meta_key)
  
  if not key_data or not metadata_str then
    return nil
  end
  
  -- Deserialize metadata
  local metadata, meta_err = cjson.decode(metadata_str)
  if not metadata then
    kong.log.err("Failed to decode metadata: ", meta_err)
    return nil
  end
  
  -- Check if key has expired
  local current_time = os_time()
  if metadata.expires_at and current_time > metadata.expires_at then
    kong.log.debug("Cached key expired for ID: ", key_id)
    cache:delete(cache_key)
    cache:delete(meta_key)
    return nil
  end
  
  -- Deserialize key_data if it's a JSON string
  if type(key_data) == "string" and key_data:sub(1,1) == "{" then
    local decoded, decode_err = cjson.decode(key_data)
    if decoded then
      key_data = decoded
    else
      kong.log.err("Failed to decode cached key data: ", decode_err)
    end
  end
  
  kong.log.debug("Retrieved cached key for ID: ", key_id)
  return key_data
end

function _M.set_key(key_id, key_data, ttl)
  local cache_key = get_cache_key(key_id)
  local meta_key = get_metadata_key(key_id)
  
  local current_time = os_time()
  local metadata = {
    cached_at = current_time,
    expires_at = current_time + (ttl or 3600),
    ttl = ttl or 3600
  }
  
  -- Serialize key_data if it's a table
  local serialized_key_data = key_data
  if type(key_data) == "table" then
    serialized_key_data = cjson.encode(key_data)
  end
  
  -- Store key data and metadata
  local ok1, err1 = cache:set(cache_key, serialized_key_data, ttl)
  local ok2, err2 = cache:set(meta_key, cjson.encode(metadata), ttl)
  
  if not ok1 then
    kong.log.err("Failed to cache key data: ", err1)
    return false
  end
  
  if not ok2 then
    kong.log.err("Failed to cache key metadata: ", err2)
    return false
  end
  
  kong.log.debug("Cached key for ID: ", key_id, " with TTL: ", ttl)
  return true
end

function _M.delete_key(key_id)
  local cache_key = get_cache_key(key_id)
  local meta_key = get_metadata_key(key_id)
  
  cache:delete(cache_key)
  cache:delete(meta_key)
  
  kong.log.debug("Deleted cached key for ID: ", key_id)
end

function _M.clear_cache()
  if cache.flush_all then
    cache:flush_all()
    kong.log.info("Cleared all cached JWKS keys")
  else
    kong.log.warn("Cache flush not supported, manual cleanup required")
  end
end

function _M.get_cache_stats()
  local stats = {
    cache_type = cache.flush_all and "shared_dict" or "fallback",
    keys_count = 0
  }
  
  if cache.get_keys then
    local keys = cache:get_keys()
    for _, key in pairs(keys) do
      if key:match("^jwks_key:") then
        stats.keys_count = stats.keys_count + 1
      end
    end
  end
  
  return stats
end

function _M.get_all_keys()
  local all_keys = {}
  if not cache.get_keys then
    kong.log.warn("cache:get_keys() not available, cannot fetch all keys from cache. This is expected with the fallback cache.")
    return nil
  end

  local keys, err = cache:get_keys()
  if not keys then
    kong.log.err("Failed to get keys from cache: ", err)
    return nil
  end

  for _, key in ipairs(keys) do
    if key:match("^jwks_key:") then
      local key_id = key:gsub("^jwks_key:", "")
      local key_data = _M.get_key(key_id) -- Use existing get_key to handle expiry and deserialization
      if key_data then
        all_keys[key_id] = key_data
      end
    end
  end

  return all_keys
end

return _M
