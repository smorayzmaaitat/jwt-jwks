local http = require "resty.http"
local cjson = require "cjson.safe"
local cache_manager = require "kong.plugins.jwt-jwks.cache_manager"
-- Remove these dependencies
-- local rsa = require "resty.rsa"
-- local evp = require "resty.evp"

local kong = kong
local ngx = ngx
local type = type
local pairs = pairs
local ipairs = ipairs
local tostring = tostring
local tonumber = tonumber

local _M = {}

local function base64_url_decode(str)
  local remainder = #str % 4
  if remainder > 0 then
    str = str .. string.rep('=', 4 - remainder)
  end
  str = str:gsub('-', '+'):gsub('_', '/')
  return ngx.decode_base64(str)
end

local function parse_jwk_to_pem(jwk)
  if jwk.kty ~= "RSA" then
    return nil, "Unsupported key type: " .. (jwk.kty or "unknown")
  end
  
  if not jwk.n or not jwk.e then
    return nil, "Missing required RSA parameters (n, e)"
  end
  
  -- Return the JWK as is, to be used by the JWT validator
  kong.log.debug("Parsed JWK: ", cjson.encode(jwk))
  return jwk
end

local function fetch_jwks_with_retry(conf)
  local httpc = http.new()
  httpc:set_timeout(conf.timeout)
  
  local retry_count = conf.retry_count or 3
  local retry_delay = conf.retry_delay or 1000
  
  for attempt = 1, retry_count do
    kong.log.info("Fetching JWKS from ", conf.jwks_uri, " (attempt ", attempt, "/", retry_count, ")")
    
    local res, err = httpc:request_uri(conf.jwks_uri, {
      method = "GET",
      ssl_verify = conf.ssl_verify,
      headers = {
        ["User-Agent"] = "Kong-JWT-JWKS-Plugin/1.0.0",
        ["Accept"] = "application/json"
      }
    })
    
    if res then
      if res.status == 200 then
        local jwks, decode_err = cjson.decode(res.body)
        if jwks then
          kong.log.info("Successfully fetched JWKS")
          return jwks
        else
          kong.log.err("Failed to decode JWKS JSON: ", decode_err)
          if attempt == retry_count then
            return nil, "Failed to decode JWKS JSON: " .. (decode_err or "unknown error")
          end
        end
      else
        kong.log.warn("JWKS endpoint returned status ", res.status)
        if attempt == retry_count then
          return nil, "JWKS endpoint returned status " .. res.status
        end
      end
    else
      kong.log.warn("Failed to fetch JWKS: ", err)
      if attempt == retry_count then
        return nil, "Failed to fetch JWKS: " .. (err or "unknown error")
      end
    end
    
    if attempt < retry_count then
      ngx.sleep(retry_delay / 1000)
    end
  end
  
  return nil, "All retry attempts failed"
end

local function process_jwks(jwks)
  if not jwks or not jwks.keys then
    return nil, "Invalid JWKS format: missing keys array"
  end
  
  local processed_keys = {}
  
  for _, jwk in ipairs(jwks.keys) do
    if jwk.kid and jwk.use == "sig" then
      -- Store the entire JWK for each key ID
      processed_keys[jwk.kid] = jwk
      kong.log.debug("Processed key with ID: ", jwk.kid)
    end
  end
  
  return processed_keys
end

function _M.get_public_key(conf, key_id)
  if not conf.jwks_uri then
    return nil, "No JWKS URI configured"
  end
  
  -- Try to get from cache first
  local cached_key = cache_manager.get_key(key_id)
  if cached_key then
    kong.log.debug("Using cached key for ID: ", key_id)
    return cached_key
  end
  
  -- Fetch JWKS
  local jwks, fetch_err = fetch_jwks_with_retry(conf)
  if not jwks then
    kong.log.err("Failed to fetch JWKS: ", fetch_err)
    return nil, fetch_err
  end
  
  -- Process JWKS
  local processed_keys, process_err = process_jwks(jwks)
  if not processed_keys then
    kong.log.err("Failed to process JWKS: ", process_err)
    return nil, process_err
  end
  
  -- Cache all keys
  for kid, key_data in pairs(processed_keys) do
    cache_manager.set_key(kid, key_data, conf.cache_ttl)
  end
  
  -- Return requested key
  if processed_keys[key_id] then
    kong.log.info("Found and cached key for ID: ", key_id)
    return processed_keys[key_id]
  else
    kong.log.warn("Key ID not found in JWKS: ", key_id)
    return nil, "Key ID not found in JWKS: " .. key_id
  end
end

function _M.refresh_cache(conf)
  if not conf.jwks_uri then
    return false, "No JWKS URI configured"
  end
  
  local jwks, fetch_err = fetch_jwks_with_retry(conf)
  if not jwks then
    return false, fetch_err
  end
  
  local processed_keys, process_err = process_jwks(jwks)
  if not processed_keys then
    return false, process_err
  end
  
  -- Update cache
  for kid, key_data in pairs(processed_keys) do
    cache_manager.set_key(kid, key_data, conf.cache_ttl)
  end
  
  kong.log.info("Successfully refreshed JWKS cache with ", #processed_keys, " keys")
  return true
end
-- new function to get all public keys from cache
function _M.get_all_public_keys(conf)
  if not conf.jwks_uri then
    return nil, "No JWKS URI configured"
  end

  -- Try to get all keys from cache first
  local all_cached_keys = cache_manager.get_all_keys()
  if all_cached_keys and next(all_cached_keys) then -- Check if table is not empty
    kong.log.debug("Using all cached keys for validation")
    return all_cached_keys
  end

  -- Fetch JWKS
  local jwks, fetch_err = fetch_jwks_with_retry(conf)
  if not jwks then
    kong.log.err("Failed to fetch JWKS: ", fetch_err)
    return nil, fetch_err
  end

  -- Process JWKS
  local processed_keys, process_err = process_jwks(jwks)
  if not processed_keys then
    kong.log.err("Failed to process JWKS: ", process_err)
    return nil, process_err
  end

  -- Cache all keys
  for kid, key_data in pairs(processed_keys) do
    cache_manager.set_key(kid, key_data, conf.cache_ttl)
  end

  kong.log.info("Fetched and cached all JWKS keys")
  return processed_keys
end

return _M
