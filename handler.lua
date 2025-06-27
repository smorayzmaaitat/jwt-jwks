local jwt_decoder = require "kong.plugins.jwt.jwt_parser"
local jwks_client = require "kong.plugins.jwt-jwks.jwks_client"
local jwt_validator = require "kong.plugins.jwt-jwks.jwt_validator"
local cache_manager = require "kong.plugins.jwt-jwks.cache_manager"
local cjson = require "cjson.safe"

local kong = kong
local ngx = ngx
local type = type
local pairs = pairs
local tostring = tostring

local JwtJwksHandler = {
  PRIORITY = 1005,
  VERSION = "1.0.0"
}


local function extract_jwt_token(request, conf)
  local token
  
  -- Try configured headers first
  if conf.header_names and #conf.header_names > 0 then
    for _, header_name in pairs(conf.header_names) do
      local header_value = request.get_header(header_name:lower())
      if header_value then
        if header_name:lower() == "authorization" then
          -- Handle Bearer token format for Authorization header
          local iterator, iter_err = ngx.re.gmatch(header_value, "\\s*[Bb]earer\\s+(.+)")
          if iterator then
            local m, err = iterator()
            if m and m[1] then
              token = m[1]
              kong.log.debug("Found JWT token in ", header_name, " header")
              break
            end
          end
        else
          -- For other headers, use the value directly
          token = header_value
          kong.log.debug("Found JWT token in ", header_name, " header")
          break
        end
      end
    end
  else
    -- Fallback to default Authorization header if no headers configured
    local authorization_header = request.get_header("authorization")
    if authorization_header then
      local iterator, iter_err = ngx.re.gmatch(authorization_header, "\\s*[Bb]earer\\s+(.+)")
      if iterator then
        local m, err = iterator()
        if m and m[1] then
          token = m[1]
        end
      end
    end
  end
  
  -- Try query parameter if no header token
  if not token then
    token = request.get_query_arg("jwt")
    if token then
      kong.log.debug("Found JWT token in query parameter")
    end
  end
  
  -- Try cookie if no query parameter
  if not token then
    local cookie_header = request.get_header("cookie")
    if cookie_header then
      local cookie_match = ngx.re.match(cookie_header, "jwt=([^;]+)")
      if cookie_match then
        token = cookie_match[1]
        kong.log.debug("Found JWT token in cookie")
      end
    end
  end
  
  return token
end

local function base64_url_decode(str)
  local remainder = #str % 4
  if remainder > 0 then
    str = str .. string.rep('=', 4 - remainder)
  end
  str = str:gsub('-', '+'):gsub('_', '/')
  return ngx.decode_base64(str)
end

local function get_key_id_from_jwt(jwt_token)
  -- Split the JWT token into parts
  local parts = {}
  for part in jwt_token:gmatch("[^%.]+") do
    table.insert(parts, part)
  end
  
  if #parts ~= 3 then
    return nil, "JWT format error: expected 3 parts, got " .. #parts
  end
  
  -- Decode the header (first part)
  local header_encoded = parts[1]
  local header_decoded = base64_url_decode(header_encoded)
  
  if not header_decoded then
    return nil, "Failed to decode JWT header"
  end
  
  -- Parse the header JSON
  local header, decode_err = cjson.decode(header_decoded)
  if not header then
    return nil, "Failed to parse JWT header JSON: " .. (decode_err or "unknown error")
  end
  
  kong.log.debug("JWT header: ", cjson.encode(header))
  
  -- Extract the key ID
  if header.kid then
    kong.log.debug("TOKEN inside jwt_validator: ", jwt_token)
    kong.log.debug("Found key ID in JWT header: ", header.kid)
    return header.kid
  end
  
  return nil, "No key ID found in JWT header"
end

local function validate_required_claims(claims, required_claims)
  if not required_claims or #required_claims == 0 then
    return true
  end
  
  for _, claim in pairs(required_claims) do
    if not claims[claim] then
      kong.log.warn("Missing required claim: ", claim)
      return false, "Missing required claim: " .. claim
    end
  end
  
  return true
end

function JwtJwksHandler:access(conf)
  -- Handle CORS preflight requests

-- inside your JwtJwksHandler:access(conf)
local uri = kong.request.get_path()
for _, pat in ipairs(conf.excluded_paths or {}) do
  if pat:sub(1,1) == "^" then
    -- starts-with
    if uri:sub(1, #pat-1) == pat:sub(2) then return end
  elseif pat:sub(-1) == "$" then
    -- ends-with
    if uri:sub(-(#pat-1)) == pat:sub(1, -2) then return end
  else
    -- exact
    if uri == pat then return end
  end
end
-- …rest of your JWT logic…


  if not conf.run_on_preflight then
    local method = kong.request.get_method()
    if method == "OPTIONS" then
      kong.log.debug("Skipping JWT validation for CORS preflight request")
      return
    end
  end
  
  -- Extract JWT token from request
  local token, extract_err = extract_jwt_token(kong.request, conf)
  if not token then
    kong.log.warn("No JWT token found in request")
    return kong.response.exit(401, {
      message = "Unauthorized",
      error = "No JWT token provided"
    })
  end
  
  kong.log.debug("Extracted JWT token: ", token:sub(1, 50) .. "...")
  
  -- Parse JWT to get key ID
  local key_id, key_err = get_key_id_from_jwt(token)

  -- Get all public keys from JWKS
  kong.log.debug("----------------------------->>>>>Calling jwks_client.get_all_public_keys with jwks_uri: ", conf.jwks_uri or "nil")

  local all_public_keys, fetch_keys_err = jwks_client.get_all_public_keys(conf)
  

  if all_public_keys then
    kong.log.debug("------------------->>>JWKS keys fetched: ", cjson.encode(all_public_keys))
  else
    kong.log.err("-------------------->>. JWKS fetch failed: ", fetch_keys_err or "Unknown error")
  end
  
  if not all_public_keys or next(all_public_keys) == nil then
    kong.log.err("Failed to obtain any public keys from JWKS: ", fetch_keys_err or "No keys found")
    return kong.response.exit(401, {
      message = "Unauthorized",
      error = "Unable to obtain public keys for JWT validation"
    })
  end

  local jwt_obj
  local jwt_err
  local validated_key_id

  -- If KID is present in the token, try to validate with that specific key first
  if key_id and all_public_keys[key_id] then
    kong.log.debug("Attempting validation with specific key ID from token: ", key_id)
    jwt_obj, jwt_err = jwt_validator.validate_jwt(token, all_public_keys[key_id], conf)
    if jwt_obj then
      validated_key_id = key_id
    else
      kong.log.debug("Validation failed with specific key ID (", key_id, "): ", jwt_err)
    end
  end

  -- If validation failed or no KID was present, try all available keys
  if not jwt_obj then
    kong.log.debug("Attempting validation with all available keys.")
    for kid_from_jwks, public_key_from_jwks in pairs(all_public_keys) do
      kong.log.debug("Trying validation with key ID: ", kid_from_jwks)
      jwt_obj, jwt_err = jwt_validator.validate_jwt(token, public_key_from_jwks, conf)
      if jwt_obj then
        validated_key_id = kid_from_jwks
        kong.log.debug("Successfully validated with key ID: ", validated_key_id)
        break -- Exit loop on first successful validation
      else
        kong.log.debug("Validation failed with key ID (", kid_from_jwks, "): ", jwt_err)
      end
    end
  end


  if not jwt_obj then
    kong.log.debug("JWT validation failed with error: ", jwt_err)
    if type(token) == "string" then
      kong.log.debug("Token format: ", token:sub(1, 20) .. "...")
      
      -- Try to decode and inspect the token parts
      local parts = {}
      for part in token:gmatch("[^%.]+") do
        table.insert(parts, part)
      end
      
      if #parts == 3 then
        local header_decoded = base64_url_decode(parts[1])
        local payload_decoded = base64_url_decode(parts[2])
        
        if header_decoded then
          local header, decode_err = cjson.decode(header_decoded)
          if header then
            kong.log.debug("Decoded header: ", cjson.encode(header))
          else
            kong.log.debug("Failed to decode header JSON: ", decode_err)
          end
        end
        
        if payload_decoded then
          local payload, decode_err = cjson.decode(payload_decoded)
          if payload then
            kong.log.debug("Decoded payload: ", cjson.encode(payload))
          else
            kong.log.debug("Failed to decode payload JSON: ", decode_err)
          end
        end
      else
        kong.log.debug("Token does not have 3 parts: found ", #parts, " parts")
      end
    end
    
    kong.log.warn("JWT validation failed: ", jwt_err)
    return kong.response.exit(401, {
      message = "Unauthorized",
      error = jwt_err or "JWT validation failed"
    })
  end
  
  -- Validate required claims
  local claims_valid, claims_err = validate_required_claims(jwt_obj.claims, conf.claims_to_verify)
  if not claims_valid then
    kong.log.warn("Claims validation failed: ", claims_err)
    return kong.response.exit(401, {
      message = "Unauthorized",
      error = claims_err or "JWT claims validation failed"
    })
  end
  
  -- Set JWT claims in context for downstream plugins
  kong.ctx.shared.jwt_claims = jwt_obj.claims
  kong.ctx.shared.jwt_header = jwt_obj.header
  
  -- Set authenticated user information
  if jwt_obj.claims.sub then
    kong.ctx.shared.authenticated_user_id = jwt_obj.claims.sub
  end
  
  kong.log.info("JWT validation successful for key ID: ", key_id or "fallback")
end

return JwtJwksHandler
