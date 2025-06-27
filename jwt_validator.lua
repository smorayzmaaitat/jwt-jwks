local jwt_decoder = require "kong.plugins.jwt.jwt_parser"
local cjson = require "cjson.safe"
-- Remove these dependencies
-- local rsa = require "resty.rsa"
-- local evp = require "resty.evp"

local kong = kong
local ngx = ngx
local type = type
local pairs = pairs
local tonumber = tonumber
local os_time = os.time
local encode_base64 = ngx.encode_base64
local decode_base64 = ngx.decode_base64

local _M = {}

-- Base64URL decode function
local function base64_url_decode(input)
  local remainder = #input % 4
  if remainder > 0 then
    input = input .. string.rep("=", 4 - remainder)
  end
  input = input:gsub("-", "+"):gsub("_", "/")
  return decode_base64(input)
end

-- Convert big-endian binary string to hex
local function bin_to_hex(bin)
  return (bin:gsub('.', function(c)
    return string.format('%02x', string.byte(c))
  end))
end

-- Convert binary string to base10 integer string
local function bin_to_int(bin)
  local hex = bin_to_hex(bin)
  local result = "0"
  for i = 1, #hex do
    local digit = tonumber(hex:sub(i, i), 16)
    result = tostring(tonumber(result) * 16 + digit)
  end
  return result
end

-- Create ASN.1 length field
local function asn1_length(length)
  if length < 128 then
    return string.char(length)
  else
    local bytes = {}
    local temp = length
    while temp > 0 do
      table.insert(bytes, 1, string.char(temp % 256))
      temp = math.floor(temp / 256)
    end
    return string.char(#bytes + 128) .. table.concat(bytes)
  end
end

-- Create ASN.1 INTEGER field
local function asn1_integer(bytes)
  kong.log.debug("asn1_integer input length: ", #bytes)
  kong.log.debug("asn1_integer first byte: ", string.byte(bytes, 1) or 0)
  kong.log.debug("asn1_integer first 10 bytes (hex): ", bin_to_hex(bytes:sub(1, math.min(10, #bytes))))
  
  -- ASN.1 DER encoding rule: if the most significant bit is set,
  -- prepend a 0x00 byte to indicate it's a positive integer
  local first_byte = string.byte(bytes, 1)
  if first_byte and (first_byte >= 0x80) then
    kong.log.debug("Adding leading zero byte to prevent negative interpretation")
    bytes = "\0" .. bytes
  end
  
  local result = "\2" .. asn1_length(#bytes) .. bytes
  kong.log.debug("asn1_integer output length: ", #result)
  kong.log.debug("asn1_integer output first 10 bytes (hex): ", bin_to_hex(result:sub(1, math.min(10, #result))))
  
  return result
end

-- Create ASN.1 SEQUENCE field
local function asn1_sequence(data)
  return "\48" .. asn1_length(#data) .. data
end

-- Create ASN.1 BIT STRING field
local function asn1_bit_string(data)
  return "\3" .. asn1_length(#data + 1) .. "\0" .. data
end

-- Create ASN.1 OBJECT IDENTIFIER field
local function asn1_object_identifier(oid)
  return "\6" .. asn1_length(#oid) .. oid
end

-- Convert JWK to PEM format
local function jwk_to_pem(jwk)
  if not jwk or jwk.kty ~= "RSA" then
    return nil, "Only RSA keys are supported"
  end
  
  if not jwk.n or not jwk.e then
    return nil, "Missing required RSA parameters (n, e)"
  end
  
  -- Decode modulus and exponent from base64url
  kong.log.debug("JWK modulus (n): ", jwk.n)
  kong.log.debug("JWK exponent (e): ", jwk.e)
  
  local modulus = base64_url_decode(jwk.n)
  local exponent = base64_url_decode(jwk.e)
  
  if not modulus or not exponent then
    return nil, "Failed to decode modulus or exponent"
  end
  
  kong.log.debug("Decoded modulus length: " .. #modulus)
  kong.log.debug("Decoded exponent length: " .. #exponent)
  kong.log.debug("Modulus first 10 bytes (hex): ", bin_to_hex(modulus:sub(1, math.min(10, #modulus))))
  kong.log.debug("Exponent bytes (hex): ", bin_to_hex(exponent))
  
  -- Create RSA public key in ASN.1 DER format
  -- RSA Public Key format:
  -- RSAPublicKey ::= SEQUENCE {
  --     modulus           INTEGER,  -- n
  --     publicExponent    INTEGER   -- e
  -- }
  local rsa_public_key = asn1_sequence(
    asn1_integer(modulus) .. 
    asn1_integer(exponent)
  )
  
  -- Wrap the RSA public key in a SubjectPublicKeyInfo structure
  -- SubjectPublicKeyInfo ::= SEQUENCE {
  --     algorithm         AlgorithmIdentifier,
  --     subjectPublicKey  BIT STRING
  -- }
  -- AlgorithmIdentifier ::= SEQUENCE {
  --     algorithm         OBJECT IDENTIFIER,
  --     parameters        ANY DEFINED BY algorithm OPTIONAL
  -- }
  
  -- OID for rsaEncryption: 1.2.840.113549.1.1.1
  local rsa_encryption_oid = "\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01"
  
  local algorithm_identifier = asn1_sequence(
    asn1_object_identifier(rsa_encryption_oid) ..
    "\5\0"  -- NULL parameter
  )
  
  local subject_public_key_info = asn1_sequence(
    algorithm_identifier ..
    asn1_bit_string(rsa_public_key)
  )
  
  -- Convert DER to PEM
  local pem = "-----BEGIN PUBLIC KEY-----\n"
  local der_base64 = encode_base64(subject_public_key_info)
  
  -- Split base64 into lines of 64 characters
  for i = 1, #der_base64, 64 do
    pem = pem .. der_base64:sub(i, i + 63) .. "\n"
  end
  
  pem = pem .. "-----END PUBLIC KEY-----"
  
kong.log.debug("Generated PEM key:\n" .. pem)
  
  -- Debug: Compare with expected structure
  kong.log.debug("Generated PEM length: " .. #pem)
  kong.log.debug("Generated PEM first line: " .. (pem:match("^[^\n]*") or ""))
  
  return pem
end

local function is_algorithm_allowed(algorithm, allowed_algorithms)
  if not allowed_algorithms or #allowed_algorithms == 0 then
    return true
  end
  
  for _, allowed in pairs(allowed_algorithms) do
    if algorithm == allowed then
      return true
    end
  end
  
  return false
end

local function verify_jwt_signature(token, public_key, algorithm)
  -- Parse the JWT
  local jwt_obj, err = jwt_decoder:new(token)
  if not jwt_obj then
    return false, "Failed to parse JWT: " .. (err or "unknown error")
  end
  
  -- For debugging
  kong.log.debug("JWT header: ", cjson.encode(jwt_obj.header))
  kong.log.debug("JWT claims: ", cjson.encode(jwt_obj.claims))
  
  -- Verify the signature
  local verified, verify_err = jwt_obj:verify_signature(public_key)
  if not verified then
    return false, "Signature verification failed: " .. (verify_err or "unknown error")
  end
  
  return true, jwt_obj
end

local function validate_expiration(claims)
  if not claims.exp then
    return true -- No expiration claim
  end
  
  local exp = tonumber(claims.exp)
  if not exp then
    return false, "Invalid expiration claim format"
  end
  
  local current_time = os_time()
  if current_time >= exp then
    return false, "JWT has expired"
  end
  
  return true
end

local function validate_not_before(claims)
  if not claims.nbf then
    return true -- No not-before claim
  end
  
  local nbf = tonumber(claims.nbf)
  if not nbf then
    return false, "Invalid not-before claim format"
  end
  
  local current_time = os_time()
  if current_time < nbf then
    return false, "JWT not yet valid"
  end
  
  return true
end

local function validate_issued_at(claims, max_age)
  if not claims.iat then
    return true -- No issued-at claim
  end
  
  local iat = tonumber(claims.iat)
  if not iat then
    return false, "Invalid issued-at claim format"
  end
  
  if max_age then
    local current_time = os_time()
    if current_time - iat > max_age then
      return false, "JWT is too old"
    end
  end
  
  return true
end

function _M.validate_jwt(jwt_token, jwk, conf)
  kong.log.debug("jwt_token from _M.validate_jwt",jwt_token)
  -- Parse JWT
  -- Convert JWK to PEM for signature verification before parsing
  local pem_key, pem_err
  if type(jwk) == "table" then
    pem_key, pem_err = jwk_to_pem(jwk)
    if not pem_key then
      kong.log.err("Failed to convert JWK to PEM: ", pem_err)
      return nil, "Failed to process public key: " .. (pem_err or "unknown error")
    end
    kong.log.debug("Successfully converted JWK to PEM")
  else
    -- If it's already a PEM key, use it directly
    pem_key = jwk
  end

  -- Debug: Log the PEM key being used
  kong.log.debug("Using PEM key for validation:\n" .. pem_key)
  kong.log.debug("PEM key length: ", #pem_key)
  kong.log.debug("PEM key starts with: ", pem_key:sub(1, 50))
  kong.log.debug("PEM key ends with: ", pem_key:sub(-50))
  
  -- Additional debugging: Check if PEM has proper line endings
  local pem_lines = {}
  for line in pem_key:gmatch("[^\r\n]+") do
    table.insert(pem_lines, line)
  end
  kong.log.debug("PEM has ", #pem_lines, " lines")
  kong.log.debug("First PEM line: ", pem_lines[1] or "none")
  kong.log.debug("Last PEM line: ", pem_lines[#pem_lines] or "none")
  
  -- Debug: Try to extract and validate the base64 content
  local pem_content = pem_key:match("-----BEGIN PUBLIC KEY-----\n(.-)\n-----END PUBLIC KEY-----")
  if pem_content then
    kong.log.debug("Extracted PEM content length: ", #pem_content)
    kong.log.debug("PEM content first 100 chars: ", pem_content:sub(1, 100))
    
    -- Try to decode the base64 content to verify it's valid
    local der_data = decode_base64(pem_content:gsub("\n", ""))
    if der_data then
      kong.log.debug("Successfully decoded PEM to DER, length: ", #der_data)
      kong.log.debug("DER first 20 bytes (hex): ", bin_to_hex(der_data:sub(1, 20)))
    else
      kong.log.err("Failed to decode PEM base64 content")
    end
  else
    kong.log.err("Failed to extract PEM content between markers")
  end
  
  -- Parse JWT with the PEM key
  kong.log.debug("About to call jwt_decoder:new with token length: ", #jwt_token)
  local jwt_obj, parse_err = jwt_decoder:new(jwt_token, pem_key)
  
  kong.log.debug("jwt_decoder:new returned - jwt_obj type: ", type(jwt_obj))
  kong.log.debug("jwt_decoder:new returned - parse_err: ", parse_err or "none")
  
  if not jwt_obj then
    kong.log.err("Failed to parse JWT: ", parse_err)
    return nil, "JWT parsing failed: " .. (parse_err or "unknown error")
  end
  
  kong.log.debug("JWT object created successfully")
  kong.log.debug("JWT object type: ", type(jwt_obj))
  kong.log.debug("JWT header: ", cjson.encode(jwt_obj.header or {}))
  kong.log.debug("JWT claims: ", cjson.encode(jwt_obj.claims or {}))
  
  -- Step 1: Verify cryptographic signature
  kong.log.debug("Starting signature verification...")
  local signature_valid = false
  
  if type(jwt_obj.verify_signature) == "function" then
    kong.log.debug("Calling jwt_obj:verify_signature(pem_key)")
    signature_valid = jwt_obj:verify_signature(pem_key)
    kong.log.debug("Signature verification result: ", signature_valid)
  else
    kong.log.err("verify_signature method not found on JWT object")
    return nil, "JWT validation failed: signature verification method not available"
  end
  
  if not signature_valid then
    kong.log.err("JWT signature verification failed")
    return nil, "JWT validation failed: invalid signature"
  end
  
  kong.log.debug("JWT signature verification successful")
  
  -- Step 2: Verify registered claims (exp, nbf, etc.)
  kong.log.debug("Starting claims verification...")
  local claims_valid = true
  local claim_errors = {}
  
  if type(jwt_obj.verify_registered_claims) == "function" then
    kong.log.debug("Calling jwt_obj:verify_registered_claims()")
    claims_valid, claim_errors = jwt_obj:verify_registered_claims()
    kong.log.debug("Claims verification result: ", claims_valid)
    if claim_errors and #claim_errors > 0 then
      kong.log.debug("Claims errors: ", cjson.encode(claim_errors))
    end
  else
    kong.log.debug("verify_registered_claims method not found, performing manual validation")
    
    -- Manual validation of exp and nbf claims
    local current_time = os_time()
    
    if jwt_obj.claims.exp then
      if current_time >= jwt_obj.claims.exp then
        claims_valid = false
        table.insert(claim_errors, "token expired")
        kong.log.debug("Token expired: current=", current_time, " exp=", jwt_obj.claims.exp)
      end
    end
    
    if jwt_obj.claims.nbf then
      if current_time < jwt_obj.claims.nbf then
        claims_valid = false
        table.insert(claim_errors, "token not yet valid")
        kong.log.debug("Token not yet valid: current=", current_time, " nbf=", jwt_obj.claims.nbf)
      end
    end
  end
  
  if not claims_valid then
    local error_msg = "JWT validation failed: " .. table.concat(claim_errors, ", ")
    kong.log.err(error_msg)
    return nil, error_msg
  end
  
  kong.log.debug("JWT claims verification successful")
  kong.log.debug("JWT validation completed successfully")
  
  -- Check algorithm
  local algorithm = jwt_obj.header.alg
  if not algorithm then
    return nil, "Missing algorithm in JWT header"
  end
  
  if not is_algorithm_allowed(algorithm, conf.allowed_algorithms) then
    return nil, "Algorithm not allowed: " .. algorithm
  end
  
  -- The jwt_decoder:new function should handle signature verification when given a PEM key.
  -- The separate verify_jwt_signature function is likely redundant here.
  -- If further issues arise, we can re-evaluate the need for a separate verification step.
  
  -- Validate time-based claims
  local exp_valid, exp_err = validate_expiration(jwt_obj.claims)
  if not exp_valid then
    return nil, exp_err
  end
  
  local nbf_valid, nbf_err = validate_not_before(jwt_obj.claims)
  if not nbf_valid then
    return nil, nbf_err
  end
  
  local iat_valid, iat_err = validate_issued_at(jwt_obj.claims, conf.max_token_age)
  if not iat_valid then
    return nil, iat_err
  end
  
  return jwt_obj
end

return _M
