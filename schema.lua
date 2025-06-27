local typedefs = require "kong.db.schema.typedefs"

return {
  name = "jwt-jwks",
  fields = {
    { consumer          = typedefs.no_consumer },
    { protocols         = typedefs.protocols_http },
    {
      config = {
        type   = "record",
        fields = {
          { jwks_uri = {
              type        = "string",
              required    = false,
              description = "URI to fetch JWKS from",
          }},

          { cache_ttl = {
              type        = "number",
              default     = 3600,
              gt          = 0,
              description = "Cache TTL for JWKS keys in seconds",
          }},

          { timeout = {
              type        = "number",
              default     = 5000,
              gt          = 0,
              description = "HTTP timeout for JWKS requests in milliseconds",
          }},

          { ssl_verify = {
              type        = "boolean",
              default     = true,
              description = "Verify SSL certificates for JWKS requests",
          }},

          { key_claim_name = {
              type        = "string",
              default     = "iss",
              description = "JWT claim containing key identifier",
          }},

          { fallback_public_key = {
              type        = "string",
              required    = false,
              description = "Static public key to use as fallback",
          }},

          { allowed_algorithms = {
              type        = "array",
              elements    = { type = "string" },
              default     = { "RS256", "RS384", "RS512", "ES256", "ES384", "ES512" },
              description = "Allowed JWT signing algorithms",
          }},

          { claims_to_verify = {
              type        = "array",
              elements    = { type = "string" },
              default     = { "exp", "iss" },
              description = "Required JWT claims to verify",
          }},

          { max_cache_size = {
              type        = "number",
              default     = 100,
              gt          = 0,
              description = "Maximum number of keys to cache",
          }},

          { refresh_ahead_time = {
              type        = "number",
              default     = 300,
              gt          = 0,
              description = "Refresh cache this many seconds before expiry",
          }},

          { retry_count = {
              type        = "number",
              default     = 3,
              gt          = 0,
              description = "Number of retries for JWKS requests",
          }},

          { retry_delay = {
              type        = "number",
              default     = 1000,
              gt          = 0,
              description = "Delay between retries in milliseconds",
          }},

          { header_names = {
              type        = "array",
              elements    = { type = "string" },
              default     = { "Authorization" },
              description = "List of header names to check for JWT tokens",
          }},

          { run_on_preflight = {
              type        = "boolean",
              default     = false,
              description = "Whether to run the plugin on CORS preflight requests",
          }},  -- ← comma added here

          { excluded_paths = {
              type        = "array",
              elements    = { type = "string" },
              default     = {},
              description = "List of paths to exclude from JWT validation",
          }}, 
        },  
      },   
    },     
  },  
}    
