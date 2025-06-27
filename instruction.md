# Kong JWKS Plugin Development Prompt

## Objective
Create a custom Kong Gateway plugin that extends JWT authentication with JWKS (JSON Web Key Set) support, enabling dynamic public key fetching and automatic key rotation.

## Plugin Requirements

### Core Functionality
1. **JWKS URI Support**: Fetch public keys from a configurable JWKS endpoint
2. **Key Caching**: Cache fetched keys with configurable TTL to avoid excessive API calls
3. **Key Rotation**: Automatically refresh keys when cache expires or validation fails
4. **Fallback Mechanism**: Support static public keys as fallback when JWKS is unavailable
5. **JWT Validation**: Validate incoming JWTs using dynamically fetched public keys

### Plugin Configuration Schema
```lua
-- Expected configuration parameters
{
  jwks_uri = "https://auth-service/.well-known/jwks.json",  -- JWKS endpoint
  cache_ttl = 3600,                                        -- Cache TTL in seconds (default: 1 hour)
  timeout = 5000,                                          -- HTTP timeout in milliseconds
  ssl_verify = true,                                       -- SSL certificate verification
  key_claim_name = "iss",                                  -- JWT claim containing key identifier
  fallback_public_key = "-----BEGIN PUBLIC KEY-----...",  -- Static fallback key
  allowed_algorithms = {"RS256", "RS384", "RS512"},       -- Supported algorithms
  claims_to_verify = {"exp", "iss", "aud"}                -- Required JWT claims
}
```

### Technical Specifications

#### Plugin Structure
- **Plugin Name**: `jwt-jwks`
- **Plugin Priority**: 1005 (same as standard JWT plugin)
- **Execution Phase**: `access` phase
- **Kong Version**: Compatible with Kong Gateway 3.5+

#### Key Components
1. **Schema Definition** (`schema.lua`)
   - Define configuration validation rules
   - Set default values and constraints
   - Validate JWKS URI format and reachability

2. **Handler Logic** (`handler.lua`)
   - Implement main plugin execution logic
   - JWT extraction and validation
   - JWKS fetching and caching
   - Error handling and fallback mechanisms

3. **JWKS Client** (`jwks_client.lua`)
   - HTTP client for fetching JWKS
   - Key parsing and validation
   - Cache management with Kong's shared dictionary

4. **JWT Validator** (`jwt_validator.lua`)
   - JWT signature verification using fetched keys
   - Claims validation
   - Algorithm verification

#### Caching Strategy
- Use Kong's `kong.cache` or `ngx.shared.DICT` for key storage
- Implement cache invalidation on HTTP 401/403 responses
- Background refresh mechanism to prevent cache expiry during high traffic

#### Error Handling
- Graceful degradation when JWKS endpoint is unavailable
- Detailed logging for troubleshooting
- Proper HTTP status codes (401 for invalid tokens, 500 for plugin errors)

### Implementation Guidelines

#### Security Considerations
1. **SSL/TLS Verification**: Always verify SSL certificates for JWKS endpoints
2. **Rate Limiting**: Implement rate limiting for JWKS endpoint calls
3. **Key Validation**: Validate fetched keys format and algorithms
4. **Timing Attack Prevention**: Use constant-time comparison for sensitive operations

#### Performance Optimization
1. **Async Operations**: Use non-blocking HTTP calls for JWKS fetching
2. **Connection Pooling**: Reuse HTTP connections to JWKS endpoints
3. **Memory Management**: Efficient memory usage for key storage
4. **Background Updates**: Update cache in background to avoid request latency

#### Error Scenarios to Handle
- JWKS endpoint unreachable or returns errors
- Invalid JWKS format or malformed keys
- JWT with unknown key ID (kid)
- Network timeouts and connection failures
- SSL certificate validation failures

### Plugin Directory Structure
```
jwt-jwks/
├── handler.lua           # Main plugin handler
├── schema.lua           # Configuration schema
├── jwks_client.lua      # JWKS HTTP client
├── jwt_validator.lua    # JWT validation logic
├── cache_manager.lua    # Cache management utilities
└── rockspec            # LuaRocks specification
```

### Testing Requirements
1. **Unit Tests**: Test individual components (JWKS client, JWT validator)
2. **Integration Tests**: Test with real JWKS endpoints
3. **Performance Tests**: Measure cache performance and memory usage
4. **Security Tests**: Test with malformed JWTs and invalid keys
5. **Failover Tests**: Test fallback mechanisms and error handling

### Installation and Usage Instructions
Provide clear documentation for:
1. Plugin installation methods (LuaRocks, manual installation)
2. Configuration examples for different use cases
3. Integration with existing Kong setups
4. Troubleshooting common issues
5. Performance tuning recommendations

### Advanced Features (Optional)
1. **Multiple JWKS Endpoints**: Support for multiple JWKS sources
2. **Key Rotation Notifications**: Webhook notifications on key rotation
3. **Metrics and Monitoring**: Plugin-specific metrics for observability
4. **Admin API Integration**: REST endpoints for cache management
5. **Hot Reload**: Dynamic configuration updates without restart

### Development Environment Setup
1. Kong Gateway development environment
2. Lua development tools and testing frameworks
3. Mock JWKS server for testing
4. Performance profiling tools

### Deliverables
1. Complete plugin source code with proper documentation
2. Installation and configuration guide
3. Test suite with comprehensive coverage
4. Performance benchmarks and optimization notes
5. Migration guide from standard JWT plugin

## Example Usage
Once developed, the plugin should be configurable like this:

```yaml
plugins:
  - name: jwt-jwks
    config:
      jwks_uri: http://auth-service:80/api/.well-known/jwks.json
      cache_ttl: 3600
      key_claim_name: iss
      claims_to_verify:
        - exp
        - iss
        - aud
```

This plugin will provide the JWKS functionality that Kong Gateway OSS lacks, enabling dynamic key management and automatic rotation for JWT authentication.