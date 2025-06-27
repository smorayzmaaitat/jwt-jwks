# jwt-jwks Kong Plugin

This custom Kong plugin (`jwt-jwks`) extends JWT authentication to fetch and cache public keys from JWKS (JSON Web Key Set) endpoints. It enables dynamic public key fetching, automatic key rotation, and importantly, exposes Admin API endpoints to inspect and clear the cache without restarting Kong.

## Features

*   **Admin API for Cache Management**:
    *   Get cache statistics (`GET /jwt-jwks/cache/info`)
    *   Clear entire cache (`POST /jwt-jwks/cache/clear`)
    *   Clear specific key by Key ID (`POST /jwt-jwks/cache/clear/:key_id`)
*   **JWKS URI Support**: Fetch public keys from configurable JWKS endpoints.
*   **Key Caching**: Cache fetched keys in an NGINX shared dictionary with configurable TTL or based on JWKS metadata.
*   **Key Rotation**: Automatically refresh keys when cache expires or validation fails.
*   **Fallback Mechanism**: Support static public keys as fallback when JWKS is unavailable.
*   **JWT Validation**: Validate incoming JWTs using dynamically fetched public keys.
*   **Security**: SSL verification, algorithm validation.
*   **Performance**: Efficient caching.

## Architecture Diagram

The following diagram illustrates the role of the `jwt-jwks` plugin within the Kong API Gateway, its interaction points, and the data flow for JWT validation.

```mermaid
graph TDgraph TD
 subgraph Client["Client"]
        A["Client Application"]
  end
 subgraph subGraph1["Kong API Gateway"]
        B("Kong Gateway")
        C{"JWT-JWKS Plugin"}
        D["JWKS Cache (Shared Dictionary)"]
  end
 subgraph subGraph2["External Services"]
        E["Auth Service (JWKS Endpoint)"]
        F["Upstream Service"]
  end
 subgraph subGraph3["Admin API Interaction"]
        G["Admin API Client"]
        H("Kong Admin API")
  end
    A -- "-1. Request with JWT" --> B
    B -- "-2. Route to Plugin'" --> C
    C -- "-3. Check Cache for JWKS Key" --> D
    D -- "-4a. Key Found (Cache Hit)" --> C
    C -- "-4b. Key Not Found/Expired (Cache Miss)" --> E
    E -- "-5. Return JWKS" --> C
    C -- "-6. Cache JWKS" --> D
    C -- "-7. Validate JWT" --> B
    B -- "-8. Forward Request" --> F
    F -- "-9. Response" --> B
    B -- "-10. Return Response" --> A
    G -- Get Cache Info / Clear Cache --> H
    H -- Interact with Cache Manager --> C
    C -- Manage Cache --> D

    style A fill:#f9f,stroke:#333,stroke-width:2px
    style B fill:#bbf,stroke:#333,stroke-width:2px
    style C fill:#ccf,stroke:#333,stroke-width:2px
    style D fill:#cfc,stroke:#333,stroke-width:2px
    style E fill:#fcc,stroke:#333,stroke-width:2px
    style F fill:#ffc,stroke:#333,stroke-width:2px
    style G fill:#f9f,stroke:#333,stroke-width:2px
    style H fill:#bbf,stroke:#333,stroke-width:2px
```

## Directory Structure

```
kong/plugins/jwt-jwks/
├── handler.lua        # Main plugin logic (access phase)
├── api.lua            # Admin API endpoint definitions
├── init.lua           # Plugin entry point (registers handler + API)
├── cache_manager.lua  # Cache management in NGINX shared dict
├── jwks_client.lua    # Client for fetching JWKS
├── jwt_validator.lua  # Logic for JWT validation
├── schema.lua         # Plugin configuration schema
├── docker-compose.test.yml # Docker Compose for testing
├── handler.lua.back   # Backup of handler.lua
├── instruction.md     # Additional instructions
├── README.md          # This README file
├── spec/              # Test specifications
└── test/              # Test files
```

### Manual Installation

1. Copy the plugin files to your Kong plugins directory:
   (e.g., `/usr/local/share/lua/5.1/kong/plugins/`).
   If you cloned the repository containing the plugin:
   ```bash
   # Example: if your plugin code is in ./api-gateway/kong/plugins/jwt-jwks
   cp -r ./api-gateway/kong/plugins/jwt-jwks /usr/local/share/lua/5.1/kong/plugins/
   ```

2. Add the plugin to your Kong configuration:
   * In **Kong Gateway** configuration (e.g., `kong.conf`) or via environment variable:
   ```bash
export KONG_PLUGINS=bundled,jwt-jwks
   ```
   * If using Docker Compose, add to your `docker-compose.yml`:
   ```yaml
   services:
     kong:
       environment:
         KONG_PLUGINS: bundled,jwt-jwks
       volumes:
         - ./kong/plugins:/usr/local/share/lua/5.1/kong/plugins # Adjust source path as needed
   ```

3. Restart Kong:
```bash
kong restart
   # or if using Docker Compose:
   docker-compose down && docker-compose up -d
```

## Configuration

### Plugin Configuration Schema

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `jwks_uri`            | string  | -                                                              | URI to fetch JWKS from                                      |
| `cache_ttl`           | number  | `3600`                                                         | Cache TTL for JWKS keys in seconds                          |
| `header_names`        | array   | `["Authorization"]`                                            | List of header names to check for JWT tokens                |
| `run_on_preflight`    | boolean | `false`                                                        | Whether to run the plugin on CORS preflight requests        |
| `timeout`             | number  | `5000`                                                         | HTTP timeout for JWKS requests in milliseconds              |
| `ssl_verify`          | boolean | `true`                                                         | Verify SSL certificates for JWKS requests                   |
| `key_claim_name`      | string  | `"iss"`                                                        | JWT claim containing key identifier (e.g., "kid", "iss")    |
| `fallback_public_key` | string  | -                                                              | Static public key to use as fallback                        |
| `allowed_algorithms`  | array   | `["RS256", "RS384", "RS512", "ES256", "ES384", "ES512"]`       | Allowed JWT signing algorithms                              |
| `claims_to_verify`    | array   | `["exp", "iss"]`                                               | Required JWT claims to verify (e.g., "exp", "iss", "aud") |
| `max_cache_size`      | number  | `100`                                                          | Maximum number of keys to cache                             |
| `refresh_ahead_time`  | number  | `300`                                                          | Refresh cache this many seconds before expiry               |
| `retry_count`         | number  | `3`                                                            | Number of retries for JWKS requests                         |
| `retry_delay`         | number  | `1000`                                                         | Delay between retries in milliseconds                       |

### Example Configuration

#### Using Kong Admin API

\`\`\`bash
curl -X POST http://kong:8001/services/{service}/plugins \
  --data "name=jwt-jwks" \
  --data "config.jwks_uri=https://example.com/.well-known/jwks.json" \
  --data "config.cache_ttl=3600" \
  --data "config.key_claim_name=kid" \
  --data "config.claims_to_verify[]=exp" \
  --data "config.claims_to_verify[]=iss"
\`\`\`

#### Using Declarative Configuration

\`\`\`yaml
plugins:
  - name: jwt-jwks
    service: my-service
    config:
      jwks_uri: https://auth-service/.well-known/jwks.json
      cache_ttl: 3600
      timeout: 5000
      ssl_verify: false # Example: if auth-service is internal and uses HTTP
      key_claim_name: iss
      allowed_algorithms:
        - RS256
        - RS384
        - RS512
      claims_to_verify:
        - exp
        - iss
        - aud
        - nbf
      retry_count: 3
      retry_delay: 1000
      header_names:
        - Authorization
        - X-JWT-Token
        - X-Access-Token
      run_on_preflight: false
\`\`\`

#### With Fallback Key

\`\`\`yaml
plugins:
  - name: jwt-jwks
    service: my-service
    config:
      jwks_uri: https://auth-service/.well-known/jwks.json
      fallback_public_key: |
        -----BEGIN PUBLIC KEY-----
        MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...
        -----END PUBLIC KEY-----
      cache_ttl: 1800
      claims_to_verify:
        - exp
        - iss
\`\`\`

## Admin API Endpoints

These endpoints are exposed on the **Admin API port** (default `:8001`).

| Endpoint                        | Method | Description                                            |
| ------------------------------- | ------ | ------------------------------------------------------ |
| `/jwt-jwks/cache/info`          | GET    | Retrieve cache statistics (`cache_type`, `keys_count`) |
| `/jwt-jwks/cache/clear`         | POST   | Clear all cached JWKS keys                             |
| `/jwt-jwks/cache/clear/:key_id` | POST   | Clear cache for a specific Key ID                      |

### Examples

*   **Get cache info**:

    ```bash
    curl http://localhost:8001/jwt-jwks/cache/info
    ```

*   **Clear entire cache**:

    ```bash
    curl -X POST http://localhost:8001/jwt-jwks/cache/clear
    ```

*   **Clear specific key**:

    ```bash
    curl -X POST http://localhost:8001/jwt-jwks/cache/clear/your-key-id
    ```

## Usage

### JWT Token Requirements

The plugin expects JWT tokens to include:

1. **Header**: Must contain `alg` (algorithm) and optionally `kid` (key ID)
2. **Payload**: Must contain required claims as configured
3. **Signature**: Must be valid according to the fetched public key

### Token Extraction

The plugin extracts JWT tokens from requests in the following order:

1. **Authorization Header**: `Authorization: Bearer <token>`
2. **Query Parameter**: `?jwt=<token>`
3. **Cookie**: `jwt=<token>`

### Example JWT Header

\`\`\`json
{
  "alg": "RS256",
  "typ": "JWT",
  "kid": "key-id-1"
}
\`\`\`

### Example JWT Payload

\`\`\`json
{
  "iss": "https://auth-service",
  "sub": "user123",
  "aud": "my-api",
  "exp": 1640995200,
  "iat": 1640991600
}
\`\`\`

## JWKS Endpoint Requirements

Your JWKS endpoint should return a JSON response in the following format:

\`\`\`json
{
  "keys": [
    {
      "kty": "RSA",
      "use": "sig",
      "kid": "key-id-1",
      "alg": "RS256",
      "n": "base64url-encoded-modulus",
      "e": "base64url-encoded-exponent"
    }
  ]
}
\`\`\`

## Error Handling

The plugin handles various error scenarios gracefully:

- **JWKS Endpoint Unavailable**: Falls back to static key if configured
- **Invalid JWT Format**: Returns 401 with descriptive error
- **Missing Key ID**: Uses fallback key if available
- **Signature Verification Failure**: Returns 401 with error details
- **Expired Tokens**: Returns 401 with expiration error
- **Network Timeouts**: Retries with exponential backoff

## Performance Considerations

### Caching Strategy

- Keys are cached in Kong's shared dictionary for fast access
- Cache TTL is configurable to balance freshness and performance
- Background refresh prevents cache expiry during high traffic
- LRU eviction when cache size limit is reached

### HTTP Client Optimization

- Connection pooling for JWKS endpoint requests
- Configurable timeouts and retry logic
- SSL session reuse for HTTPS endpoints
- Async operations to prevent request blocking

### Memory Management

- Efficient key storage using shared dictionaries
- Automatic cleanup of expired cache entries
- Configurable cache size limits
- Memory-efficient JWT parsing

## Security Features

### SSL/TLS Security

- SSL certificate verification enabled by default
- Support for custom CA certificates
- Protection against man-in-the-middle attacks

### Algorithm Validation

- Configurable list of allowed signing algorithms
- Protection against algorithm confusion attacks
- Support for RSA and ECDSA algorithms

### Timing Attack Prevention

- Constant-time string comparisons for sensitive operations
- Secure random number generation for cache keys
- Protection against timing-based attacks

## Monitoring and Observability

### Logging

The plugin logs cache operations at the `info` level, and errors or unexpected conditions at the `err` level:

*   `[jwt-jwks] Admin API: Fetching JWKS cache stats`
*   `[jwt-jwks] Admin API: Clearing JWKS cache`
*   `[jwt-jwks] Admin API: Clearing cache for key ID: <key_id>`
*   Successful JWT validation and key fetching are also logged.
*   Errors are logged with stack traces if using `pcall` for Admin API calls.

General plugin logging:
- **ERROR**: Failures and configuration issues
- **DEBUG**: Detailed operation traces

### Metrics

Key metrics exposed through Kong's metrics plugins:

- JWT validation success/failure rates
- JWKS fetch success/failure rates
- Cache hit/miss ratios
- Response times for JWKS requests

## Troubleshooting

### Common Issues

1.  **404 on Admin API routes** (`/jwt-jwks/cache/...`):
    *   Ensure the `jwt-jwks` plugin is correctly listed in `KONG_PLUGINS` (or `plugins` in `kong.conf`).
    *   Verify that `init.lua` correctly exports an `api` table that points to `api.lua`.
    *   Check Kong's startup logs for errors related to loading the plugin or its API endpoints.

2.  **"Method Not Allowed" on Admin API routes**:
    *   Ensure the HTTP verbs (`GET`, `POST`) are correctly defined directly for the routes in `api.lua`, not under a `methods` subtable.

3.  **Shared Dictionary Missing or Cache Not Working**:
    *   Confirm `lua_shared_dict jwt_jwks_cache <size>;` (e.g., `lua_shared_dict jwt_jwks_cache 10m;`) is defined in Kong’s NGINX configuration template, typically within the `http` block.
    *   Check Kong logs for warnings like "Shared dictionary 'jwt_jwks_cache' not found, using fallback cache". The fallback cache is in-memory per worker and not shared, nor clearable via the Admin API.

4.  **Permissions for Shared Dictionary**:
    *   Ensure Kong worker processes have the necessary permissions to read/write to the NGINX shared dictionary. This is usually handled by NGINX itself.

5.  **"No JWT token provided"**:
    *   **Cause**: Token not found in configured `header_names`, query parameters, or cookies.
    *   **Solution**: Ensure the token is being sent correctly and the plugin is configured to look in the right places.

6.  **"Signature verification failed"**:
    *   **Cause**: Mismatch between the key used for signing and the key retrieved from JWKS, or an incorrect algorithm.
    *   **Solution**: Verify the `kid` in the JWT header matches a key in the JWKS. Ensure `allowed_algorithms` in the plugin config matches the JWT's `alg` header.

7.  **"Unable to determine key for JWT validation"**:
    *   **Cause**: The JWT does not contain a `kid` (Key ID) in its header, and no `fallback_public_key` is configured in the plugin.
    *   **Solution**: Ensure your JWTs include a `kid` header claim, or configure a `fallback_public_key` in the plugin for tokens that lack a `kid`.

8.  **"JWKS endpoint returned status 404" or other HTTP errors**:
    *   **Cause**: The `jwks_uri` configured in the plugin is incorrect, the JWKS endpoint is down, or there is a network issue between Kong and the JWKS endpoint.
    *   **Solution**:
        *   Verify that the `jwks_uri` is correct and accessible from the Kong container/node.
        *   Check the status of your authentication service's JWKS endpoint.
        *   Review network policies or firewalls that might be blocking the connection.

### Debug Mode

Enable debug logging to troubleshoot issues:

\`\`\`bash
export KONG_LOG_LEVEL=debug
kong restart
\`\`\`

### Cache Inspection

Check cache status using Kong's Admin API:
This command is for Kong's generic cache API, not specific to this plugin's shared dictionary directly. For this plugin, use the `/jwt-jwks/cache/info` endpoint.
\`\`\`bash
curl http://kong:8001/cache/jwt_jwks_cache
\`\`\`

## Migration from Standard JWT Plugin

### Configuration Mapping

| Standard JWT | JWT-JWKS | Notes |
|--------------|----------|-------|
| `secret_is_base64` | N/A | Not needed with JWKS |
| `key_claim_name` | `key_claim_name` | Same parameter |
| `claims_to_verify` | `claims_to_verify` | Same parameter |
| `maximum_expiration` | N/A | Use `max_token_age` |

### Migration Steps

1. **Backup Configuration**: Export current JWT plugin configuration
2. **Install Plugin**: Install jwt-jwks plugin
3. **Update Configuration**: Convert configuration to jwt-jwks format
4. **Test Thoroughly**: Verify JWT validation works correctly
5. **Switch Plugins**: Replace jwt plugin with jwt-jwks
6. **Monitor**: Watch logs and metrics for issues

## Development

### Building from Source

\`\`\`bash
git clone https://github.com/your-org/kong-plugin-jwt-jwks.git
cd kong-plugin-jwt-jwks
luarocks make
\`\`\`

### Running Tests

\`\`\`bash
busted spec/
\`\`\`

### Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Submit a pull request

## License

This plugin is licensed under the Apache License 2.0. See LICENSE file for details.

## Support

For issues and questions:

- GitHub Issues: https://github.com/your-org/kong-plugin-jwt-jwks/issues
- Documentation: https://docs.your-org.com/kong-jwt-jwks
- Community Forum: https://discuss.konghq.com
\`\`\`

```rockspec file="kong-plugin-jwt-jwks-1.0.0-1.rockspec"
package = "kong-plugin-jwt-jwks"
version = "1.0.0-1"
supported_platforms = {"linux", "macosx"}

source = {
  url = "git://github.com/your-org/kong-plugin-jwt-jwks",
  tag = "1.0.0"
}

description = {
  summary = "Kong Gateway plugin for JWT authentication with JWKS support",
  detailed = [[
    A Kong Gateway plugin that extends JWT authentication with JWKS (JSON Web Key Set) 
    support, enabling dynamic public key fetching and automatic key rotation.
  ]],
  homepage = "https://github.com/your-org/kong-plugin-jwt-jwks",
  license = "Apache 2.0"
}

dependencies = {
  "lua >= 5.1",
  "lua-resty-http >= 0.16",
  "lua-resty-jwt >= 0.2.0",
  "lua-cjson >= 2.1.0"
}

build = {
  type = "builtin",
  modules = {
    ["kong.plugins.jwt-jwks.handler"] = "handler.lua",
    ["kong.plugins.jwt-jwks.schema"] = "schema.lua",
    ["kong.plugins.jwt-jwks.jwks_client"] = "jwks_client.lua",
    ["kong.plugins.jwt-jwks.jwt_validator"] = "jwt_validator.lua",
    ["kong.plugins.jwt-jwks.cache_manager"] = "cache_manager.lua"
  }
}
