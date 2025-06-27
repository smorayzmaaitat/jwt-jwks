local JwtJwksHandler = require "kong.plugins.jwt-jwks.handler"
local api = require "kong.plugins.jwt-jwks.api"

return {
  name     = "jwt-jwks",
  VERSION  = JwtJwksHandler.VERSION,
  PRIORITY = JwtJwksHandler.PRIORITY,
  handler  = JwtJwksHandler,
  api      = api,
}
