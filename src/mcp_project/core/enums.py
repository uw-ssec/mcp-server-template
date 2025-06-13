from enum import Enum

class ServerTransportOptions(Enum):
    STDIO = "stdio"
    SSE = "sse"
    STREAMHTTP = "streamable-http"

class EnvironmentOption(Enum):
    LOCAL = "local"
    STAGING = "staging"
    PRODUCTION = "production"