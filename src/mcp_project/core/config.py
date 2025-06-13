from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import AnyHttpUrl, BaseModel, Field, computed_field

from .enums import EnvironmentOption, ServerTransportOptions

class Server(BaseModel):
    name: str = Field(default="MCP Server")
    instructions: str = Field(default="MCP Server Project Template")
    transport: ServerTransportOptions = Field(default=ServerTransportOptions.STDIO)
    scope: str = Field(default="user")
    host: str = "localhost"
    port: int = 8000
    url: AnyHttpUrl = AnyHttpUrl("http://localhost:8000")

class Github(BaseModel):
    # GitHub OAuth settings - MUST be provided via environment variables
    client_id: str = Field(default="")
    client_secret: str = Field(default="")
    callback_path: str = Field(default="http://localhost:8000/github/callback")

    # GitHub OAuth URLs
    auth_url: str = Field(default="https://github.com/login/oauth/authorize")
    token_url: str = Field(default="https://github.com/login/oauth/access_token")
    scope: str = Field(default="read:user")


class Settings(BaseSettings):
    # Server settings
    server: Server = Server()
    
    # Debug settings
    debug: bool = Field(default=False)
    
    # Environment settings
    environment: EnvironmentOption = Field(default=EnvironmentOption.LOCAL)

    # GitHub OAuth settings
    github: Github = Github()

    model_config = SettingsConfigDict(env_file='.env', env_file_encoding='utf-8', env_nested_delimiter='__')


settings = Settings()