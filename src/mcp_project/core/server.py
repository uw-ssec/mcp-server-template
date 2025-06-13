from typing import Any
from starlette.exceptions import HTTPException
from starlette.requests import Request
from starlette.responses import JSONResponse, RedirectResponse, Response
from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.settings import AuthSettings, ClientRegistrationOptions
from mcp.shared._httpx_utils import create_mcp_http_client

from ..servers import v1_mcp
from .config import Settings
from .enums import EnvironmentOption, ServerTransportOptions
from .auth.github import GitHubOAuthProvider, get_github_token
from .logger import logging

logger = logging.getLogger(__name__)

class MCPServer:
    def __init__(self, settings: Settings, **kwargs):
        self.settings = settings
        self.kwargs = kwargs
        self._oauth_provider = None
        self._auth_settings = None

        # Initialize the OAuth provider
        if self.settings.environment == EnvironmentOption.PRODUCTION:
            self._oauth_provider = GitHubOAuthProvider(self.settings)
            self._auth_settings = AuthSettings(
                issuer_url=self.settings.server.url,
                client_registration_options=ClientRegistrationOptions(
                    enabled=True,
                    valid_scopes=[self.settings.server.scope],
                    default_scopes=[self.settings.server.scope],
                ),
                required_scopes=[self.settings.server.scope],
            )

        self.mcp_server = self._create_mcp_server()

        if self.settings.environment == EnvironmentOption.PRODUCTION:
            # Add the callback route for GitHub OAuth
            self.__add_callback_route()
            self.__add_user_info_tool()

    
    def __add_user_info_tool(self):
        """
        Add user info tool to the MCP server.
        """
        @self.mcp_server.tool()
        async def get_user_profile() -> dict[str, Any]:
            """Get the authenticated user's GitHub profile information.

            This is the only tool in our simple example. It requires the 'user' scope.
            """
            github_token = get_github_token(self._oauth_provider)

            async with create_mcp_http_client() as client:
                response = await client.get(
                    "https://api.github.com/user",
                    headers={
                        "Authorization": f"Bearer {github_token}",
                        "Accept": "application/vnd.github.v3+json",
                    },
                )

                if response.status_code != 200:
                    raise ValueError(
                        f"GitHub API error: {response.status_code} - {response.text}"
                    )

                return response.json()
    
    def __add_callback_route(self):
        if self.settings.environment == EnvironmentOption.PRODUCTION:
            # TODO: Make this a generic callback route
            @self.mcp_server.custom_route("/github/callback", methods=["GET"])
            async def github_callback_handler(request: Request) -> Response:
                """Handle GitHub OAuth callback."""
                code = request.query_params.get("code")
                state = request.query_params.get("state")

                if not code or not state:
                    raise HTTPException(400, "Missing code or state parameter")

                try:
                    redirect_uri = await self._oauth_provider.handle_github_callback(code, state)
                    return RedirectResponse(status_code=302, url=redirect_uri)
                except HTTPException:
                    raise
                except Exception as e:
                    logger.error("Unexpected error", exc_info=e)
                    return JSONResponse(
                        status_code=500,
                        content={
                            "error": "server_error",
                            "error_description": "Unexpected error",
                        },
                    )

    def _create_mcp_server(self):
        """
        Create and configure the MCP server.
        """
        from fastmcp import FastMCP

        if isinstance(self.settings, Settings):
            to_update = {
                "name": self.settings.server.name,
                "instructions": self.settings.server.instructions,
                "debug": self.settings.debug,
                "host": self.settings.server.host,
                "port": self.settings.server.port,
            }
            self.kwargs.update(to_update)

            if self.settings.environment == EnvironmentOption.PRODUCTION:
                # Enforce Auth Middleware in PRODUCTION
                self.kwargs.update({
                    "auth": self._auth_settings,
                    "auth_server_provider": self._oauth_provider,
                })

        mcp_server = FastMCP(**self.kwargs)
        mcp_server.mount("v1", v1_mcp)

        return mcp_server

    async def serve(self):
        """
        Start the MCP server.
        """
        if isinstance(self.settings, Settings):
            if self.settings.environment == EnvironmentOption.PRODUCTION:
                transport = ServerTransportOptions.STREAMHTTP.value
            else:
                transport = self.settings.server.transport.value
            # Use serve() in async contexts
            await self.mcp_server.run_async(transport=transport)
