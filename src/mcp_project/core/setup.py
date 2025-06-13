from .server import MCPServer
from .config import Settings


def create_mcp_server(settings: Settings, **kwargs) -> MCPServer:
    """
    Create and configure the MCP server.
    """
    mcp_server = MCPServer(settings, **kwargs)
    return mcp_server