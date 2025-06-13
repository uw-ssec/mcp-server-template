from .core.setup import create_mcp_server
from .core.config import settings

mcp_server = create_mcp_server(settings=settings, name="mcp-project", instructions="This is the main MCP server for the project.")

def main():
    import asyncio
    asyncio.run(mcp_server.serve())

if __name__ == "__main__":
    main()