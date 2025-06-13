from fastmcp import FastMCP

from .hello import hello_mcp

v1_mcp = FastMCP(name="v1", instructions="This is the version 1 collections MCP servers.")

v1_mcp.mount("hello", hello_mcp)
