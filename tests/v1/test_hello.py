import pytest
from fastmcp import Client
from mcp_project import mcp_server

@pytest.mark.asyncio
async def test_hello_say_hello():
    async with Client(mcp_server) as _client:
        result = await _client.call_tool("v1_hello_say_hello", {"name": "World"})
        assert result[0].text == "Hello, World!"