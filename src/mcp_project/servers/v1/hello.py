from fastmcp import FastMCP

hello_mcp = FastMCP(name="hello", instructions="This server provides as simple hello functionality.")

@hello_mcp.tool()
async def say_hello(name: str) -> str:
    """
    Say hello to the user.
    """
    return f"Hello, {name}!"
