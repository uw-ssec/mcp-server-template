# mcp-template
MCP Server Template

## Development

0. Install dependencies

    ```
    pixi install
    ```

1. Start MCP Inspector in a terminal

    ```
    pixi run npx @modelcontextprotocol/inspector
    ```

2. Start the MCP Server in a separate terminal

    ```
    pixi run python -m mcp_project
    ```

Run tests with `pytest`

```
pixi run -e dev pytest
```
