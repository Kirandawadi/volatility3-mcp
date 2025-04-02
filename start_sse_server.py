from mcp.server.fastmcp import FastMCP
from starlette.applications import Starlette
from mcp.server.sse import SseServerTransport
from starlette.requests import Request
from starlette.routing import Mount, Route
from mcp.server import Server
import uvicorn
import argparse
import os
from bridge_mcp_volatility import mcp

def create_starlette_app(mcp_server: Server, *, debug: bool = False) -> Starlette:
    """Create a Starlette application that can serve the provided mcp server with SSE."""
    sse = SseServerTransport("/messages/")

    async def handle_sse(request: Request) -> None:
        async with sse.connect_sse(
                request.scope,
                request.receive,
                request._send,
        ) as (read_stream, write_stream):
            await mcp_server.run(
                read_stream,
                write_stream,
                mcp_server.create_initialization_options(),
            )

    return Starlette(
        debug=debug,
        routes=[
            Route("/sse", endpoint=handle_sse),
            Mount("/messages/", app=sse.handle_post_message),
        ],
    )

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Run Volatility3 MCP SSE-based server')
    parser.add_argument('--host', default='127.0.0.1', help='Host to bind to')
    parser.add_argument('--port', type=int, default=8080, help='Port to listen on')
    parser.add_argument('--debug', action='store_true', help='Enable debug mode')
    args = parser.parse_args()

    mcp_server = mcp._mcp_server

    # Create the Starlette app with SSE support
    starlette_app = create_starlette_app(mcp_server, debug=args.debug)

    # Print the SSE URL for Cursor to connect to
    sse_url = f"http://{args.host}:{args.port}/sse"
    print(f"\n=== Volatility3 MCP Server ===")
    print(f"Server running at: http://{args.host}:{args.port}")
    print(f"SSE URL for Cursor: {sse_url}")
    print(f"Copy this URL into Cursor's MCP configuration")
    print(f"==============================\n")

    # Run the server
    uvicorn.run(starlette_app, host=args.host, port=args.port) 