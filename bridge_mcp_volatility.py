from mcp.server.fastmcp import FastMCP
from vol_wrapper import VolatilityWrapper
from typing import List, Dict, Any, Optional
import os
import tempfile
import time

mcp = FastMCP("volatility3-mcp")

# Global volatility wrapper instance
vol_wrapper = None


@mcp.tool(
    description="""Initialize Volatility3 with a memory dump file. This tool MUST be called first before any other 
    memory analysis tools. Use this tool when:
    - You're starting a new memory forensics investigation
    - You want to switch to analyzing a different memory dump
    - You need to reset the analysis environment
    The tool accepts a file path to the memory dump and validates that the file exists and is accessible.
    Successful initialization is required for all other tools to function properly."""
)
def initialize_memory_file(file_path: str) -> str:
    """
    Initialize the Volatility3 wrapper with a memory dump file.

    Args:
        file_path: Path to the memory dump file

    Returns:
        Success or error message
    """
    global vol_wrapper
    try:
        vol_wrapper = VolatilityWrapper(file_path)
        return f"Successfully initialized Volatility3 with memory file: {file_path}"
    except Exception as e:
        return f"Error initializing Volatility3: {str(e)}"


@mcp.tool(
    description="""Detect the operating system type from the memory dump. Use this tool when:
    - You need to identify the OS of the memory dump before further analysis
    - You want to determine which OS-specific plugins are applicable
    - You're starting an investigation and need to establish the basic system information
    - You need to verify the OS type to select appropriate analysis techniques
    The tool attempts to identify if the memory dump is from Windows or Linux by
    running OS-specific plugins and analyzing their output. This information is crucial for
    selecting the appropriate analysis plugins and interpreting the results correctly."""
)
def detect_os() -> str:
    """
    Detect the operating system type from the memory dump.

    Returns:
        String indicating the OS type: 'windows', 'linux', or 'unknown'
    """
    if vol_wrapper is None:
        return "Error: Volatility3 not initialized. Call initialize_memory_file first."

    os_type = vol_wrapper.detect_os()

    if os_type == "unknown":
        return "Could not definitively determine the operating system. The memory dump may be corrupted or from an unsupported OS."
    else:
        return f"Detected operating system: {os_type.capitalize()}"


@mcp.tool(
    description="""List all available Volatility3 plugins that can be used for memory analysis. Use this tool when:
    - You want to explore what analysis capabilities are available
    - You need to find a specific plugin for a particular analysis task
    - You're unsure which plugin to use for a specific investigation goal
    The tool returns a comprehensive list of plugin names that can be used with the run_plugin tool.
    This is useful for discovering available analysis options before diving into specific analyses."""
)
def list_plugins() -> List[str]:
    """
    List all available Volatility3 plugins.

    Returns:
        List of plugin names
    """
    if vol_wrapper is None:
        return [
            "Error: Volatility3 not initialized. Call initialize_memory_file first."
        ]

    return vol_wrapper.available_plugins


@mcp.tool(
    description="""Get detailed information about a specific Volatility3 plugin. Use this tool when:
    - You need to understand what a plugin does before using it
    - You want to learn about the requirements and parameters for a plugin
    - You're deciding which plugin is most appropriate for your analysis needs
    The tool provides the plugin's description and required parameters, helping you understand
    its purpose and how to use it effectively in your investigation."""
)
def get_plugin_info(plugin_name: str) -> str:
    """
    Get detailed information about a specific plugin.

    Args:
        plugin_name: Name of the plugin

    Returns:
        Plugin information including description and requirements
    """
    if vol_wrapper is None:
        return {
            "error": "Volatility3 not initialized. Call initialize_memory_file first."
        }

    return vol_wrapper.get_plugin_info(plugin_name)


@mcp.tool(
    description="""Run any Volatility3 plugin with custom arguments. This is the most flexible analysis tool that
    gives you access to the full range of Volatility3 capabilities. Use this tool when:
    - You need to run a specific plugin not covered by the specialized tools
    - You want to provide custom arguments to a plugin
    - You're performing advanced analysis that requires specific plugin configurations
    - You need access to plugins that don't have dedicated wrapper functions
    The tool accepts the plugin name and an optional dictionary of arguments specific to that plugin.
    Results are returned as structured data that can be further analyzed and interpreted."""
)
def run_plugin(
    plugin_name: str, args: Optional[Dict[str, Any]] = None
) -> List[Dict[str, Any]]:
    """
    Run a Volatility3 plugin with optional arguments.

    Args:
        plugin_name: Name of the plugin to run
        args: Optional dictionary of plugin arguments

    Returns:
        Plugin results as structured data
    """
    if vol_wrapper is None:
        return [
            {"error": "Volatility3 not initialized. Call initialize_memory_file first."}
        ]

    return vol_wrapper.run_plugin(plugin_name, args)



if __name__ == "__main__":
    mcp.run()
