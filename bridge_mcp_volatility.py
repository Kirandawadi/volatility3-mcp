from typing import Any

from mcp.server.fastmcp import FastMCP
from vol_wrapper import VolatilityWrapper

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
        return "Could not determine the operating system. The memory dump may be corrupted or from an unsupported OS."
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
def list_plugins() -> list[str]:
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
    plugin_name: str, args: dict[str, Any] | None = None
) -> list[dict[str, Any]]:
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


@mcp.tool(
    description="""Get a comprehensive list of all processes from the memory dump. This tool should be used when:
    - You need to identify running processes at the time of memory capture
    - You're looking for suspicious or unexpected processes
    - You need process IDs for further analysis of specific processes
    - You want to establish a baseline of system activity
    The tool returns detailed information about each process including name, PID, PPID, start time,
    and memory information. This is often one of the first analyses to perform when investigating
    a memory dump to understand what was running on the system."""
)
def get_processes() -> list[dict[str, Any]]:
    """
    Get a list of processes from the memory dump.

    Returns:
        List of processes with details
    """
    if vol_wrapper is None:
        return [
            {"error": "Volatility3 not initialized. Call initialize_memory_file first."}
        ]

    return vol_wrapper.get_processes()


@mcp.tool(
    description="""Retrieve all network connections from the memory dump. Use this tool when:
    - You're investigating potential command and control (C2) communications
    - You need to identify data exfiltration or unauthorized connections
    - You want to map process-to-network activity
    - You're looking for suspicious IPs, ports, or connection states
    The tool returns comprehensive information about each connection including local/remote addresses,
    ports, connection state, and the associated process. This is crucial for identifying malicious
    network activity and understanding how processes were communicating externally."""
)
def get_network_connections() -> list[dict[str, Any]]:
    """
    Get network connections from the memory dump.

    Returns:
        List of network connections with details
    """
    if vol_wrapper is None:
        return [
            {"error": "Volatility3 not initialized. Call initialize_memory_file first."}
        ]

    return vol_wrapper.get_network_connections()


@mcp.tool(
    description="""List open handles for a specific process. Use this tool when:
    - You need to investigate which files, registry keys, or other resources a process has open
    - You're analyzing potential data exfiltration by examining file handles
    - You want to understand inter-process communication by examining shared handles
    - You're investigating malware behavior by examining its interaction with system resources
    - You need to determine if a process has access to sensitive system objects

    This tool works differently depending on the operating system:
    - On Windows: Lists file handles, registry keys, mutexes, events, and other Windows-specific objects
    - On Linux: Lists open files, sockets, pipes, and other file descriptors

    The output provides detailed information about each handle, including its type, permissions, and the
    object it references. This can be crucial for understanding process behavior and identifying suspicious activity."""
)
def list_process_open_handles(pid: int) -> dict[str, Any]:
    """
    List all open handles for a specific process.

    Args:
        pid: Process ID to list handles for

    Returns:
        Dictionary containing handle information for the specified process
    """
    if vol_wrapper is None:
        return {
            "error": "Volatility3 not initialized. Call initialize_memory_file first."
        }

    try:
        pid_int = int(pid)
    except ValueError:
        return {"error": "Invalid PID format. PID must be an integer."}

    return vol_wrapper.list_process_open_handles(pid_int)


@mcp.tool(
    description="""Scan memory with YARA rules to detect malware signatures. This tool should be used when:
    - You need to identify known malware patterns in memory
    - You want to check for specific threat indicators
    - You're investigating potential compromise using signature-based detection
    - You have custom YARA rules for specific threats you're hunting
    Results include detailed match information with process context and rule metadata.
    This scanning usually takes a lot of time because we are scanning with extensive Yara rules list"""
)
def scan_with_yara() -> list[dict[str, Any]]:
    """
    Scan memory with YARA rules to detect malware signatures.

    Returns:
        List of matches with process and rule information
    """
    if vol_wrapper is None:
        return [
            {"error": "Volatility3 not initialized. Call initialize_memory_file first."}
        ]

    results = vol_wrapper.scan_with_yara()

    if not results:
        return {"message": "No malware detected", "matches": []}
    return results


if __name__ == "__main__":
    mcp.run()
