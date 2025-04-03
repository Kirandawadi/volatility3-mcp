import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

from volatility3 import framework, plugins
from volatility3.framework import contexts


class VolatilityWrapper:
    def __init__(self, memory_file: str):
        """Initialize the Volatility3 wrapper with a memory dump file."""
        self.memory_file = Path(memory_file)
        if not self.memory_file.exists():
            raise FileNotFoundError(f"Memory file not found: {memory_file}")

        # Initialize the volatility context
        self.context = contexts.Context()
        # Import all plugins to ensure they're registered
        framework.import_files(plugins, True)
        self.available_plugins_with_descriptions = (
            self._list_plugins_with_descriptions()
        )
        self.available_plugins = list(framework.list_plugins().keys())
        self.os_type = None

    def _sanitize_description(self, description):
        """Sanitize the description by removing newlines and escaping quotes."""
        if not description:
            return "No description available"

        sanitized = description.replace("\n", " ")
        sanitized = " ".join(sanitized.split())
        return sanitized

    def _list_plugins_with_descriptions(self):
        """Get a dictionary of available plugins and their descriptions."""
        plugins_with_descriptions = {}
        plugin_list = framework.list_plugins()
        for plugin_name in sorted(plugin_list.keys()):
            plugin_class = plugin_list[plugin_name]

            description = "No description available"
            if plugin_class.__doc__:
                description = plugin_class.__doc__
                plugins_with_descriptions[plugin_name] = self._sanitize_description(
                    description
                )

        return plugins_with_descriptions

    def get_plugin_info(self, plugin_name: str) -> dict[str, Any]:
        """Get detailed information about a specific plugin."""
        if plugin_name not in self.available_plugins:
            return {"error": f"Plugin {plugin_name} not found"}

        return self.available_plugins_with_descriptions[plugin_name]

    def detect_os(self) -> str:
        """Detect OS type from which the memory dump was taken"""
        os_checks = {"windows": "windows.info.Info", "linux": "banners.Banners"}

        for os_type, plugin in os_checks.items():
            try:
                result = self.run_plugin(plugin_name=plugin)
                if os_type in json.dumps(result).lower():
                    self.os_type = os_type
                    return os_type
            except Exception as e:
                print(f"Error checking for {os_type}: {str(e)}")
                continue

        self.os_type = "unknown"
        return "unknown"

    def run_plugin(
        self, plugin_name: str, args: dict[str, Any] | None = None
    ) -> list[dict[str, Any]]:
        """Run a Volatility3 plugin and return the results as structured data.

        Args:
            plugin_name: Name of the plugin to run (e.g., 'windows.pslist.PsList')

        Returns:
            List of dictionaries containing the plugin results
        """
        if args is None:
            args = {}

        if plugin_name not in self.available_plugins:
            return [{"error": f"Plugin {plugin_name} not found"}]

        try:
            # Find path to vol dynamically
            os.environ["PATH"] = (
                sys.executable.split("/python3")[0] + ":" + os.environ["PATH"]
            )
            vol_path = shutil.which("vol")
            if not vol_path:
                return [{"error": "Could not find 'vol' executable in PATH"}]

            cmd = [vol_path, "-r", "json", "-f", str(self.memory_file), plugin_name]

            # Add any additional arguments
            for arg_name, arg_value in args.items():
                if arg_value is True:
                    cmd.append(f"--{arg_name}")
                elif arg_value is not False and arg_value is not None:
                    cmd.append(f"--{arg_name}")
                    cmd.append(str(arg_value))

            result = subprocess.run(cmd, capture_output=True, text=True, check=False)

            # Check for errors
            if result.returncode != 0:
                return [{"error": f"Plugin execution failed: {result.stderr}"}]

            try:
                return json.loads(result.stdout)
            except json.JSONDecodeError:
                # If JSON parsing fails, return the raw output
                return [
                    {
                        "error": "Failed to parse JSON output",
                        "raw_output": result.stdout,
                    }
                ]

        except Exception as e:
            return [{"error": f"Error running plugin {plugin_name}: {str(e)}"}]

    def get_processes(self) -> list[dict[str, Any]]:
        """Get a list of processes from the memory dump."""
        if not hasattr(self, "os_type") or self.os_type is None:
            self.detect_os()

        if self.os_type == "windows":
            return self.run_plugin("windows.pslist.PsList")
        elif self.os_type == "linux":
            return self.run_plugin("linux.pslist.PsList")
        else:
            return [
                {"error": f"Process listing not supported for OS type: {self.os_type}"}
            ]

    def get_network_connections(self) -> list[dict[str, Any]]:
        """Get network connections from the memory dump."""
        if not hasattr(self, "os_type") or self.os_type is None:
            self.detect_os()

        if self.os_type == "windows":
            return self.run_plugin("windows.netscan.NetScan")
        elif self.os_type == "linux":
            return self.run_plugin("linux.sockstat.Sockstat")
        else:
            return [
                {
                    "error": f"Network connection listing not supported for OS type: {self.os_type}"
                }
            ]

    def list_process_open_handles(self, pid: int) -> dict[str, Any]:
        "Lists open handles for a process"
        if not hasattr(self, "os_type") or self.os_type is None:
            self.detect_os()

        args = {"pid": pid}

        if self.os_type == "windows":
            return self.run_plugin("windows.handles.Handles", args)
        elif self.os_type == "linux":
            return self.run_plugin("linux.lsof.Lsof", args)
        else:
            return [
                {
                    "error": f"Listing process open handles not supported for OS type: {self.os_type}"
                }
            ]

    def scan_with_yara(self) -> list[dict[str, Any]]:
        """Scan memory with YARA rules.

        Returns:
            List of matches with process, rule information, and full rule definition
        """
        current_dir = os.path.dirname(os.path.abspath(__file__))
        yara_file = os.path.join(current_dir, "malware_rules.yar")
        if not os.path.exists(yara_file):
            return [{"error": f"YARA rules file not found: {yara_file}"}]

        if not hasattr(self, "os_type") or self.os_type is None:
            self.detect_os()

        # Use yarascan.YaraScan for both Windows and Linux
        plugin_name = "yarascan.YaraScan"
        args = {"yara-file": yara_file}

        results = self.run_plugin(plugin_name, args)
        # Return top 10 scan results only because this might overwhelm the MCP Client
        results = results[:10]

        # If we have results, enhance them with the full rule definitions
        if results and not (
            isinstance(results, list) and len(results) > 0 and "error" in results[0]
        ):
            # Look for the index file
            index_file = os.path.join(
                os.path.dirname(yara_file), "malware_rules_index.json"
            )

            if os.path.exists(index_file):
                try:
                    with open(index_file) as f:
                        rule_index = json.load(f)

                    # Add rule definitions to the results
                    for match in results:
                        if "Rule" in match and match["Rule"] in rule_index:
                            match["rule_definition"] = rule_index[match["Rule"]]
                except Exception as e:
                    print(f"Error loading rule index: {str(e)}")

        return results


def main():
    memory_file = (
        "/Users/dkiran/Documents/MCP/volatility3-mcp/memory_dump/linux-sample.mem"
    )
    vol_wrapper = VolatilityWrapper(memory_file)
    print(vol_wrapper.detect_os())
    print(vol_wrapper.os_type)
    print(vol_wrapper.scan_with_yara())


if __name__ == "__main__":
    main()
