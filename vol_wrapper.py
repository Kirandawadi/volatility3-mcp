import sys
import io
import json
from typing import List, Dict, Any, Optional
import contextlib
from pathlib import Path
import os
import subprocess
import yara
import tempfile
import time
import inspect
import shutil

# Import Volatility3
import volatility3
from volatility3.cli import text_renderer
from volatility3.framework import contexts, automagic, interfaces, plugins
import volatility3.framework
from volatility3.framework.configuration import requirements
from volatility3 import framework


class VolatilityWrapper:
    def __init__(self, memory_file: str):
        """Initialize the Volatility3 wrapper with a memory dump file."""
        self.memory_file = Path(memory_file)
        if not self.memory_file.exists():
            raise FileNotFoundError(f"Memory file not found: {memory_file}")

        # Initialize the volatility context
        self.context = contexts.Context()
        # Import all plugins to ensure they're registered
        framework.import_files(volatility3.plugins, True)
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

    def get_plugin_info(self, plugin_name: str) -> Dict[str, Any]:
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
        self, plugin_name: str, args: Optional[Dict[str, Any]] = None
    ) -> List[Dict[str, Any]]:
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

            print(f"Running command: {' '.join(cmd)}")
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
                        "error": f"Failed to parse JSON output",
                        "raw_output": result.stdout,
                    }
                ]

        except Exception as e:
            return [{"error": f"Error running plugin {plugin_name}: {str(e)}"}]

    def get_processes(self) -> List[Dict[str, Any]]:
        """Get a list of processes from the memory dump."""
        return self.run_plugin("windows.pslist.PsList")

    def get_network_connections(self) -> List[Dict[str, Any]]:
        """Get network connections from the memory dump."""
        return self.run_plugin("windows.netscan.NetScan")

    def get_loaded_modules(self, pid: Optional[int] = None) -> List[Dict[str, Any]]:
        """Get loaded modules, optionally filtered by process ID."""
        args = {}
        if pid is not None:
            args["pid"] = pid
        return self.run_plugin("windows.modules.Modules", args)

    def search_memory(
        self, pattern: str, case_sensitive: bool = False
    ) -> List[Dict[str, Any]]:
        """Search memory for a specific pattern."""
        args = {"pattern": pattern, "case_sensitive": case_sensitive}
        return self.run_plugin("windows.vadyarascan.VadYaraScan", args)

    def dump_process_memory(self, pid: int, output_dir: str) -> Dict[str, Any]:
        """Dump a process's memory to disk."""
        args = {"pid": pid, "dump_dir": output_dir}
        return self.run_plugin("windows.memmap.Memmap", args)

    def scan_with_yara(
        self, yara_file: str, scan_all: bool = False
    ) -> List[Dict[str, Any]]:
        """Scan memory with YARA rules.

        Args:
            yara_file: Path to the YARA rules file
            scan_all: If True, scan all memory; if False, scan only process memory

        Returns:
            List of matches with process and rule information
        """
        if not os.path.exists(yara_file):
            return [{"error": f"YARA rules file not found: {yara_file}"}]

        plugin_name = (
            "yarascan.YaraScan" if scan_all else "windows.vadyarascan.VadYaraScan"
        )
        args = {"yara_file": yara_file}

        return self.run_plugin(plugin_name, args)

    def download_yara_rules(self, output_dir: str = "rules") -> str:
        """Download and merge YARA malware rules from various GitHub repositories.

        Args:
            output_dir: Directory to save the rules

        Returns:
            Path to the merged rules file
        """
        try:
            # Create the output directory if it doesn't exist
            os.makedirs(output_dir, exist_ok=True)

            # Download the script to merge YARA rules
            script_url = "https://gist.githubusercontent.com/andreafortuna/29c6ea48adf3d45a979a78763cdc7ce9/raw/4ec711d37f1b428b63bed1f786b26a0654aa2f31/malware_yara_rules.py"
            script_path = os.path.join(output_dir, "malware_yara_rules.py")

            subprocess.run(["wget", script_url, "-O", script_path], check=True)

            # Run the script to download and merge rules
            subprocess.run(["python", script_path], cwd=output_dir, check=True)

            # Return the path to the merged rules file
            rules_file = os.path.join(output_dir, "malware_rules.yar")
            if os.path.exists(rules_file):
                return rules_file
            else:
                return f"Error: Rules file not created in {output_dir}"

        except Exception as e:
            return f"Error downloading YARA rules: {str(e)}"

    def compile_custom_yara_rule(
        self, rule_content: str, output_file: str = None
    ) -> str:
        """Compile a custom YARA rule provided as a string.

        Args:
            rule_content: The YARA rule content as a string
            output_file: Optional path to save the compiled rule

        Returns:
            Path to the compiled rule file or error message
        """
        try:
            # Validate the rule by compiling it
            # yara.compile(source=rule_content)

            # Save to file if requested
            if output_file:
                with open(output_file, "w") as f:
                    f.write(rule_content)
                return output_file

            # Otherwise create a temporary file
            temp_file = os.path.join(
                tempfile.gettempdir(), f"custom_rule_{int(time.time())}.yar"
            )
            with open(temp_file, "w") as f:
                f.write(rule_content)
            return temp_file

        except Exception as e:
            return f"Error compiling YARA rule: {str(e)}"


def main():
    memory_file = (
        "/Users/dkiran/Documents/MCP/volatility3-mcp/memory_dump/linux-sample-1.bin"
    )
    vol_wrapper = VolatilityWrapper(memory_file)
    print(vol_wrapper.detect_os())


if __name__ == "__main__":
    main()
