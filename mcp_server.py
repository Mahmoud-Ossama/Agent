"""
MCP Server for AI-Powered Penetration Testing
This implements the Model Context Protocol for penetration testing tools
"""

import asyncio
import json
import logging
import subprocess
import os
import time
from typing import Any, Dict, List, Optional, Union
from datetime import datetime

# MCP Server implementation
class MCPServer:
    def __init__(self):
        self.name = "pentest-mcp-server"
        self.version = "1.0.0"
        self.description = "MCP Server for AI-Powered Penetration Testing"
        self.tools = self._register_tools()
        self.resources = self._register_resources()
        self.prompts = self._register_prompts()
        self.results_dir = "results"
        self.memory_file = os.path.join(self.results_dir, "mcp_memory.json")
        self.setup_logging()
        self.ensure_directories()

    def setup_logging(self):
        """Setup logging for the MCP server"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('mcp_server.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)

    def ensure_directories(self):
        """Create necessary directories"""
        os.makedirs(self.results_dir, exist_ok=True)

    def _register_tools(self) -> List[Dict[str, Any]]:
        """Register all available tools for the MCP server"""
        return [
            {
                "name": "nmap_scan",
                "description": "Perform network mapping and port scanning using nmap",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "target": {"type": "string", "description": "Target IP or hostname"},
                        "scan_type": {"type": "string", "enum": ["basic", "service", "aggressive"], "default": "basic"},
                        "ports": {"type": "string", "description": "Port range (optional)"}
                    },
                    "required": ["target"]
                }
            },
            {
                "name": "sqlmap_test",
                "description": "Test for SQL injection vulnerabilities using sqlmap",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "url": {"type": "string", "description": "Target URL to test"},
                        "parameter": {"type": "string", "description": "Parameter to test (optional)"},
                        "level": {"type": "integer", "minimum": 1, "maximum": 5, "default": 1},
                        "risk": {"type": "integer", "minimum": 1, "maximum": 3, "default": 1}
                    },
                    "required": ["url"]
                }
            },
            {
                "name": "web_scan",
                "description": "Scan web application for vulnerabilities using nikto",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "target": {"type": "string", "description": "Target URL"},
                        "timeout": {"type": "integer", "default": 300}
                    },
                    "required": ["target"]
                }
            },
            {
                "name": "directory_bruteforce",
                "description": "Brute force directories and files using dirb or gobuster",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "target": {"type": "string", "description": "Target URL"},
                        "wordlist": {"type": "string", "description": "Wordlist to use (optional)"},
                        "extensions": {"type": "string", "description": "File extensions to search for"}
                    },
                    "required": ["target"]
                }
            },
            {
                "name": "technology_detection",
                "description": "Detect web technologies using whatweb",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "target": {"type": "string", "description": "Target URL"},
                        "verbosity": {"type": "integer", "minimum": 1, "maximum": 3, "default": 1}
                    },
                    "required": ["target"]
                }
            },
            {
                "name": "save_findings",
                "description": "Save penetration testing findings to memory",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "findings": {"type": "string", "description": "Findings to save"},
                        "category": {"type": "string", "enum": ["reconnaissance", "enumeration", "vulnerability", "exploitation"]},
                        "severity": {"type": "string", "enum": ["info", "low", "medium", "high", "critical"]}
                    },
                    "required": ["findings", "category"]
                }
            },
            {
                "name": "get_memory",
                "description": "Retrieve stored penetration testing findings",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "category": {"type": "string", "description": "Filter by category (optional)"},
                        "limit": {"type": "integer", "default": 10}
                    }
                }
            },
            {
                "name": "generate_report",
                "description": "Generate a comprehensive penetration testing report",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "target": {"type": "string", "description": "Target that was tested"},
                        "format": {"type": "string", "enum": ["markdown", "json", "html"], "default": "markdown"}
                    },
                    "required": ["target"]
                }
            },
            {
                "name": "custom_command",
                "description": "Execute a custom penetration testing command (restricted to safe tools)",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "command": {"type": "string", "description": "Command to execute"},
                        "timeout": {"type": "integer", "default": 300}
                    },
                    "required": ["command"]
                }
            }
        ]

    def _register_resources(self) -> List[Dict[str, Any]]:
        """Register resources that can be accessed"""
        return [
            {
                "uri": "pentest://findings",
                "name": "Penetration Test Findings",
                "description": "Current penetration testing findings and results"
            },
            {
                "uri": "pentest://memory",
                "name": "Testing Memory",
                "description": "Persistent memory of testing activities"
            },
            {
                "uri": "pentest://tools",
                "name": "Available Tools",
                "description": "List of available penetration testing tools"
            }
        ]

    def _register_prompts(self) -> List[Dict[str, Any]]:
        """Register prompt templates"""
        return [
            {
                "name": "pentest_strategy",
                "description": "Generate a penetration testing strategy",
                "arguments": [
                    {
                        "name": "target",
                        "description": "Target to test",
                        "required": True
                    },
                    {
                        "name": "scope",
                        "description": "Testing scope",
                        "required": False
                    }
                ]
            },
            {
                "name": "vulnerability_analysis",
                "description": "Analyze discovered vulnerabilities",
                "arguments": [
                    {
                        "name": "findings",
                        "description": "Raw findings to analyze",
                        "required": True
                    }
                ]
            }
        ]

    def is_safe_command(self, command: str) -> bool:
        """Validate that a command is safe to execute"""
        safe_tools = [
            'nmap', 'sqlmap', 'nikto', 'dirb', 'gobuster', 'whatweb',
            'curl', 'wget', 'dig', 'host', 'whois', 'ping', 'traceroute',
            'wfuzz', 'ffuf', 'enum4linux', 'smbclient', 'masscan'
        ]
        
        dangerous_patterns = [
            'rm ', 'del ', 'format', 'fdisk', 'mkfs', 'dd ',
            'shutdown', 'reboot', 'halt', 'poweroff', 'init ',
            'kill', 'killall', 'su ', 'sudo ', 'passwd',
            'useradd', 'userdel', '&& rm', '; rm', '| rm'
        ]
        
        command_lower = command.lower().strip()
        
        # Check for dangerous patterns
        for pattern in dangerous_patterns:
            if pattern in command_lower:
                return False
        
        # Check if command starts with a safe tool
        first_word = command_lower.split()[0] if command_lower.split() else ""
        return first_word in safe_tools

    async def execute_tool(self, name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a tool with given arguments"""
        try:
            self.logger.info(f"Executing tool: {name} with args: {arguments}")
            
            if name == "nmap_scan":
                return await self._execute_nmap(arguments)
            elif name == "sqlmap_test":
                return await self._execute_sqlmap(arguments)
            elif name == "web_scan":
                return await self._execute_nikto(arguments)
            elif name == "directory_bruteforce":
                return await self._execute_dirb(arguments)
            elif name == "technology_detection":
                return await self._execute_whatweb(arguments)
            elif name == "save_findings":
                return await self._save_findings(arguments)
            elif name == "get_memory":
                return await self._get_memory(arguments)
            elif name == "generate_report":
                return await self._generate_report(arguments)
            elif name == "custom_command":
                return await self._execute_custom_command(arguments)
            else:
                return {
                    "success": False,
                    "error": f"Unknown tool: {name}"
                }
                
        except Exception as e:
            self.logger.error(f"Error executing tool {name}: {str(e)}")
            return {
                "success": False,
                "error": str(e)
            }

    async def _execute_command(self, command: str, timeout: int = 300) -> Dict[str, Any]:
        """Execute a shell command safely"""
        try:
            if not self.is_safe_command(command):
                return {
                    "success": False,
                    "error": f"Command blocked for security: {command}"
                }
            
            self.logger.info(f"Executing command: {command}")
            
            process = await asyncio.create_subprocess_shell(
                command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=self.results_dir
            )
            
            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(), 
                    timeout=timeout
                )
                
                return {
                    "success": True,
                    "command": command,
                    "return_code": process.returncode,
                    "stdout": stdout.decode('utf-8', errors='ignore'),
                    "stderr": stderr.decode('utf-8', errors='ignore'),
                    "timestamp": datetime.now().isoformat()
                }
                
            except asyncio.TimeoutError:
                process.kill()
                return {
                    "success": False,
                    "error": f"Command timed out after {timeout} seconds"
                }
                
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }

    async def _execute_nmap(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Execute nmap scan"""
        target = args["target"]
        scan_type = args.get("scan_type", "basic")
        ports = args.get("ports", "")
        
        if scan_type == "basic":
            command = f"nmap {target}"
        elif scan_type == "service":
            command = f"nmap -sV {target}"
        elif scan_type == "aggressive":
            command = f"nmap -A {target}"
        else:
            command = f"nmap {target}"
        
        if ports:
            command += f" -p {ports}"
        
        result = await self._execute_command(command)
        
        if result["success"]:
            # Save results to file
            output_file = os.path.join(self.results_dir, f"nmap_{target.replace('/', '_')}.txt")
            with open(output_file, "w") as f:
                f.write(result["stdout"])
            result["output_file"] = output_file
        
        return result

    async def _execute_sqlmap(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Execute sqlmap test"""
        url = args["url"]
        level = args.get("level", 1)
        risk = args.get("risk", 1)
        parameter = args.get("parameter", "")
        
        command = f"sqlmap -u \"{url}\" --batch --level={level} --risk={risk}"
        
        if parameter:
            command += f" -p {parameter}"
        
        # Add safe options
        command += " --no-cast --disable-coloring --fresh-queries"
        
        return await self._execute_command(command)

    async def _execute_nikto(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Execute nikto web scan"""
        target = args["target"]
        timeout = args.get("timeout", 300)
        
        command = f"nikto -h {target}"
        
        return await self._execute_command(command, timeout)

    async def _execute_dirb(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Execute directory brute force"""
        target = args["target"]
        wordlist = args.get("wordlist", "/usr/share/dirb/wordlists/common.txt")
        extensions = args.get("extensions", "")
        
        command = f"dirb {target}"
        
        if os.path.exists(wordlist):
            command += f" {wordlist}"
        
        if extensions:
            command += f" -X {extensions}"
        
        return await self._execute_command(command)

    async def _execute_whatweb(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Execute whatweb technology detection"""
        target = args["target"]
        verbosity = args.get("verbosity", 1)
        
        command = f"whatweb -v {verbosity} {target}"
        
        return await self._execute_command(command)

    async def _execute_custom_command(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Execute custom command with safety checks"""
        command = args["command"]
        timeout = args.get("timeout", 300)
        
        return await self._execute_command(command, timeout)

    async def _save_findings(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Save findings to memory"""
        try:
            findings = args["findings"]
            category = args["category"]
            severity = args.get("severity", "info")
            
            # Load existing memory
            memory = self._load_memory()
            
            # Add new finding
            memory["findings"].append({
                "content": findings,
                "category": category,
                "severity": severity,
                "timestamp": datetime.now().isoformat()
            })
            
            # Save memory
            self._save_memory(memory)
            
            return {
                "success": True,
                "message": "Findings saved successfully"
            }
            
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }

    async def _get_memory(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Retrieve memory/findings"""
        try:
            memory = self._load_memory()
            category = args.get("category")
            limit = args.get("limit", 10)
            
            findings = memory.get("findings", [])
            
            if category:
                findings = [f for f in findings if f.get("category") == category]
            
            # Return most recent findings
            findings = findings[-limit:]
            
            return {
                "success": True,
                "findings": findings,
                "total_count": len(memory.get("findings", []))
            }
            
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }

    async def _generate_report(self, args: Dict[str, Any]) -> Dict[str, Any]:
        """Generate penetration testing report"""
        try:
            target = args["target"]
            format_type = args.get("format", "markdown")
            
            memory = self._load_memory()
            findings = memory.get("findings", [])
            
            if format_type == "markdown":
                report = self._generate_markdown_report(target, findings)
                filename = f"pentest_report_{target.replace('/', '_')}.md"
            elif format_type == "json":
                report = json.dumps({
                    "target": target,
                    "timestamp": datetime.now().isoformat(),
                    "findings": findings
                }, indent=2)
                filename = f"pentest_report_{target.replace('/', '_')}.json"
            else:
                return {
                    "success": False,
                    "error": f"Unsupported format: {format_type}"
                }
            
            # Save report
            report_path = os.path.join(self.results_dir, filename)
            with open(report_path, "w") as f:
                f.write(report)
            
            return {
                "success": True,
                "report_path": report_path,
                "report_content": report[:1000] + "..." if len(report) > 1000 else report
            }
            
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }

    def _generate_markdown_report(self, target: str, findings: List[Dict]) -> str:
        """Generate markdown format report"""
        report = f"""# Penetration Testing Report

**Target:** {target}
**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
**Generated by:** MCP Penetration Testing Server

## Executive Summary

This report contains the results of penetration testing performed against {target}.

## Findings Summary

"""
        
        # Group findings by category and severity
        categories = {}
        severities = {"critical": [], "high": [], "medium": [], "low": [], "info": []}
        
        for finding in findings:
            category = finding.get("category", "unknown")
            severity = finding.get("severity", "info")
            
            if category not in categories:
                categories[category] = []
            categories[category].append(finding)
            
            if severity in severities:
                severities[severity].append(finding)
        
        # Severity summary
        report += "### Severity Distribution\n\n"
        for severity in ["critical", "high", "medium", "low", "info"]:
            count = len(severities[severity])
            report += f"- **{severity.title()}:** {count}\n"
        
        report += "\n## Detailed Findings\n\n"
        
        # Detailed findings by category
        for category, category_findings in categories.items():
            report += f"### {category.title()}\n\n"
            
            for i, finding in enumerate(category_findings, 1):
                report += f"#### Finding {i}\n\n"
                report += f"**Severity:** {finding.get('severity', 'info').title()}\n\n"
                report += f"**Details:**\n{finding.get('content', 'No details')}\n\n"
                report += f"**Timestamp:** {finding.get('timestamp', 'Unknown')}\n\n"
                report += "---\n\n"
        
        report += """
## Recommendations

1. Address all critical and high severity vulnerabilities immediately
2. Implement proper input validation and sanitization
3. Use parameterized queries to prevent SQL injection
4. Keep all systems and software updated
5. Implement proper access controls
6. Regular security testing and monitoring

## Methodology

This test was conducted using various penetration testing tools through the MCP server interface, including:
- Network scanning (nmap)
- Web vulnerability scanning (nikto)
- SQL injection testing (sqlmap)
- Directory enumeration (dirb/gobuster)
- Technology fingerprinting (whatweb)

---
*Report generated automatically by MCP Penetration Testing Server*
"""
        
        return report

    def _load_memory(self) -> Dict[str, Any]:
        """Load memory from file"""
        if os.path.exists(self.memory_file):
            try:
                with open(self.memory_file, "r") as f:
                    return json.load(f)
            except:
                pass
        
        return {
            "findings": [],
            "targets": [],
            "sessions": []
        }

    def _save_memory(self, memory: Dict[str, Any]) -> None:
        """Save memory to file"""
        with open(self.memory_file, "w") as f:
            json.dump(memory, f, indent=2)

    async def handle_request(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Main request handler for MCP protocol"""
        try:
            method = request.get("method")
            params = request.get("params", {})
            
            if method == "initialize":
                return {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {
                        "tools": {},
                        "resources": {},
                        "prompts": {}
                    },
                    "serverInfo": {
                        "name": self.name,
                        "version": self.version
                    }
                }
            
            elif method == "tools/list":
                return {"tools": self.tools}
            
            elif method == "tools/call":
                tool_name = params.get("name")
                arguments = params.get("arguments", {})
                result = await self.execute_tool(tool_name, arguments)
                
                return {
                    "content": [
                        {
                            "type": "text",
                            "text": json.dumps(result, indent=2)
                        }
                    ]
                }
            
            elif method == "resources/list":
                return {"resources": self.resources}
            
            elif method == "prompts/list":
                return {"prompts": self.prompts}
            
            else:
                return {
                    "error": {
                        "code": -32601,
                        "message": f"Method not found: {method}"
                    }
                }
                
        except Exception as e:
            self.logger.error(f"Error handling request: {str(e)}")
            return {
                "error": {
                    "code": -32603,
                    "message": f"Internal error: {str(e)}"
                }
            }

# Server instance
mcp_server = MCPServer()

async def main():
    """Main server loop"""
    import sys
    import json
    
    print("MCP Penetration Testing Server started", file=sys.stderr)
    
    while True:
        try:
            # Read JSON-RPC request from stdin
            line = sys.stdin.readline()
            if not line:
                break
                
            request = json.loads(line.strip())
            response = await mcp_server.handle_request(request)
            
            # Add ID if present in request
            if "id" in request:
                response["id"] = request["id"]
            
            # Write response to stdout
            print(json.dumps(response))
            sys.stdout.flush()
            
        except KeyboardInterrupt:
            break
        except Exception as e:
            print(f"Server error: {str(e)}", file=sys.stderr)

if __name__ == "__main__":
    asyncio.run(main())
