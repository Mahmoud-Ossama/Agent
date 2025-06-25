import os
import time
import subprocess
import json
from agent.chains.attack_chain import AttackChain
from llm.llm_interface import get_llm
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class DynamicPenTestAgent:
    def __init__(self, target_url):
        self.target_url = target_url
        self.attack_chain = AttackChain(target_url)
        self.llm = get_llm()
        self.results_dir = "results"
        os.makedirs(self.results_dir, exist_ok=True)
        self.command_history = []
        
        # Configurable timeouts for different tools
        self.command_timeouts = {
            'sqlmap': 1800,  # 30 minutes for sqlmap
            'nikto': 900,    # 15 minutes for nikto
            'nmap': 600,     # 10 minutes for nmap
            'dirb': 600,     # 10 minutes for dirb
            'gobuster': 600, # 10 minutes for gobuster
            'hydra': 1800,   # 30 minutes for hydra
            'katana': 300,   # 5 minutes for katana
            'amass': 900,    # 15 minutes for amass
            'subfinder': 300, # 5 minutes for subfinder
            'assetfinder': 300, # 5 minutes for assetfinder
            'sublist3r': 600, # 10 minutes for sublist3r
            'waybackurls': 300, # 5 minutes for waybackurls
            'default': 300   # 5 minutes default
        }
        
    def get_available_tools(self):
        """Get list of available penetration testing tools"""
        tools = {
            "nmap": "Network mapping and port scanning",
            "sqlmap": "SQL injection detection and exploitation",
            "nikto": "Web vulnerability scanner",
            "dirb": "Directory and file brute forcing",
            "gobuster": "Directory/file/DNS busting tool",
            "whatweb": "Website technology identification",
            "curl": "Command line tool for HTTP requests",
            "wget": "Web content retrieval",
            "netcat": "Network connection tool",
            "hydra": "Password cracking tool",
            "john": "Password cracking tool",
            "hashcat": "Password recovery tool",
            "wpscan": "WordPress vulnerability scanner",
            "enum4linux": "Linux enumeration tool",
            "smbclient": "SMB client tool",
            "dig": "DNS lookup tool",
            "host": "DNS lookup tool",
            "whois": "Domain information lookup",
            "ping": "Network connectivity test",
            "traceroute": "Network path tracing",
            "masscan": "Fast port scanner",
            "zap-cli": "OWASP ZAP command line interface",
            "wfuzz": "Web application fuzzer",
            "ffuf": "Fast web fuzzer",
            "burpsuite": "Web application security testing",
            "metasploit": "Penetration testing framework",
            "katana": "Fast web crawler and spider tool",
            "waybackurls": "Web archive URL enumeration",
            "subfinder": "Subdomain discovery tool",
            "assetfinder": "Asset discovery tool",
            "amass": "Network mapping and attack surface discovery",
            "sublist3r": "Subdomain enumeration tool"
        }
        return tools
    
    def ask_llm_for_commands(self, current_stage, findings):
        """Ask LLM what commands to execute next"""
        available_tools = self.get_available_tools()
        tools_list = "\n".join([f"- {tool}: {desc}" for tool, desc in available_tools.items()])
        
        prompt = f"""
You are a professional penetration tester working on target: {self.target_url}

Current Stage: {current_stage}
Previous Findings: {findings}

Available Tools:
{tools_list}

Based on the current stage and findings, what specific commands should I execute next?
Please provide ONLY the exact terminal commands, one per line.
Do not include explanations, just the raw commands.
Make sure commands are valid for Linux/Kali environment.
Focus on SQL injection testing and web application security.

Examples of good responses:
nmap -sV -sC {self.target_url}
sqlmap -u "{self.target_url}" --batch --risk=3 --level=5
nikto -h {self.target_url}

Your commands:
"""
        
        try:
            response = self.llm.generate(prompt)
            
            # Check if LLM returned an error message
            if response and response.startswith("Error generating"):
                logger.error(f"LLM failed to generate response: {response}")
                return self.get_fallback_commands(current_stage)
            
            commands = self.parse_commands(response)
            
            # If no valid commands were parsed, use fallback
            if not commands:
                logger.warning(f"No valid commands parsed from LLM response, using fallback for stage: {current_stage}")
                return self.get_fallback_commands(current_stage)
                
            return commands
            
        except Exception as e:
            logger.error(f"Exception while asking LLM for commands: {str(e)}")
            return self.get_fallback_commands(current_stage)
    
    def parse_commands(self, response):
        """Parse LLM response to extract valid commands"""
        lines = response.strip().split('\n')
        commands = []
        
        for line in lines:
            line = line.strip()
            # Skip empty lines and lines that look like explanations
            if line and not line.startswith('#') and not line.startswith('//'):
                # Remove common prefixes that might be added by LLM
                if line.startswith('$ '):
                    line = line[2:]
                elif line.startswith('> '):
                    line = line[2:]
                
                commands.append(line)
        
        return commands

    def execute_command(self, command):
        """Execute a shell command and return the output"""
        try:
            logger.info(f"Executing command: {command}")
            
            # Security check - only allow certain commands
            if not self.is_safe_command(command):
                error_msg = f"Command blocked for security reasons: {command}"
                logger.warning(error_msg)
                
                # Store blocked command in history for analysis
                self.command_history.append({
                    "command": command,
                    "return_code": -1,
                    "stdout": error_msg,
                    "stderr": "Security filter blocked execution",
                    "timestamp": time.time()
                })
                
                return error_msg
                
            # Execute command with timeout
            # Get timeout based on command
            first_word = command.split()[0] if command.split() else "default"
            timeout = self.command_timeouts.get(first_word, self.command_timeouts['default'])
            
            logger.info(f"Executing with {timeout}s timeout: {command}")
            
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=self.results_dir
            )
            
            output = f"Command: {command}\n"
            output += f"Return Code: {result.returncode}\n"
            output += f"STDOUT:\n{result.stdout}\n"
            if result.stderr:
                output += f"STDERR:\n{result.stderr}\n"
            
            # Store command in history
            self.command_history.append({
                "command": command,
                "return_code": result.returncode,
                "stdout": result.stdout,
                "stderr": result.stderr,
                "timestamp": time.time()
            })
            
            return output
            
        except subprocess.TimeoutExpired:
            error_msg = f"Command timed out: {command}"
            logger.error(error_msg)
            
            # Store timeout in history
            self.command_history.append({
                "command": command,
                "return_code": -2,
                "stdout": error_msg,
                "stderr": "Command execution timeout",
                "timestamp": time.time()
            })
            
            return error_msg
            
        except Exception as e:
            error_msg = f"Error executing command '{command}': {str(e)}"
            logger.error(error_msg)
            
            # Store error in history
            self.command_history.append({
                "command": command,
                "return_code": -3,
                "stdout": error_msg,
                "stderr": str(e),
                "timestamp": time.time()
            })
            
            return error_msg

    def is_safe_command(self, command):
        """Check if command is safe to execute"""
        # List of allowed commands/tools
        allowed_tools = [
            'nmap', 'sqlmap', 'nikto', 'dirb', 'gobuster', 'whatweb', 'waybackurls',
            'curl', 'wget', 'netcat', 'nc', 'hydra', 'john', 'hashcat',
            'wpscan', 'enum4linux', 'smbclient', 'dig', 'host', 'whois',
            'ping', 'traceroute', 'masscan', 'wfuzz', 'ffuf', 'grep',
            'cat', 'head', 'tail', 'ls', 'find', 'sort', 'uniq',
            'katana', 'subfinder', 'assetfinder', 'amass', 'sublist3r'
        ]
        
        # Blocked commands for security (exact matches to avoid false positives)
        blocked_commands = [
            'rm -rf /', 'rm -rf *', 'del *', 'format c:', 'fdisk /dev/', 'mkfs.', 'dd if=/dev/zero', 
            'shutdown now', 'reboot now', 'halt now', 'poweroff now', 'init 0', 'kill -9', 'killall -9',
            'chmod +x /bin/', 'su root', 'sudo su -', 'passwd root', 'useradd root', 'userdel root',
            'mount /dev/', 'umount /dev/', 'crontab -r', 'echo "" > /etc/passwd', 'cat /etc/shadow'
        ]
        
        command_lower = command.lower()
        
        # Check for blocked commands (more specific matching)
        for blocked in blocked_commands:
            if blocked in command_lower:
                return False
        
        # Additional security checks
        dangerous_patterns = [
            'rm -rf /', 'rm -rf *', '> /dev/sda', 'dd if=/dev/zero',
            'mkfs.ext4', 'fdisk /dev/', 'echo > /etc/'
        ]
        
        for pattern in dangerous_patterns:
            if pattern in command_lower:
                return False
        
        # Check if command starts with allowed tool
        first_word = command.split()[0] if command.split() else ""
        is_allowed = first_word in allowed_tools
        
        if not is_allowed:
            logger.warning(f"Command blocked: '{command}' - First word: '{first_word}' not in allowed tools")
        else:
            logger.debug(f"Command allowed: '{command}' - First word: '{first_word}' found in allowed tools")
        
        return is_allowed

    def run_dynamic_stage(self, stage_name):
        """Run a penetration testing stage dynamically"""
        logger.info(f"Starting dynamic stage: {stage_name}")
        
        # Get current findings
        findings = "\n".join(str(item) for item in self.attack_chain.memory.get("findings", []))
        
        # Ask LLM for commands
        commands = self.ask_llm_for_commands(stage_name, findings)
        
        if not commands:
            logger.warning(f"No commands received for stage: {stage_name}")
            return "No commands to execute"
            
        # Execute each command
        stage_output = f"=== {stage_name.upper()} STAGE ===\n\n"
        
        for i, command in enumerate(commands, 1):
            logger.info(f"Executing command {i}/{len(commands)}: {command}")
            
            # Get expected timeout for this command
            first_word = command.split()[0] if command.split() else "default"
            timeout = self.command_timeouts.get(first_word, self.command_timeouts['default'])
            
            if timeout > 300:  # If timeout is more than 5 minutes, show progress message
                print(f"⏳ Running {first_word} (may take up to {timeout//60} minutes)...")
            
            output = self.execute_command(command)
            stage_output += f"{output}\n{'='*50}\n\n"
            
            # Update findings with command output
            self.attack_chain.update_findings(f"Command: {command}")
            self.attack_chain.update_findings(output)
            
            # Small delay between commands
            time.sleep(2)
        
        # Update tools used
        self.attack_chain.update_tools_used(f"{stage_name}_dynamic")
        
        logger.info(f"Completed dynamic stage: {stage_name}")
        return stage_output

    def run(self):
        """Run the complete penetration testing lifecycle"""
        logger.info(f"Starting dynamic penetration test for {self.target_url}")
        
        # Define stages
        stages = [
            "reconnaissance",
            "enumeration", 
            "scanning",
            "vulnerability_assessment",
            "exploitation"
        ]
        
        # Run each stage dynamically
        for stage in stages:
            try:
                output = self.run_dynamic_stage(stage)
                
                # Save stage output
                stage_file = os.path.join(self.results_dir, f"{stage}_output.txt")
                with open(stage_file, "w", encoding="utf-8") as f:
                    f.write(output)
                
                logger.info(f"Stage {stage} completed and saved to {stage_file}")
                
            except Exception as e:
                error_msg = f"Error in stage {stage}: {str(e)}"
                logger.error(error_msg)
                self.attack_chain.update_findings(error_msg)
        
        # Save command history
        history_file = os.path.join(self.results_dir, "command_history.json")
        with open(history_file, "w", encoding="utf-8") as f:
            json.dump(self.command_history, f, indent=2)
            
        # Generate final report
        self.generate_final_report()
        
        # Generate HTML report
        self.generate_html_report()
        
        logger.info("Dynamic penetration test completed")

    def generate_final_report(self):
        """Generate comprehensive final report"""
        # Generate executive summary
        executive_summary = self.generate_executive_summary()
        
        # Generate technical report
        technical_report = self.attack_chain.generate_report()
        
        # Add command history section to technical report
        technical_report += "\n\n## Command History\n\n"
        for i, cmd in enumerate(self.command_history, 1):
            technical_report += f"### Command {i}\n"
            technical_report += f"**Command:** `{cmd['command']}`\n"
            technical_report += f"**Return Code:** {cmd['return_code']}\n"
            technical_report += f"**Timestamp:** {time.ctime(cmd['timestamp'])}\n\n"
            
            if cmd['stdout']:
                technical_report += f"**Output:**\n```\n{cmd['stdout'][:1000]}...\n```\n\n"
            
            if cmd['stderr']:
                technical_report += f"**Errors:**\n```\n{cmd['stderr'][:500]}...\n```\n\n"
        
        # Save executive summary (non-technical)
        summary_path = os.path.join(self.results_dir, "EXECUTIVE_SUMMARY.md")
        with open(summary_path, "w", encoding="utf-8") as f:
            f.write(executive_summary)
        
        # Save technical report
        report_path = os.path.join(self.results_dir, "dynamic_pentest_report.md")
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(technical_report)
        
        # Generate HTML report
        html_report_path = self.generate_html_report()
        
        # Display summary to console
        print("\n" + "="*80)
        print("🎯 PENETRATION TEST RESULTS SUMMARY")
        print("="*80)
        print(self.format_console_summary())
        print("="*80)
        
        logger.info(f"Executive summary generated: {summary_path}")
        logger.info(f"Technical report generated: {report_path}")
        logger.info(f"HTML report generated: {html_report_path}")
        
        return technical_report

    def analyze_command_results(self):
        """Analyze command results to extract key findings"""
        successful_commands = []
        failed_commands = []
        blocked_commands = []
        vulnerabilities_found = []
        tools_used = set()
        
        for cmd in self.command_history:
            tool_name = cmd['command'].split()[0] if cmd['command'].split() else "unknown"
            tools_used.add(tool_name)
            
            # Check if command was blocked
            if 'blocked for security reasons' in cmd.get('stdout', '') or 'blocked for security reasons' in cmd.get('stderr', ''):
                blocked_commands.append({
                    'tool': tool_name,
                    'command': cmd['command'],
                    'reason': 'Security filter blocked execution'
                })
            elif cmd['return_code'] == 0:
                successful_commands.append({
                    'tool': tool_name,
                    'command': cmd['command'],
                    'output': cmd['stdout']
                })
                
                # Check for potential vulnerabilities in output
                if 'vulnerable' in cmd['stdout'].lower() or 'injection' in cmd['stdout'].lower():
                    vulnerabilities_found.append({
                        'tool': tool_name,
                        'type': 'Potential SQL Injection' if 'injection' in cmd['stdout'].lower() else 'Vulnerability',
                        'output': cmd['stdout'][:200] + '...'
                    })
            else:
                failed_commands.append({
                    'tool': tool_name,
                    'command': cmd['command'],
                    'error': cmd['stderr']
                })
        
        return {
            'successful_commands': successful_commands,
            'failed_commands': failed_commands,
            'blocked_commands': blocked_commands,
            'vulnerabilities_found': vulnerabilities_found,
            'tools_used': list(tools_used),
            'total_commands': len(self.command_history)
        }

    def generate_executive_summary(self):
        """Generate non-technical executive summary"""
        analysis = self.analyze_command_results()
        
        summary = f"""# 🎯 PENETRATION TEST EXECUTIVE SUMMARY

## Target Information
- **Target Website:** {self.target_url}
- **Test Date:** {time.strftime('%Y-%m-%d %H:%M:%S')}
- **Test Duration:** Automated AI-driven security assessment

## 📊 Test Overview
- **Total Security Tools Used:** {len(analysis['tools_used'])}
- **Total Commands Executed:** {analysis['total_commands']}
- **Successful Tests:** {len(analysis['successful_commands'])}
- **Failed Tests:** {len(analysis['failed_commands'])}

## 🔍 Tools Successfully Executed
"""
        
        if analysis['successful_commands']:
            for cmd in analysis['successful_commands']:
                summary += f"- ✅ **{cmd['tool'].upper()}** - Security testing tool executed successfully\n"
        else:
            summary += "- ❌ No tools executed successfully\n"
        
        summary += "\n## 🚨 Security Findings\n"
        
        if analysis['vulnerabilities_found']:
            summary += f"**⚠️ ATTENTION: {len(analysis['vulnerabilities_found'])} potential security issues detected**\n\n"
            for vuln in analysis['vulnerabilities_found']:
                summary += f"- **{vuln['type']}** detected by {vuln['tool']}\n"
                summary += f"  - Details: {vuln['output']}\n\n"
        else:
            summary += "- ✅ No obvious vulnerabilities detected in automated scan\n"
        
        summary += "\n## 🛠️ Testing Tools Analysis\n"
        
        tools_descriptions = {
            'curl': 'HTTP request analysis - Checks website response headers',
            'sqlmap': 'SQL Injection testing - Tests for database vulnerabilities',
            'nikto': 'Web vulnerability scanner - Comprehensive security check',
            'gobuster': 'Directory discovery - Finds hidden files and folders',
            'nmap': 'Network scanning - Identifies open ports and services',
            'wpscan': 'WordPress security - Tests WordPress-specific vulnerabilities',
            'katana': 'Web crawling - Fast website structure discovery',
            'waybackurls': 'Archive analysis - Historical website content discovery',
            'subfinder': 'Subdomain discovery - Finds subdomains of target',
            'assetfinder': 'Asset discovery - Identifies digital assets',
            'amass': 'Network mapping - Advanced attack surface discovery',
            'sublist3r': 'Subdomain enumeration - Python-based subdomain finder',
            'whatweb': 'Technology identification - Identifies web technologies',
            'dirb': 'Directory brute force - Finds hidden directories',
            'masscan': 'Fast port scanning - High-speed network discovery',
            'ffuf': 'Web fuzzing - Fast directory and parameter discovery'
        }
        
        for tool in analysis['tools_used']:
            status = "✅ SUCCESS" if any(cmd['tool'] == tool for cmd in analysis['successful_commands']) else "❌ FAILED"
            description = tools_descriptions.get(tool, 'Security testing tool')
            summary += f"- **{tool.upper()}** - {status}\n  {description}\n\n"
        
        summary += """## 📈 Risk Assessment
- **Low Risk:** Basic information gathering completed
- **Medium Risk:** Web application tested for common vulnerabilities
- **High Risk:** SQL injection and database security tested

## 🎯 Recommendations
1. Review any vulnerabilities found above immediately
2. Implement web application firewall (WAF) if not present
3. Regular security testing should be conducted monthly
4. Keep all web applications and plugins updated

## 📁 Detailed Reports Available
- `EXECUTIVE_SUMMARY.md` - This non-technical summary
- `dynamic_pentest_report.md` - Technical details for IT team
- `command_history.json` - Complete audit trail

---
*Report generated by AI-Powered Penetration Testing Agent*
"""
        
        return summary

    def format_console_summary(self):
        """Format summary for console display"""
        analysis = self.analyze_command_results()
        
        console_output = f"""
🎯 Target: {self.target_url}
📅 Test Date: {time.strftime('%Y-%m-%d %H:%M:%S')}

📊 TEST RESULTS:
   Total Commands: {analysis['total_commands']}
   Successful: {len(analysis['successful_commands'])} ✅
   Failed: {len(analysis['failed_commands'])} ❌
   Blocked: {len(analysis['blocked_commands'])} 🛡️

🛠️ TOOLS USED:
"""
        
        for tool in analysis['tools_used']:
            status = "✅" if any(cmd['tool'] == tool for cmd in analysis['successful_commands']) else "❌"
            console_output += f"   {tool.upper()}: {status}\n"
        
        if analysis['blocked_commands']:
            console_output += f"\n🛡️ SECURITY BLOCKS:\n"
            for blocked in analysis['blocked_commands'][:3]:  # Show first 3
                console_output += f"   {blocked['tool'].upper()}: Blocked by security filter\n"
            if len(analysis['blocked_commands']) > 3:
                console_output += f"   ... and {len(analysis['blocked_commands']) - 3} more\n"
        
        console_output += f"""
🚨 SECURITY STATUS:
   Vulnerabilities Found: {len(analysis['vulnerabilities_found'])}
"""
        
        if analysis['vulnerabilities_found']:
            console_output += "   ⚠️  ATTENTION REQUIRED - Issues detected!\n"
        else:
            console_output += "   ✅ No obvious vulnerabilities in automated scan\n"
        
        console_output += f"""
📁 REPORTS GENERATED:
   📋 Executive Summary: results/EXECUTIVE_SUMMARY.md
   🔧 Technical Report: results/dynamic_pentest_report.md
   📊 Command History: results/command_history.json
   🌐 HTML Report: results/security_report.html
"""
        
        return console_output

    def generate_html_report(self):
        """Generate HTML report for easy viewing"""
        analysis = self.analyze_command_results()
        
        html_template = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Penetration Test Results - {self.target_url}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; background-color: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 0 20px rgba(0,0,0,0.1); }}
        .header {{ text-align: center; border-bottom: 3px solid #007acc; padding-bottom: 20px; margin-bottom: 30px; }}
        .section {{ margin: 30px 0; }}
        .success {{ color: #28a745; }}
        .warning {{ color: #ffc107; }}
        .danger {{ color: #dc3545; }}
        .info {{ color: #007acc; }}
        .tool-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; }}
        .tool-card {{ border: 1px solid #ddd; padding: 15px; border-radius: 8px; background: #f9f9f9; }}
        .status-success {{ border-left: 4px solid #28a745; }}
        .status-failed {{ border-left: 4px solid #dc3545; }}
        .vulnerability {{ background: #fff3cd; border: 1px solid #ffeaa7; padding: 15px; border-radius: 5px; margin: 10px 0; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Security Assessment Report</h1>
            <h2 class="info">{self.target_url}</h2>
            <p><strong>Test Date:</strong> {time.strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>

        <div class="section">
            <h2>📊 Test Summary</h2>
            <div class="tool-grid">
                <div class="tool-card">
                    <h3>Total Commands</h3>
                    <h2 class="info">{analysis['total_commands']}</h2>
                </div>
                <div class="tool-card status-success">
                    <h3>Successful Tests</h3>
                    <h2 class="success">{len(analysis['successful_commands'])}</h2>
                </div>
                <div class="tool-card status-failed">
                    <h3>Failed Tests</h3>
                    <h2 class="danger">{len(analysis['failed_commands'])}</h2>
                </div>
                <div class="tool-card">
                    <h3>Tools Used</h3>
                    <h2 class="info">{len(analysis['tools_used'])}</h2>
                </div>
            </div>
        </div>

        <div class="section">
            <h2>🚨 Security Findings</h2>
"""
        
        if analysis['vulnerabilities_found']:
            html_template += f"<div class='vulnerability'><h3 class='warning'>⚠️ {len(analysis['vulnerabilities_found'])} Potential Issues Detected</h3>"
            for vuln in analysis['vulnerabilities_found']:
                html_template += f"<p><strong>{vuln['type']}</strong> detected by {vuln['tool']}</p>"
                html_template += f"<p><code>{vuln['output']}</code></p>"
            html_template += "</div>"
        else:
            html_template += "<div class='vulnerability' style='background: #d4edda; border-color: #c3e6cb;'><h3 class='success'>✅ No obvious vulnerabilities detected</h3></div>"
        
        html_template += """
        </div>

        <div class="section">
            <h2>🛠️ Tools Analysis</h2>
            <div class="tool-grid">
"""
        
        tools_descriptions = {
            'curl': 'HTTP request analysis - Checks website response headers',
            'sqlmap': 'SQL Injection testing - Tests for database vulnerabilities',
            'nikto': 'Web vulnerability scanner - Comprehensive security check',
            'gobuster': 'Directory discovery - Finds hidden files and folders',
            'nmap': 'Network scanning - Identifies open ports and services',
            'wpscan': 'WordPress security - Tests WordPress-specific vulnerabilities',
            'katana': 'Web crawling - Fast website structure discovery',
            'waybackurls': 'Archive analysis - Historical website content discovery',
            'subfinder': 'Subdomain discovery - Finds subdomains of target',
            'assetfinder': 'Asset discovery - Identifies digital assets',
            'amass': 'Network mapping - Advanced attack surface discovery',
            'sublist3r': 'Subdomain enumeration - Python-based subdomain finder',
            'whatweb': 'Technology identification - Identifies web technologies',
            'dirb': 'Directory brute force - Finds hidden directories',
            'masscan': 'Fast port scanning - High-speed network discovery',
            'ffuf': 'Web fuzzing - Fast directory and parameter discovery'
        }
        
        for tool in analysis['tools_used']:
            status = "SUCCESS" if any(cmd['tool'] == tool for cmd in analysis['successful_commands']) else "FAILED"
            status_class = "status-success" if status == "SUCCESS" else "status-failed"
            status_color = "success" if status == "SUCCESS" else "danger"
            description = tools_descriptions.get(tool, 'Security testing tool')
            
            html_template += f"""
                <div class="tool-card {status_class}">
                    <h3>{tool.upper()}</h3>
                    <p class="{status_color}"><strong>{status}</strong></p>
                    <p>{description}</p>
                </div>
"""
        
        html_template += """
            </div>
        </div>

        <div class="section">
            <h2>📋 Recommendations</h2>
            <ul>
                <li>Review any vulnerabilities found above immediately</li>
                <li>Implement web application firewall (WAF) if not present</li>
                <li>Regular security testing should be conducted monthly</li>
                <li>Keep all web applications and plugins updated</li>
            </ul>
        </div>

        <div class="section">
            <h2>📁 Available Reports</h2>
            <ul>
                <li><strong>EXECUTIVE_SUMMARY.md</strong> - Non-technical summary</li>
                <li><strong>dynamic_pentest_report.md</strong> - Technical details</li>
                <li><strong>command_history.json</strong> - Complete audit trail</li>
                <li><strong>security_report.html</strong> - This visual report</li>
            </ul>
        </div>

        <footer style="text-align: center; margin-top: 40px; padding-top: 20px; border-top: 1px solid #ddd;">
            <p><em>Report generated by AI-Powered Penetration Testing Agent</em></p>
        </footer>
    </div>
</body>
</html>"""
        
        # Save HTML report
        html_path = os.path.join(self.results_dir, "security_report.html")
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(html_template)
        
        logger.info(f"HTML report generated: {html_path}")
        return html_path

    def get_fallback_commands(self, stage_name):
        """Provide fallback commands when LLM fails"""
        logger.info(f"Using fallback commands for stage: {stage_name}")
        
        # Extract domain from URL for better command targeting
        domain = self.target_url.replace('http://', '').replace('https://', '').split('/')[0]
        
        # Comprehensive fallback commands based on stage
        fallback_commands = {
            "reconnaissance": [
                f"whatweb {self.target_url}",
                f"curl -I {self.target_url}",
                f"nmap -sV -sC {domain}",
                f"dig {domain}",
                f"whois {domain}"
            ],
            "enumeration": [
                f"gobuster dir -u {self.target_url} -w /usr/share/wordlists/dirb/common.txt",
                f"nikto -h {self.target_url}",
                f"waybackurls {domain}",
                f"subfinder -d {domain}"
            ],
            "scanning": [
                f"nmap -sV -sC -p- {domain}",
                f"masscan -p1-65535 {domain} --rate=1000",
                f"curl -s {self.target_url}/robots.txt",
                f"curl -s {self.target_url}/sitemap.xml"
            ],
            "vulnerability_assessment": [
                f"nikto -h {self.target_url}",
                f"sqlmap -u '{self.target_url}' --batch --risk=1 --level=1",
                f"dirb {self.target_url}",
                f"wpscan --url {self.target_url}"
            ],
            "exploitation": [
                f"sqlmap -u '{self.target_url}' --batch --dbs",
                f"curl -X POST {self.target_url}",
                f"ffuf -w /usr/share/wordlists/dirb/common.txt -u {self.target_url}/FUZZ"
            ]
        }
        
        # Get fallback commands for the stage, or default reconnaissance commands
        commands = fallback_commands.get(stage_name.lower(), fallback_commands["reconnaissance"])
        
        logger.info(f"Fallback commands for {stage_name}: {commands}")
        return commands

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Dynamic AI-Powered Penetration Testing Agent")
    parser.add_argument("--target", required=True, help="Target URL for penetration testing")
    args = parser.parse_args()

    agent = DynamicPenTestAgent(args.target)
    agent.run()
