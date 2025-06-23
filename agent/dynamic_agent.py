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
            "metasploit": "Penetration testing framework"
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
        
        response = self.llm.generate(prompt)
        return self.parse_commands(response)
    
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
                return error_msg
            
            # Execute command with timeout
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=300,  # 5 minute timeout
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
            return error_msg
            
        except Exception as e:
            error_msg = f"Error executing command '{command}': {str(e)}"
            logger.error(error_msg)
            return error_msg

    def is_safe_command(self, command):
        """Check if command is safe to execute"""        # List of allowed commands/tools
        allowed_tools = [
            'nmap', 'sqlmap', 'nikto', 'dirb', 'gobuster', 'whatweb', 'waybackurls',
            'curl', 'wget', 'netcat', 'nc', 'hydra', 'john', 'hashcat',
            'wpscan', 'enum4linux', 'smbclient', 'dig', 'host', 'whois',
            'ping', 'traceroute', 'masscan', 'wfuzz', 'ffuf', 'grep',
            'cat', 'head', 'tail', 'ls', 'find', 'sort', 'uniq'
        ]
        
        # Blocked commands for security
        blocked_commands = [
            'rm', 'del', 'format', 'fdisk', 'mkfs', 'dd', 'shutdown',
            'reboot', 'halt', 'poweroff', 'init', 'kill', 'killall',
            'chmod +x', 'su', 'sudo', 'passwd', 'useradd', 'userdel'
        ]
        
        command_lower = command.lower()
        
        # Check for blocked commands
        for blocked in blocked_commands:
            if blocked in command_lower:
                return False
        
        # Check if command starts with allowed tool
        first_word = command.split()[0] if command.split() else ""
        return first_word in allowed_tools

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
        
        for command in commands:
            logger.info(f"Executing: {command}")
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
        
        logger.info("Dynamic penetration test completed")

    def generate_final_report(self):
        """Generate comprehensive final report"""
        report_md = self.attack_chain.generate_report()
        
        # Add command history section
        report_md += "\n\n## Command History\n\n"
        for i, cmd in enumerate(self.command_history, 1):
            report_md += f"### Command {i}\n"
            report_md += f"**Command:** `{cmd['command']}`\n"
            report_md += f"**Return Code:** {cmd['return_code']}\n"
            report_md += f"**Timestamp:** {time.ctime(cmd['timestamp'])}\n\n"
            
            if cmd['stdout']:
                report_md += f"**Output:**\n```\n{cmd['stdout'][:1000]}...\n```\n\n"
            
            if cmd['stderr']:
                report_md += f"**Errors:**\n```\n{cmd['stderr'][:500]}...\n```\n\n"
        
        # Save report
        report_path = os.path.join(self.results_dir, "dynamic_pentest_report.md")
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(report_md)
        
        logger.info(f"Final report generated: {report_path}")
        
        return report_md

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Dynamic AI-Powered Penetration Testing Agent")
    parser.add_argument("--target", required=True, help="Target URL for penetration testing")
    args = parser.parse_args()

    agent = DynamicPenTestAgent(args.target)
    agent.run()
