import os
import time
import subprocess
import json
import logging
from agent.chains.intelligent_chain import IntelligentAttackChain
from llm.llm_interface import get_llm

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class EnhancedPenTestAgent:
    def __init__(self, target_url):
        self.target_url = target_url
        self.intelligent_chain = IntelligentAttackChain(target_url)
        self.llm = get_llm()
        self.results_dir = "results"
        os.makedirs(self.results_dir, exist_ok=True)
        self.max_iterations_per_stage = 5

    def is_safe_command(self, command):
        """Check if command is safe to execute"""
        allowed_tools = [
            'nmap', 'sqlmap', 'nikto', 'dirb', 'gobuster', 'whatweb',
            'curl', 'wget', 'netcat', 'nc', 'hydra', 'john', 'hashcat',
            'wpscan', 'enum4linux', 'smbclient', 'dig', 'host', 'whois',
            'ping', 'traceroute', 'masscan', 'wfuzz', 'ffuf', 'grep',
            'cat', 'head', 'tail', 'ls', 'find', 'sort', 'uniq',
            'waybackurls', 'gau', 'subfinder', 'assetfinder'
        ]
        
        blocked_commands = [
            'rm', 'del', 'format', 'fdisk', 'mkfs', 'dd', 'shutdown',
            'reboot', 'halt', 'poweroff', 'init', 'kill', 'killall',
            'chmod +x', 'su', 'sudo', 'passwd', 'useradd', 'userdel'
        ]
        
        command_lower = command.lower()
        
        for blocked in blocked_commands:
            if blocked in command_lower:
                return False
        
        first_word = command.split()[0] if command.split() else ""
        return first_word in allowed_tools

    def execute_command(self, command):
        """Execute a shell command safely"""
        try:
            logger.info(f"Executing command: {command}")
            
            if not self.is_safe_command(command):
                error_msg = f"Command blocked for security: {command}"
                logger.warning(error_msg)
                return error_msg, -1
            
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=300,
                cwd=self.results_dir
            )
            
            output = f"STDOUT:\n{result.stdout}\n"
            if result.stderr:
                output += f"STDERR:\n{result.stderr}\n"
            
            return output, result.returncode
            
        except subprocess.TimeoutExpired:
            error_msg = f"Command timed out: {command}"
            logger.error(error_msg)
            return error_msg, -1
            
        except Exception as e:
            error_msg = f"Error executing command: {str(e)}"
            logger.error(error_msg)
            return error_msg, -1

    def run_intelligent_stage(self, stage_name):
        """Run a stage with AI decision making"""
        logger.info(f"Starting intelligent stage: {stage_name}")
        
        self.intelligent_chain.set_current_stage(stage_name)
        
        # Get current context
        recent_findings = self.intelligent_chain.memory.get("findings", [])[-3:]
        context = " ".join([f.get("content", str(f)) for f in recent_findings])
        
        stage_outputs = []
        iterations = 0
        
        while iterations < self.max_iterations_per_stage:
            iterations += 1
            logger.info(f"Stage {stage_name} - Iteration {iterations}")
            
            # Get AI decision
            decision = self.intelligent_chain.intelligent_decision(stage_name, context)
            
            if decision.get("action_type") == "conclusion":
                logger.info(f"AI concluded stage {stage_name}")
                break
            
            if decision.get("action_type") == "analysis":
                # Just analysis, no commands
                analysis = decision.get("analysis", "No analysis provided")
                self.intelligent_chain.update_findings(f"ANALYSIS: {analysis}")
                stage_outputs.append(f"AI Analysis: {analysis}")
                continue
            
            # Execute commands
            commands = decision.get("commands", [])
            if not commands:
                logger.warning(f"No commands in decision for {stage_name}")
                break
            
            for command in commands:
                output, return_code = self.execute_command(command)
                
                # Update chain memory
                self.intelligent_chain.update_command_history(command, output, return_code)
                self.intelligent_chain.update_findings(f"Command: {command}\nOutput: {output}")
                
                stage_outputs.append(f"Command: {command}\n{output}")
                
                # Update context for next iteration
                context = output
                
                time.sleep(2)  # Delay between commands
        
        self.intelligent_chain.complete_stage(stage_name)
        
        # Save stage output
        stage_file = os.path.join(self.results_dir, f"{stage_name}_intelligent.txt")
        with open(stage_file, "w", encoding="utf-8") as f:
            f.write("\n\n".join(stage_outputs))
        
        logger.info(f"Completed intelligent stage: {stage_name}")
        return "\n\n".join(stage_outputs)

    def run(self):
        """Run the complete intelligent penetration test"""
        logger.info(f"Starting intelligent penetration test for {self.target_url}")
        
        stages = [
            "reconnaissance",
            "enumeration",
            "scanning", 
            "vulnerability_assessment",
            "exploitation"
        ]
        
        # Run each stage intelligently
        for stage in stages:
            try:
                self.run_intelligent_stage(stage)
                
                # Check if we found critical vulnerabilities and should stop
                vulnerabilities = self.intelligent_chain.memory.get("vulnerabilities", [])
                critical_vulns = [v for v in vulnerabilities if v.get("severity") == "high"]
                
                if len(critical_vulns) >= 3:
                    logger.info("Found multiple critical vulnerabilities, proceeding to exploitation")
                    if stage != "exploitation":
                        self.run_intelligent_stage("exploitation")
                    break
                    
            except Exception as e:
                error_msg = f"Error in stage {stage}: {str(e)}"
                logger.error(error_msg)
                self.intelligent_chain.update_findings(error_msg)
        
        # Generate intelligent report
        self.generate_final_report()
        logger.info("Intelligent penetration test completed")

    def generate_final_report(self):
        """Generate comprehensive report using AI"""
        try:
            report = self.intelligent_chain.generate_intelligent_report()
            
            # Save report
            report_path = os.path.join(self.results_dir, "intelligent_pentest_report.md")
            with open(report_path, "w", encoding="utf-8") as f:
                f.write(report)
            
            # Save memory dump
            memory_path = os.path.join(self.results_dir, "complete_memory.json")
            with open(memory_path, "w", encoding="utf-8") as f:
                json.dump(self.intelligent_chain.memory, f, indent=2)
            
            logger.info(f"Intelligent report generated: {report_path}")
            
        except Exception as e:
            logger.error(f"Error generating report: {str(e)}")

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Enhanced AI-Powered Penetration Testing Agent")
    parser.add_argument("--target", required=True, help="Target URL for penetration testing")
    args = parser.parse_args()

    agent = EnhancedPenTestAgent(args.target)
    agent.run()
