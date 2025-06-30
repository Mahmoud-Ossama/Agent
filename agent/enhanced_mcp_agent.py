"""
Enhanced Multi-Terminal MCP Penetration Testing Agent
Supports parallel command execution across multiple terminals following professional methodology
"""

import os
import time
import subprocess
import json
import random
import logging
import asyncio
import threading
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor, as_completed
from agent.chains.intelligent_chain import IntelligentAttackChain
from llm.llm_interface import get_llm

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class ParallelCommand:
    """Command structure for parallel execution"""
    command: str
    stage: str
    terminal_id: int
    priority: int
    dependencies: List[str]
    expected_duration: float
    category: str

@dataclass
class TerminalSession:
    """Terminal session management"""
    terminal_id: int
    process: Optional[subprocess.Popen]
    current_directory: str
    session_history: List[Dict]
    active: bool
    stage: str

class MultiTerminalController:
    """Advanced multi-terminal controller for parallel pentesting"""
    
    def __init__(self, target_url: str, max_terminals: int = 4):
        self.target_url = target_url
        self.max_terminals = max_terminals
        self.terminals: Dict[int, TerminalSession] = {}
        self.llm = get_llm()
        self.intelligent_chain = IntelligentAttackChain(target_url)
        self.stage_dependencies = {
            'reconnaissance': [],
            'enumeration': ['reconnaissance'],
            'vulnerability_analysis': ['enumeration'],
            'exploitation': ['vulnerability_analysis']
        }
        self.parallel_commands_queue = []
        self.completed_commands = []
        self.stage_results = {}
        
    def initialize_terminals(self):
        """Initialize multiple terminal sessions"""
        logger.info(f"🖥️  Initializing {self.max_terminals} terminal sessions...")
        
        for i in range(self.max_terminals):
            terminal = TerminalSession(
                terminal_id=i,
                process=None,
                current_directory=os.getcwd(),
                session_history=[],
                active=True,
                stage="ready"
            )
            self.terminals[i] = terminal
            logger.info(f"✅ Terminal {i} ready")
    
    def get_stage_commands(self, stage: str) -> List[ParallelCommand]:
        """Get commands for a specific stage with parallel execution plan"""
        
        commands_map = {
            'reconnaissance': [
                ParallelCommand(f"whois {self.target_url}", "reconnaissance", 0, 1, [], 10.0, "domain_info"),
                ParallelCommand(f"nslookup {self.target_url}", "reconnaissance", 1, 1, [], 5.0, "dns_lookup"),
                ParallelCommand(f"dig {self.target_url}", "reconnaissance", 2, 1, [], 5.0, "dns_detailed"),
                ParallelCommand(f"theHarvester -d {self.target_url} -b all -l 50", "reconnaissance", 3, 2, [], 30.0, "osint"),
            ],
            'enumeration': [
                ParallelCommand(f"nmap -sS -Pn -T4 {self.target_url}", "enumeration", 0, 1, ["reconnaissance"], 45.0, "port_scan"),
                ParallelCommand(f"nmap -sV -T4 {self.target_url}", "enumeration", 1, 1, ["reconnaissance"], 60.0, "service_scan"),
                ParallelCommand(f"nmap -sC -T4 {self.target_url}", "enumeration", 2, 2, ["reconnaissance"], 90.0, "script_scan"),
                ParallelCommand(f"whatweb {self.target_url}", "enumeration", 3, 1, ["reconnaissance"], 15.0, "web_tech"),
            ],
            'vulnerability_analysis': [
                ParallelCommand(f"nmap --script vuln -T4 {self.target_url}", "vulnerability_analysis", 0, 1, ["enumeration"], 120.0, "vuln_scan"),
                ParallelCommand(f"nikto -h {self.target_url}", "vulnerability_analysis", 1, 1, ["enumeration"], 180.0, "web_vuln"),
                ParallelCommand(f"dirb http://{self.target_url}/", "vulnerability_analysis", 2, 2, ["enumeration"], 300.0, "directory_scan"),
                ParallelCommand(f"sqlmap -u 'http://{self.target_url}' --batch --crawl=2", "vulnerability_analysis", 3, 1, ["enumeration"], 240.0, "sql_injection"),
            ],
            'exploitation': [
                ParallelCommand(f"msfconsole -q -x 'search {self.target_url}; exit'", "exploitation", 0, 1, ["vulnerability_analysis"], 30.0, "metasploit_search"),
                ParallelCommand(f"searchsploit apache", "exploitation", 1, 2, ["vulnerability_analysis"], 15.0, "exploit_search"),
                ParallelCommand(f"hydra -l admin -P /usr/share/wordlists/rockyou.txt {self.target_url} http-get", "exploitation", 2, 3, ["vulnerability_analysis"], 600.0, "brute_force"),
            ]
        }
        
        return commands_map.get(stage, [])
    
    def can_execute_stage(self, stage: str) -> bool:
        """Check if stage dependencies are satisfied"""
        dependencies = self.stage_dependencies.get(stage, [])
        
        for dep_stage in dependencies:
            if dep_stage not in self.stage_results or not self.stage_results[dep_stage].get('completed', False):
                return False
        
        return True
    
    def simulate_human_typing(self, command: str, terminal_id: int) -> str:
        """Simulate human-like typing for a command"""
        logger.info(f"🧠 Terminal {terminal_id}: Thinking about command: {command[:50]}...")
        
        # Human thinking time
        thinking_time = random.uniform(2.0, 5.0)
        time.sleep(thinking_time)
        
        # Simulate typing with random delays
        logger.info(f"⌨️  Terminal {terminal_id}: Typing command...")
        
        typed_chars = []
        for char in command:
            typed_chars.append(char)
            
            # Random typing delay
            delay = random.uniform(0.05, 0.2)
            time.sleep(delay)
            
            # Occasional longer pauses (thinking)
            if char == ' ' and random.random() < 0.15:
                pause = random.uniform(0.5, 2.0)
                time.sleep(pause)
            
            # Occasional typos and corrections
            if random.random() < 0.02 and char.isalpha():
                # Make a typo
                wrong_char = random.choice('abcdefghijklmnopqrstuvwxyz')
                typed_chars[-1] = wrong_char
                time.sleep(0.3)  # Realize mistake
                typed_chars[-1] = char  # Correct it
                time.sleep(0.2)
        
        # Pause before hitting Enter
        enter_delay = random.uniform(0.5, 2.0)
        time.sleep(enter_delay)
        
        return ''.join(typed_chars)
    
    def execute_command_in_terminal(self, cmd: ParallelCommand) -> Dict:
        """Execute a command in specific terminal with human simulation"""
        terminal = self.terminals[cmd.terminal_id]
        
        logger.info(f"🎯 Terminal {cmd.terminal_id}: Starting {cmd.category} - {cmd.command[:50]}...")
        
        # Simulate human typing
        typed_command = self.simulate_human_typing(cmd.command, cmd.terminal_id)
        
        try:
            # Execute command
            start_time = time.time()
            
            result = subprocess.run(
                typed_command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=cmd.expected_duration + 60,  # Add buffer to expected duration
                cwd=terminal.current_directory
            )
            
            execution_time = time.time() - start_time
            
            # Store result
            command_result = {
                'command': cmd.command,
                'terminal_id': cmd.terminal_id,
                'stage': cmd.stage,
                'category': cmd.category,
                'return_code': result.returncode,
                'stdout': result.stdout,
                'stderr': result.stderr,
                'execution_time': execution_time,
                'timestamp': time.time(),
                'success': result.returncode == 0
            }
            
            # Update terminal history
            terminal.session_history.append(command_result)
            
            # Update intelligent chain
            self.intelligent_chain.update_command_history(
                cmd.command, 
                result.stdout + result.stderr, 
                result.returncode
            )
            
            logger.info(f"✅ Terminal {cmd.terminal_id}: Completed {cmd.category} in {execution_time:.2f}s")
            return command_result
            
        except subprocess.TimeoutExpired:
            error_result = {
                'command': cmd.command,
                'terminal_id': cmd.terminal_id,
                'stage': cmd.stage,
                'category': cmd.category,
                'return_code': -1,
                'stdout': '',
                'stderr': f'Command timed out after {cmd.expected_duration + 60}s',
                'execution_time': cmd.expected_duration + 60,
                'timestamp': time.time(),
                'success': False
            }
            
            logger.warning(f"⏰ Terminal {cmd.terminal_id}: Command timed out - {cmd.category}")
            return error_result
            
        except Exception as e:
            error_result = {
                'command': cmd.command,
                'terminal_id': cmd.terminal_id,
                'stage': cmd.stage,
                'category': cmd.category,
                'return_code': -1,
                'stdout': '',
                'stderr': str(e),
                'execution_time': 0,
                'timestamp': time.time(),
                'success': False
            }
            
            logger.error(f"❌ Terminal {cmd.terminal_id}: Error executing {cmd.category} - {str(e)}")
            return error_result
    
    def execute_stage_parallel(self, stage: str) -> Dict:
        """Execute stage commands in parallel across multiple terminals"""
        if not self.can_execute_stage(stage):
            logger.warning(f"⚠️  Cannot execute {stage} - dependencies not satisfied")
            return {'completed': False, 'reason': 'dependencies_not_satisfied'}
        
        logger.info(f"🚀 Starting parallel execution of {stage} stage")
        
        # Get commands for this stage
        commands = self.get_stage_commands(stage)
        
        if not commands:
            logger.warning(f"⚠️  No commands defined for stage: {stage}")
            return {'completed': False, 'reason': 'no_commands'}
        
        # Create stage-specific results directory
        stage_results_dir = os.path.join("results", "stage_results")
        os.makedirs(stage_results_dir, exist_ok=True)
        
        # Create terminal logs directory
        terminal_logs_dir = os.path.join("results", "terminal_logs")
        os.makedirs(terminal_logs_dir, exist_ok=True)
        
        # Execute commands in parallel using ThreadPoolExecutor
        stage_results = []
        
        with ThreadPoolExecutor(max_workers=self.max_terminals) as executor:
            # Submit all commands
            future_to_command = {
                executor.submit(self.execute_command_in_terminal, cmd): cmd 
                for cmd in commands
            }
            
            # Collect results as they complete
            for future in as_completed(future_to_command):
                cmd = future_to_command[future]
                try:
                    result = future.result()
                    stage_results.append(result)
                    
                    # Save individual terminal log
                    terminal_log_file = os.path.join(
                        terminal_logs_dir, 
                        f"{stage}_terminal_{result['terminal_id']}.log"
                    )
                    with open(terminal_log_file, "w", encoding="utf-8") as f:
                        f.write(f"Terminal {result['terminal_id']} - {stage.upper()} Stage\n")
                        f.write(f"Command: {result['command']}\n")
                        f.write(f"Return Code: {result['return_code']}\n")
                        f.write(f"Execution Time: {result['execution_time']:.2f}s\n")
                        f.write(f"Timestamp: {time.ctime(result['timestamp'])}\n\n")
                        f.write("STDOUT:\n")
                        f.write(result['stdout'])
                        f.write("\n\nSTDERR:\n")
                        f.write(result['stderr'])
                    
                    # Update findings immediately
                    if result['success'] and result['stdout'].strip():
                        self.intelligent_chain.update_findings(
                            f"[{stage.upper()}] {cmd.category}: {result['stdout'][:500]}..."
                        )
                    
                except Exception as e:
                    logger.error(f"❌ Error in parallel execution: {str(e)}")
                    stage_results.append({
                        'command': cmd.command,
                        'terminal_id': cmd.terminal_id,
                        'stage': stage,
                        'success': False,
                        'error': str(e)
                    })
        
        # Analyze stage results
        successful_commands = [r for r in stage_results if r.get('success', False)]
        total_time = max([r.get('execution_time', 0) for r in stage_results] + [0])
        
        stage_summary = {
            'stage': stage,
            'completed': True,
            'total_commands': len(commands),
            'successful_commands': len(successful_commands),
            'total_execution_time': total_time,
            'results': stage_results,
            'timestamp': time.time(),
            'findings_summary': self.extract_stage_findings(stage_results),
            'vulnerabilities_found': self.extract_stage_vulnerabilities(stage_results),
            'next_stage_recommendations': self.generate_next_stage_recommendations(stage, stage_results)
        }
        
        # Save stage results to JSON file
        stage_results_file = os.path.join("results", f"{stage}_results.json")
        with open(stage_results_file, "w", encoding="utf-8") as f:
            json.dump(stage_summary, f, indent=2, default=str)
        
        # Generate stage-specific report
        self.generate_stage_report(stage, stage_summary)
        
        # Store stage results
        self.stage_results[stage] = stage_summary
        
        logger.info(f"✅ Completed {stage} stage: {len(successful_commands)}/{len(commands)} commands successful in {total_time:.2f}s")
        logger.info(f"📄 Stage results saved to: {stage_results_file}")
        
        return stage_summary
    
    def run_full_parallel_assessment(self):
        """Run complete parallel penetration test"""
        logger.info("🌟 Starting Enhanced Multi-Terminal Parallel Penetration Test")
        logger.info(f"🎯 Target: {self.target_url}")
        logger.info(f"🖥️  Using {self.max_terminals} parallel terminals")
        
        # Initialize terminals
        self.initialize_terminals()
        
        # Define execution order (considering dependencies)
        execution_stages = [
            'reconnaissance',
            'enumeration', 
            'vulnerability_analysis',
            'exploitation'
        ]
        
        total_start_time = time.time()
        
        # Execute each stage
        for stage in execution_stages:
            stage_start = time.time()
            
            logger.info(f"\n{'='*60}")
            logger.info(f"🔍 STAGE: {stage.upper()}")
            logger.info(f"{'='*60}")
            
            # Wait for dependencies if needed
            while not self.can_execute_stage(stage):
                logger.info(f"⏳ Waiting for {stage} dependencies...")
                time.sleep(5)
            
            # Execute stage in parallel
            stage_result = self.execute_stage_parallel(stage)
            
            stage_time = time.time() - stage_start
            logger.info(f"⏱️  Stage {stage} completed in {stage_time:.2f} seconds")
            
            # Brief pause between stages for analysis
            if stage != execution_stages[-1]:
                logger.info("🧠 Analyzing results before next stage...")
                time.sleep(random.uniform(3, 7))
        
        total_time = time.time() - total_start_time
        
        # Generate comprehensive report
        self.generate_parallel_report()
        
        logger.info(f"\n🎉 Parallel Penetration Test Completed!")
        logger.info(f"⏱️  Total execution time: {total_time:.2f} seconds")
        logger.info(f"🖥️  Utilized {self.max_terminals} parallel terminals")
    
    def generate_parallel_report(self):
        """Generate comprehensive report for parallel execution"""
        logger.info("📊 Generating parallel execution report...")
        
        report = f"""# Enhanced Multi-Terminal Parallel Penetration Test Report

**Target:** {self.target_url}
**Date:** {time.ctime()}
**Testing Method:** Parallel Multi-Terminal Execution
**Terminals Used:** {self.max_terminals}

## Executive Summary

This penetration test was conducted using an enhanced AI-powered agent with parallel multi-terminal execution capabilities. The agent simultaneously executed reconnaissance, enumeration, vulnerability analysis, and exploitation commands across multiple terminals to maximize efficiency.

## Methodology

### Parallel Execution Strategy
- **Reconnaissance:** All commands executed simultaneously
- **Enumeration:** Parallel execution after reconnaissance data available
- **Vulnerability Analysis:** Parallel execution after service enumeration
- **Exploitation:** Targeted exploitation based on discovered vulnerabilities

"""
        
        # Add stage summaries
        for stage, results in self.stage_results.items():
            report += f"\n## {stage.upper()} Stage Results\n\n"
            report += f"- **Total Commands:** {results['total_commands']}\n"
            report += f"- **Successful Commands:** {results['successful_commands']}\n"
            report += f"- **Execution Time:** {results['total_execution_time']:.2f} seconds\n"
            report += f"- **Success Rate:** {(results['successful_commands']/results['total_commands']*100):.1f}%\n\n"
            
            # Add command details
            for cmd_result in results['results']:
                if cmd_result.get('success', False):
                    report += f"### {cmd_result['category'].title()}\n"
                    report += f"**Command:** `{cmd_result['command']}`\n"
                    report += f"**Terminal:** {cmd_result['terminal_id']}\n"
                    report += f"**Execution Time:** {cmd_result['execution_time']:.2f}s\n"
                    
                    if cmd_result['stdout']:
                        report += f"**Output Preview:**\n```\n{cmd_result['stdout'][:300]}...\n```\n\n"
        
        # Add AI analysis
        report += "\n## AI Analysis\n\n"
        ai_analysis = self.intelligent_chain.generate_intelligent_report()
        report += ai_analysis
        
        # Save report
        os.makedirs("results", exist_ok=True)
        report_path = "results/parallel_pentest_report.md"
        
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(report)
        
        logger.info(f"📄 Report saved: {report_path}")
    
    def extract_stage_findings(self, stage_results: List[Dict]) -> List[str]:
        """Extract key findings from stage results"""
        findings = []
        
        for result in stage_results:
            if result.get('success', False) and result.get('stdout'):
                output = result['stdout']
                category = result.get('category', 'unknown')
                
                # Extract meaningful findings based on category
                if category == 'domain_info':
                    # Extract registrar, creation date, etc.
                    if 'Registrar:' in output:
                        registrar = [line for line in output.split('\n') if 'Registrar:' in line]
                        findings.extend(registrar)
                
                elif category == 'port_scan':
                    # Extract open ports
                    open_ports = [line for line in output.split('\n') if '/tcp' in line and 'open' in line]
                    findings.extend(open_ports[:10])  # Limit to first 10
                
                elif category == 'service_scan':
                    # Extract service versions
                    services = [line for line in output.split('\n') if 'open' in line and any(svc in line for svc in ['http', 'ssh', 'ftp', 'smtp'])]
                    findings.extend(services[:10])
                
                elif category == 'web_tech':
                    # Extract web technologies
                    if 'Title:' in output:
                        findings.append(f"Web Title: {output.split('Title:')[1].split()[0] if 'Title:' in output else 'N/A'}")
                
                elif category == 'sql_injection':
                    # Extract SQL injection findings
                    if 'vulnerable' in output.lower():
                        vuln_lines = [line for line in output.split('\n') if 'vulnerable' in line.lower()]
                        findings.extend(vuln_lines[:5])
        
        return findings[:20]  # Limit total findings
    
    def extract_stage_vulnerabilities(self, stage_results: List[Dict]) -> List[Dict]:
        """Extract vulnerability information from stage results"""
        vulnerabilities = []
        
        for result in stage_results:
            if result.get('success', False) and result.get('stdout'):
                output = result['stdout']
                category = result.get('category', 'unknown')
                
                # Look for vulnerability indicators
                if 'vulnerable' in output.lower() or 'exploit' in output.lower():
                    if category == 'sql_injection':
                        vulnerabilities.append({
                            'type': 'SQL Injection',
                            'severity': 'High',
                            'location': result.get('command', ''),
                            'description': 'Potential SQL injection vulnerability detected',
                            'evidence': output[:200] + '...'
                        })
                    elif category == 'vuln_scan':
                        # Parse nmap vuln script output
                        if 'CVE-' in output:
                            cves = [line for line in output.split('\n') if 'CVE-' in line]
                            for cve in cves[:3]:
                                vulnerabilities.append({
                                    'type': 'Known CVE',
                                    'severity': 'Medium',
                                    'location': result.get('command', ''),
                                    'description': cve.strip(),
                                    'evidence': cve.strip()
                                })
        
        return vulnerabilities
    
    def generate_next_stage_recommendations(self, current_stage: str, stage_results: List[Dict]) -> List[str]:
        """Generate recommendations for the next stage based on current findings"""
        recommendations = []
        
        if current_stage == 'reconnaissance':
            recommendations.extend([
                "Focus port scanning on discovered IP addresses",
                "Investigate subdomains found during reconnaissance",
                "Analyze certificate information for additional domains"
            ])
        
        elif current_stage == 'enumeration':
            # Check for specific services found
            has_web = any('80' in str(r.get('stdout', '')) or '443' in str(r.get('stdout', '')) for r in stage_results)
            has_ssh = any('22' in str(r.get('stdout', '')) for r in stage_results)
            has_ftp = any('21' in str(r.get('stdout', '')) for r in stage_results)
            
            if has_web:
                recommendations.append("Prioritize web application security testing")
                recommendations.append("Perform comprehensive directory enumeration")
            if has_ssh:
                recommendations.append("Consider SSH brute force testing")
            if has_ftp:
                recommendations.append("Test for FTP anonymous access")
        
        elif current_stage == 'vulnerability_analysis':
            # Check for specific vulnerabilities found
            has_sqli = any('sql' in str(r.get('stdout', '')).lower() for r in stage_results)
            has_ssl_issues = any('ssl' in str(r.get('stdout', '')).lower() or 'tls' in str(r.get('stdout', '')).lower() for r in stage_results)
            
            if has_sqli:
                recommendations.append("Exploit SQL injection vulnerabilities found")
            if has_ssl_issues:
                recommendations.append("Investigate SSL/TLS configuration issues")
        
        return recommendations[:5]  # Limit recommendations
    
    def generate_stage_report(self, stage: str, stage_summary: Dict):
        """Generate a detailed report for a specific stage"""
        report_content = f"""# {stage.title()} Stage Report

**Target:** {self.target_url}
**Stage:** {stage.upper()}
**Execution Date:** {time.ctime(stage_summary['timestamp'])}
**Total Commands:** {stage_summary['total_commands']}
**Successful Commands:** {stage_summary['successful_commands']}
**Total Execution Time:** {stage_summary['total_execution_time']:.2f} seconds

## Stage Summary

This stage executed {stage_summary['total_commands']} commands across {self.max_terminals} parallel terminals.
Success Rate: {(stage_summary['successful_commands']/stage_summary['total_commands']*100):.1f}%

## Key Findings

"""
        
        # Add findings
        for finding in stage_summary.get('findings_summary', []):
            report_content += f"- {finding}\n"
        
        report_content += "\n## Vulnerabilities Discovered\n\n"
        
        # Add vulnerabilities
        for vuln in stage_summary.get('vulnerabilities_found', []):
            report_content += f"### {vuln['type']} ({vuln['severity']})\n"
            report_content += f"**Location:** {vuln['location']}\n"
            report_content += f"**Description:** {vuln['description']}\n"
            report_content += f"**Evidence:** {vuln['evidence']}\n\n"
        
        report_content += "\n## Command Execution Details\n\n"
        
        # Add command details
        for result in stage_summary['results']:
            if result.get('success', False):
                report_content += f"### {result.get('category', 'Unknown').title()}\n"
                report_content += f"**Command:** `{result['command']}`\n"
                report_content += f"**Terminal:** {result['terminal_id']}\n"
                report_content += f"**Execution Time:** {result['execution_time']:.2f}s\n"
                report_content += f"**Return Code:** {result['return_code']}\n\n"
                
                if result['stdout']:
                    report_content += "**Output:**\n```\n"
                    report_content += result['stdout'][:500] + ("..." if len(result['stdout']) > 500 else "")
                    report_content += "\n```\n\n"
        
        report_content += "\n## Next Stage Recommendations\n\n"
        
        # Add recommendations
        for rec in stage_summary.get('next_stage_recommendations', []):
            report_content += f"- {rec}\n"
        
        # Save stage report
        stage_report_file = os.path.join("results", f"{stage}_stage_report.md")
        with open(stage_report_file, "w", encoding="utf-8") as f:
            f.write(report_content)
        
        logger.info(f"📄 Stage report saved to: {stage_report_file}")

class EnhancedMCPAgent:
    """Main enhanced MCP agent with multi-terminal capabilities"""
    
    def __init__(self, target_url: str, max_terminals: int = 4):
        self.target_url = target_url
        self.multi_terminal = MultiTerminalController(target_url, max_terminals)
        
    def run_enhanced_assessment(self):
        """Run enhanced parallel assessment"""
        self.multi_terminal.run_full_parallel_assessment()

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Enhanced Multi-Terminal MCP Penetration Testing Agent")
    parser.add_argument("--target", required=True, help="Target URL for penetration testing")
    parser.add_argument("--terminals", type=int, default=4, help="Number of parallel terminals (default: 4)")
    args = parser.parse_args()
    
    agent = EnhancedMCPAgent(args.target, args.terminals)
    agent.run_enhanced_assessment()
