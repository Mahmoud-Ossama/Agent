"""
MCP-Enhanced Penetration Testing Agent with Human-like Terminal Control
Integrates Model Context Protocol for natural Kali Linux interaction
"""

import os
import time
import subprocess
import json
import random
import logging
from typing import Dict, List, Optional
from dataclasses import dataclass
from agent.chains.intelligent_chain import IntelligentAttackChain
from llm.llm_interface import get_llm

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class MCPCommand:
    """MCP Command structure for human-like execution"""
    command: str
    typing_delay: float = 0.1
    execution_delay: float = 2.0
    human_thinking_time: float = 1.0
    error_correction: bool = True

class HumanTypingSimulator:
    """Simulate human typing patterns and behaviors"""
    
    def __init__(self):
        self.typing_speeds = {
            'fast': 0.05,
            'normal': 0.1,
            'slow': 0.2,
            'thinking': 0.5
        }
        self.error_rate = 0.02  # 2% chance of typos
        
    def simulate_typing(self, text: str, speed: str = 'normal') -> List[str]:
        """Simulate human typing with realistic delays and occasional errors"""
        typing_sequence = []
        delay = self.typing_speeds.get(speed, 0.1)
        
        i = 0
        while i < len(text):
            char = text[i]
            
            # Simulate thinking pauses at word boundaries
            if char == ' ' and random.random() < 0.1:
                typing_sequence.append(('pause', random.uniform(0.5, 2.0)))
            
            # Simulate typing errors occasionally
            if random.random() < self.error_rate and char.isalpha():
                # Make a typo
                wrong_char = random.choice('abcdefghijklmnopqrstuvwxyz')
                typing_sequence.append(('type', wrong_char, delay))
                # Realize the mistake and correct it
                typing_sequence.append(('pause', random.uniform(0.2, 0.8)))
                typing_sequence.append(('backspace', None, delay))
                typing_sequence.append(('type', char, delay))
            else:
                typing_sequence.append(('type', char, delay))
            
            i += 1
        
        return typing_sequence

    def execute_typing_sequence(self, sequence: List[tuple]) -> str:
        """Execute the typing sequence and return the final command"""
        command_buffer = ""
        
        for action in sequence:
            if action[0] == 'type':
                char = action[1]
                delay = action[2]
                command_buffer += char
                logger.debug(f"Typed: '{char}' (buffer: '{command_buffer}')")
                time.sleep(delay)
                
            elif action[0] == 'backspace':
                if command_buffer:
                    command_buffer = command_buffer[:-1]
                    logger.debug(f"Backspace (buffer: '{command_buffer}')")
                time.sleep(action[2] if len(action) > 2 else 0.1)
                
            elif action[0] == 'pause':
                pause_time = action[1]
                logger.debug(f"Thinking pause: {pause_time:.2f}s")
                time.sleep(pause_time)
        
        return command_buffer

class MCPKaliController:
    """MCP-enhanced Kali Linux controller with human-like behavior"""
    
    def __init__(self, target_url: str):
        self.target_url = target_url
        self.llm = get_llm()
        self.typing_simulator = HumanTypingSimulator()
        self.intelligent_chain = IntelligentAttackChain(target_url)
        self.session_history = []
        self.current_directory = os.getcwd()
        self.terminal_state = {
            'pwd': self.current_directory,
            'env_vars': dict(os.environ),
            'active_processes': []
        }
        
    def get_mcp_context(self) -> Dict:
        """Get current MCP context for decision making"""
        return {
            'target': self.target_url,
            'current_directory': self.terminal_state['pwd'],
            'recent_commands': self.session_history[-5:],
            'findings': self.intelligent_chain.memory.get('findings', [])[-3:],
            'vulnerabilities': self.intelligent_chain.memory.get('vulnerabilities', []),
            'stage': self.intelligent_chain.current_stage
        }
    
    def think_like_human(self, context: Dict) -> Dict:
        """Use MCP to think and decide like a human penetration tester"""
        
        mcp_prompt = f"""
You are an expert penetration tester working in a Kali Linux terminal. You need to think step-by-step like a human and decide what to type next.

CURRENT CONTEXT:
- Target: {context['target']}
- Current Directory: {context['current_directory']}
- Current Stage: {context['stage']}

RECENT COMMAND HISTORY:
{json.dumps(context['recent_commands'], indent=2)}

RECENT FINDINGS:
{json.dumps(context['findings'], indent=2)}

DISCOVERED VULNERABILITIES:
{json.dumps(context['vulnerabilities'], indent=2)}

As a human penetration tester, think about:
1. What would be the logical next step?
2. What command should I type in the terminal?
3. How should I approach this systematically?
4. What am I looking for in the output?

Respond in JSON format:
{{
    "thought_process": "What I'm thinking about the current situation",
    "next_command": "exact command to type in terminal",
    "expected_outcome": "what I expect this command to reveal",
    "typing_speed": "fast|normal|slow",
    "confidence": 0.8,
    "reasoning": "why this command makes sense now",
    "follow_up_actions": ["action1", "action2"]
}}

Focus on SQL injection testing and web application security. Be methodical and human-like in your approach.
"""
        
        try:
            response = self.llm.generate(mcp_prompt)
            decision = json.loads(response)
            return decision
        except json.JSONDecodeError:
            # Fallback if JSON parsing fails
            return {
                "thought_process": "Continuing systematic reconnaissance",
                "next_command": f"nmap -sV {self.target_url}",
                "expected_outcome": "Port and service information",
                "typing_speed": "normal",
                "confidence": 0.5,
                "reasoning": "Basic port scan to understand target",
                "follow_up_actions": ["Analyze open ports", "Check web services"]
            }
    
    def execute_command_humanlike(self, command: str, typing_speed: str = 'normal') -> tuple:
        """Execute command with human-like typing simulation"""
        
        logger.info(f"🧠 Thinking about command: {command}")
        
        # Human thinking time before typing
        thinking_time = random.uniform(1.0, 3.0)
        logger.info(f"💭 Thinking for {thinking_time:.1f} seconds...")
        time.sleep(thinking_time)
        
        # Simulate typing the command
        logger.info(f"⌨️  Typing command with {typing_speed} speed...")
        typing_sequence = self.typing_simulator.simulate_typing(command, typing_speed)
        typed_command = self.typing_simulator.execute_typing_sequence(typing_sequence)
        
        # Validate command matches (in case of typing errors that weren't corrected)
        if typed_command != command:
            logger.warning(f"Typed command differs from intended: '{typed_command}' vs '{command}'")
            command = typed_command
        
        # Human pause before hitting Enter
        enter_delay = random.uniform(0.5, 2.0)
        logger.info(f"⏸️  Pausing {enter_delay:.1f}s before pressing Enter...")
        time.sleep(enter_delay)
        
        # Execute the command
        logger.info(f"🚀 Executing: {command}")
        return self.execute_kali_command(command)
    
    def execute_kali_command(self, command: str) -> tuple:
        """Execute command in Kali Linux environment"""
        try:
            # Security validation
            if not self.is_safe_command(command):
                error_msg = f"🚫 Command blocked for security: {command}"
                logger.warning(error_msg)
                return error_msg, -1
            
            # Update terminal state
            if command.startswith('cd '):
                new_dir = command[3:].strip()
                if os.path.exists(new_dir):
                    self.terminal_state['pwd'] = os.path.abspath(new_dir)
                    os.chdir(new_dir)
            
            # Execute with human-like characteristics
            start_time = time.time()
            
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=300,
                cwd=self.terminal_state['pwd'],
                env=self.terminal_state['env_vars']
            )
            
            execution_time = time.time() - start_time
            
            # Store command in session history
            self.session_history.append({
                'command': command,
                'return_code': result.returncode,
                'execution_time': execution_time,
                'timestamp': time.time(),
                'directory': self.terminal_state['pwd']
            })
            
            # Format output
            output = ""
            if result.stdout:
                output += f"STDOUT:\n{result.stdout}\n"
            if result.stderr:
                output += f"STDERR:\n{result.stderr}\n"
            
            # Human-like delay after command completion
            if execution_time < 1.0:  # Quick commands
                time.sleep(random.uniform(0.5, 1.5))
            else:  # Longer commands
                time.sleep(random.uniform(1.0, 2.0))
            
            return output, result.returncode
            
        except subprocess.TimeoutExpired:
            error_msg = f"⏰ Command timed out: {command}"
            logger.error(error_msg)
            return error_msg, -1
            
        except Exception as e:
            error_msg = f"❌ Error executing command: {str(e)}"
            logger.error(error_msg)
            return error_msg, -1
    
    def is_safe_command(self, command: str) -> bool:
        """Validate command safety for Kali Linux"""
        allowed_tools = [
            'nmap', 'sqlmap', 'nikto', 'dirb', 'gobuster', 'whatweb',
            'curl', 'wget', 'netcat', 'nc', 'hydra', 'john', 'hashcat',
            'wpscan', 'enum4linux', 'smbclient', 'dig', 'host', 'whois',
            'ping', 'traceroute', 'masscan', 'wfuzz', 'ffuf', 'grep',
            'cat', 'head', 'tail', 'ls', 'pwd', 'cd', 'find', 'sort', 
            'uniq', 'awk', 'sed', 'cut', 'wc', 'less', 'more'
        ]
        
        dangerous_commands = [
            'rm -rf', 'dd if=', 'mkfs', 'fdisk', 'format', 'del /f',
            'shutdown', 'reboot', 'halt', 'poweroff', 'init 0',
            'killall', 'pkill', 'chmod 777', '> /dev/', 'exec'
        ]
        
        command_lower = command.lower()
        
        # Check for dangerous patterns
        for dangerous in dangerous_commands:
            if dangerous in command_lower:
                return False
        
        # Check if starts with allowed tool
        first_word = command.split()[0] if command.split() else ""
        return first_word in allowed_tools or first_word in ['cd', 'ls', 'pwd']
    
    def human_analysis_pause(self, output: str) -> str:
        """Simulate human reading and analyzing command output"""
        # Estimate reading time based on output length
        reading_time = min(len(output) / 100, 10.0)  # Max 10 seconds
        reading_time = max(reading_time, 1.0)  # Min 1 second
        
        logger.info(f"📖 Analyzing output for {reading_time:.1f} seconds...")
        time.sleep(reading_time)
        
        # Generate human-like analysis
        analysis_prompt = f"""
As a penetration tester, quickly analyze this command output and provide key insights:

OUTPUT:
{output[:2000]}...

Provide a brief analysis focusing on:
1. Key findings
2. Potential vulnerabilities
3. Next logical steps

Keep it concise and practical.
"""
        
        try:
            analysis = self.llm.generate(analysis_prompt)
            logger.info(f"🔍 Analysis: {analysis[:200]}...")
            return analysis
        except Exception as e:
            return f"Analysis error: {str(e)}"
    
    def run_mcp_stage(self, stage_name: str, max_iterations: int = 5):
        """Run a penetration testing stage with MCP human-like control"""
        
        logger.info(f"🎯 Starting MCP stage: {stage_name}")
        self.intelligent_chain.set_current_stage(stage_name)
        
        iteration = 0
        stage_findings = []
        
        while iteration < max_iterations:
            iteration += 1
            logger.info(f"🔄 Stage {stage_name} - Iteration {iteration}/{max_iterations}")
            
            # Get MCP context and think like human
            context = self.get_mcp_context()
            decision = self.think_like_human(context)
            
            logger.info(f"💭 Thought: {decision.get('thought_process', 'No thought process')}")
            logger.info(f"🎯 Reasoning: {decision.get('reasoning', 'No reasoning')}")
            
            # Check if stage should conclude
            if 'conclude' in decision.get('next_command', '').lower() or \
               'finished' in decision.get('thought_process', '').lower():
                logger.info(f"🏁 Human decision: Concluding stage {stage_name}")
                break
            
            command = decision.get('next_command', '')
            if not command:
                logger.warning("No command provided by MCP decision")
                break
            
            typing_speed = decision.get('typing_speed', 'normal')
            
            # Execute command with human-like behavior
            output, return_code = self.execute_command_humanlike(command, typing_speed)
            
            # Human-like analysis of output
            analysis = self.human_analysis_pause(output)
            
            # Update findings
            finding = {
                'stage': stage_name,
                'iteration': iteration,
                'command': command,
                'output': output[:1000] + "..." if len(output) > 1000 else output,
                'analysis': analysis,
                'decision_context': decision
            }
            
            stage_findings.append(finding)
            self.intelligent_chain.update_findings(json.dumps(finding))
            self.intelligent_chain.update_command_history(command, output, return_code)
            
            # Human-like break between commands
            break_time = random.uniform(2.0, 5.0)
            logger.info(f"⏱️  Taking a {break_time:.1f}s break before next action...")
            time.sleep(break_time)
        
        self.intelligent_chain.complete_stage(stage_name)
        logger.info(f"✅ Completed MCP stage: {stage_name}")
        
        return stage_findings

class MCPPenTestAgent:
    """Main MCP-enhanced penetration testing agent"""
    
    def __init__(self, target_url: str, enable_parallel: bool = True, max_terminals: int = 4):
        self.target_url = target_url
        self.enable_parallel = enable_parallel
        self.max_terminals = max_terminals
        self.kali_controller = MCPKaliController(target_url)
        self.results_dir = "results"
        os.makedirs(self.results_dir, exist_ok=True)
        
        # Initialize enhanced parallel controller if enabled
        if self.enable_parallel:
            from agent.enhanced_mcp_agent import MultiTerminalController
            self.parallel_controller = MultiTerminalController(target_url, max_terminals)
        
    def run_full_assessment(self):
        """Run complete MCP-controlled penetration test"""
        
        if self.enable_parallel:
            logger.info("🚀 Starting Enhanced Multi-Terminal Parallel Assessment")
            self.parallel_controller.run_full_parallel_assessment()
            return
        
        # Original single-terminal implementation
        logger.info("🚀 Starting MCP-Enhanced Penetration Test")
        logger.info(f"🎯 Target: {self.target_url}")
        
        stages = [
            ("reconnaissance", "Initial information gathering"),
            ("enumeration", "Detailed service discovery"),
            ("scanning", "Vulnerability identification"),
            ("vulnerability_assessment", "Deep vulnerability analysis"),
            ("exploitation", "Safe vulnerability demonstration")
        ]
        
        all_findings = {}
        
        for stage_name, stage_description in stages:
            logger.info(f"\n📋 Stage: {stage_name.upper()}")
            logger.info(f"📝 Description: {stage_description}")
            
            try:
                findings = self.kali_controller.run_mcp_stage(stage_name)
                all_findings[stage_name] = findings
                
                # Save stage results
                stage_file = os.path.join(self.results_dir, f"mcp_{stage_name}.json")
                with open(stage_file, 'w') as f:
                    json.dump(findings, f, indent=2)
                
            except Exception as e:
                logger.error(f"❌ Error in stage {stage_name}: {str(e)}")
                all_findings[stage_name] = [{"error": str(e)}]
        
        # Generate final report
        self.generate_mcp_report(all_findings)
        
        logger.info("🎉 MCP Penetration Test Completed!")
    
    def generate_mcp_report(self, findings: Dict):
        """Generate comprehensive MCP-enhanced report"""
        
        report_data = {
            'target': self.target_url,
            'timestamp': time.time(),
            'session_history': self.kali_controller.session_history,
            'findings_by_stage': findings,
            'vulnerabilities': self.kali_controller.intelligent_chain.memory.get('vulnerabilities', [])
        }
        
        # Save raw data
        raw_report_file = os.path.join(self.results_dir, "mcp_full_report.json")
        with open(raw_report_file, 'w') as f:
            json.dump(report_data, f, indent=2)
        
        # Generate human-readable report
        readable_report = self.kali_controller.intelligent_chain.generate_intelligent_report()
        
        # Save readable report
        readable_file = os.path.join(self.results_dir, "mcp_readable_report.md")
        with open(readable_file, 'w') as f:
            f.write(readable_report)
        
        logger.info(f"📊 Reports generated:")
        logger.info(f"   - Raw data: {raw_report_file}")
        logger.info(f"   - Readable: {readable_file}")

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="MCP-Enhanced Kali Linux Penetration Testing Agent")
    parser.add_argument("--target", required=True, help="Target URL for testing")
    args = parser.parse_args()
    
    agent = MCPPenTestAgent(args.target)
    agent.run_full_assessment()
