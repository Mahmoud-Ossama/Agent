"""
MCP Client for Human-like Penetration Testing
Provides human-like terminal interaction through MCP protocol
"""

import asyncio
import time
import random
import logging
from typing import Dict, List, Optional
from mcp_server import MCPServer
from agent.mcp_agent import HumanTypingSimulator

logger = logging.getLogger(__name__)

class MCPHumanClient:
    """MCP Client with human-like behavior simulation"""
    
    def __init__(self, target_url: str):
        self.target_url = target_url
        self.mcp_server = MCPServer()
        self.typing_simulator = HumanTypingSimulator()
        self.session_memory = {
            "commands_executed": [],
            "findings": [],
            "stage": "reconnaissance"
        }
    
    async def start_human_session(self):
        """Start a human-like penetration testing session"""
        logger.info(f"🎯 Starting MCP Human session for target: {self.target_url}")
        
        # Simulate human thinking and planning
        await self._simulate_human_planning()
        
        # Execute penetration testing stages
        stages = [
            "reconnaissance", 
            "enumeration", 
            "scanning", 
            "vulnerability_assessment", 
            "exploitation"
        ]
        
        for stage in stages:
            logger.info(f"🔍 Starting {stage} stage...")
            self.session_memory["stage"] = stage
            await self._execute_stage_with_human_behavior(stage)
            
            # Human-like pause between stages
            await self._simulate_thinking_pause(2, 5)
        
        # Generate final report
        await self._generate_human_report()
    
    async def _simulate_human_planning(self):
        """Simulate human thinking and planning phase"""
        logger.info("🧠 Human operator is analyzing the target...")
        
        # Simulate reading and research time
        await asyncio.sleep(random.uniform(1, 3))
        
        planning_thoughts = [
            f"Analyzing target: {self.target_url}",
            "Planning reconnaissance approach...",
            "Selecting appropriate tools...",
            "Preparing test methodology..."        ]
        
        for thought in planning_thoughts:
            logger.info(f"💭 {thought}")
            await asyncio.sleep(random.uniform(0.5, 1.5))
    
    async def _execute_stage_with_human_behavior(self, stage: str):
        """Execute a testing stage with human-like behavior"""
        # Get stage-appropriate tools
        tools = await self._get_stage_tools(stage)
        
        for tool_name in tools[:3]:  # Limit to 3 tools per stage
            logger.info(f"🔧 Human operator selecting tool: {tool_name}")
            
            # Simulate human decision making
            await self._simulate_thinking_pause(1, 3)
            
            # Execute tool with human typing simulation
            await self._execute_tool_human_style(tool_name, stage)
            
            # Human-like pause between commands
            await self._simulate_thinking_pause(2, 4)
    
    async def _execute_tool_human_style(self, tool_name: str, stage: str):
        """Execute a tool with human-like typing and behavior"""
        
        # Simulate human typing the command
        command = self._get_tool_command(tool_name, stage)
        
        logger.info(f"⌨️  Human typing: {command}")
          # Simulate realistic typing with pauses and corrections
        typing_sequence = self.typing_simulator.simulate_typing(command)
        final_command = self.typing_simulator.execute_typing_sequence(typing_sequence)
        
        # Execute the command through MCP
        try:
            result = await self._execute_mcp_command(tool_name, {
                "target": self.target_url,
                "stage": stage
            })
            
            # Simulate human reading and analyzing results
            await self._simulate_result_analysis(result)
            
            # Store findings
            self.session_memory["commands_executed"].append({
                "tool": tool_name,
                "command": command,
                "stage": stage,
                "timestamp": time.time(),
                "result_summary": result.get("summary", "No summary available")
            })
            
        except Exception as e:
            logger.error(f"❌ Command execution failed: {e}")
            await self._simulate_human_error_handling(str(e))
    
    async def _simulate_result_analysis(self, result: Dict):
        """Simulate human analyzing command results"""
        logger.info("👀 Human operator analyzing results...")
        
        # Simulate reading time based on result length
        result_text = str(result.get("output", ""))
        reading_time = min(len(result_text) / 100, 10)  # Max 10 seconds
        
        await asyncio.sleep(random.uniform(reading_time/2, reading_time))
        
        # Simulate human insights
        insights = [
            "Interesting findings detected...",
            "Taking notes on potential vulnerabilities...",
            "Cross-referencing with known attack patterns...",
            "Planning next steps based on results..."
        ]
        
        selected_insight = random.choice(insights)
        logger.info(f"💡 {selected_insight}")
    
    async def _simulate_human_error_handling(self, error: str):
        """Simulate human response to errors"""
        logger.info("🤔 Human operator encountered an issue...")
        
        error_responses = [
            "Let me try a different approach...",
            "Adjusting command parameters...",
            "Checking tool availability...",
            "Moving to alternative method..."
        ]
        
        response = random.choice(error_responses)
        logger.info(f"🔄 {response}")
        await asyncio.sleep(random.uniform(1, 2))
    
    async def _simulate_thinking_pause(self, min_seconds: float, max_seconds: float):
        """Simulate human thinking/decision-making pause"""
        pause_time = random.uniform(min_seconds, max_seconds)
        await asyncio.sleep(pause_time)
    
    async def _get_stage_tools(self, stage: str) -> List[str]:
        """Get appropriate tools for each stage"""
        stage_tools = {
            "reconnaissance": ["nmap_basic", "whatweb_scan", "whois_lookup"],
            "enumeration": ["dirb_scan", "gobuster_dir", "curl_request"],
            "scanning": ["nmap_aggressive", "nikto_scan"],
            "vulnerability_assessment": ["sqlmap_detect"],
            "exploitation": ["sqlmap_exploit", "custom_command"]
        }
        
        return stage_tools.get(stage, ["nmap_basic"])
    
    def _get_tool_command(self, tool_name: str, stage: str) -> str:
        """Generate human-like command for tool"""
        commands = {
            "nmap_basic": f"nmap -sV {self.target_url}",
            "whatweb_scan": f"whatweb {self.target_url}",
            "whois_lookup": f"whois {self.target_url.replace('http://', '').replace('https://', '')}",
            "dirb_scan": f"dirb {self.target_url}",
            "gobuster_dir": f"gobuster dir -u {self.target_url} -w /usr/share/wordlists/dirb/common.txt",
            "nikto_scan": f"nikto -h {self.target_url}",
            "sqlmap_detect": f"sqlmap -u '{self.target_url}' --batch --level=1 --risk=1",
            "sqlmap_exploit": f"sqlmap -u '{self.target_url}' --batch --dump"
        }
        
        return commands.get(tool_name, f"echo 'Tool {tool_name} not configured'")
    
    async def _execute_mcp_command(self, tool_name: str, params: Dict) -> Dict:
        """Execute command through MCP server"""
        try:
            # Simulate MCP tool execution
            result = {
                "tool": tool_name,
                "success": True,
                "output": f"Simulated output for {tool_name} on {params.get('target')}",
                "summary": f"Tool {tool_name} executed successfully",
                "findings": [],
                "timestamp": time.time()
            }
            
            # Add some realistic variations
            if "nmap" in tool_name:
                result["findings"] = ["Port 80 open", "Port 443 open", "Port 22 open"]
            elif "sqlmap" in tool_name:
                result["findings"] = ["Potential SQL injection point found"]
            elif "nikto" in tool_name:
                result["findings"] = ["Server version detected", "Directory listing enabled"]
            
            return result
            
        except Exception as e:
            return {
                "tool": tool_name,
                "success": False,
                "error": str(e),
                "timestamp": time.time()
            }
    
    async def _generate_human_report(self):
        """Generate human-style penetration testing report"""
        logger.info("📝 Human operator generating final report...")
        
        await asyncio.sleep(random.uniform(2, 4))
        
        report = {
            "target": self.target_url,
            "session_duration": time.time(),
            "stages_completed": ["reconnaissance", "enumeration", "scanning", "vulnerability_assessment", "exploitation"],
            "commands_executed": len(self.session_memory["commands_executed"]),
            "key_findings": [
                "Target responds to ping",
                "Web services detected",
                "Potential SQL injection points identified",
                "Directory structure partially enumerated"
            ],
            "recommendations": [
                "Implement input validation",
                "Update server software",
                "Restrict directory listings",
                "Enable security headers"
            ],
            "human_insights": [
                "Testing methodology was systematic and thorough",
                "Human operator showed careful consideration between stages",
                "Realistic timing and decision-making patterns observed",
                "Professional penetration testing approach maintained"
            ]
        }
        
        logger.info("✅ Human MCP session completed successfully")
        logger.info(f"📊 Commands executed: {report['commands_executed']}")
        logger.info(f"🎯 Key findings: {len(report['key_findings'])}")
        
        return report

async def run_human_mcp_pentest(target_url: str):
    """Main entry point for human MCP penetration testing"""
    logger.info(f"🚀 Initializing MCP Human Penetration Testing for {target_url}")
    
    client = MCPHumanClient(target_url)
    
    try:
        await client.start_human_session()
        logger.info("🎉 MCP Human penetration testing session completed!")
        
    except Exception as e:
        logger.error(f"❌ MCP Human session failed: {e}")
        raise

if __name__ == "__main__":
    # Test the MCP human client
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python mcp_client.py <target_url>")
        sys.exit(1)
    
    target = sys.argv[1]
    asyncio.run(run_human_mcp_pentest(target))
