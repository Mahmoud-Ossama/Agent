import os
import json
import time
from llm.llm_interface import get_llm
import logging

logger = logging.getLogger(__name__)

class IntelligentAttackChain:
    def __init__(self, target_url, memory_path="agent/memory/agent_memory.json", prompt_path="agent/prompts/dynamic_prompt.txt"):
        self.target_url = target_url
        self.memory_path = memory_path
        self.prompt_path = prompt_path
        self.llm = get_llm()
        self.memory = self.load_memory()
        self.current_stage = "initialization"

    def load_memory(self):
        if os.path.exists(self.memory_path):
            with open(self.memory_path, "r", encoding="utf-8") as f:
                return json.load(f)
        else:
            return {
                "findings": [], 
                "decisions": [], 
                "tools_used": [], 
                "reports": [],
                "command_history": [],
                "vulnerabilities": [],
                "stage_progress": {}
            }

    def save_memory(self):
        with open(self.memory_path, "w", encoding="utf-8") as f:
            json.dump(self.memory, f, indent=2)

    def get_dynamic_prompt(self, stage, context):
        """Generate dynamic prompt based on current stage and context"""
        base_prompt = f"""
You are an elite penetration tester with expertise in SQL injection and web application security.

TARGET: {self.target_url}
CURRENT STAGE: {stage}
CONTEXT: {context}

PREVIOUS FINDINGS:
{json.dumps(self.memory.get('findings', [])[-5:], indent=2)}

VULNERABILITIES FOUND:
{json.dumps(self.memory.get('vulnerabilities', []), indent=2)}

COMMANDS EXECUTED:
{json.dumps([cmd.get('command', '') for cmd in self.memory.get('command_history', [])[-3:]], indent=2)}

Your task is to analyze the current situation and decide what to do next.
You can:
1. Suggest specific terminal commands to execute
2. Analyze findings and provide insights
3. Recommend next steps based on discovered vulnerabilities
4. Conclude if enough information has been gathered

Respond in JSON format:
{{
    "action_type": "command|analysis|recommendation|conclusion",
    "commands": ["command1", "command2"],
    "analysis": "your analysis of current findings",
    "next_steps": ["step1", "step2"],
    "confidence": 0.8,
    "priority": "high|medium|low"
}}

Focus on SQL injection testing and be methodical in your approach.
"""
        return base_prompt

    def intelligent_decision(self, stage, context):
        """Make intelligent decisions based on current context"""
        prompt = self.get_dynamic_prompt(stage, context)
        
        try:
            response = self.llm.generate(prompt)
            
            # Try to parse JSON response
            try:
                decision = json.loads(response)
            except json.JSONDecodeError:
                # Fallback: extract commands from text response
                decision = {
                    "action_type": "command",
                    "commands": self.extract_commands_from_text(response),
                    "analysis": response[:500],
                    "next_steps": [],
                    "confidence": 0.5,
                    "priority": "medium"
                }
            
            # Store decision
            self.memory["decisions"].append({
                "stage": stage,
                "decision": decision,
                "timestamp": time.time(),
                "context": context[:200] + "..." if len(context) > 200 else context
            })
            self.save_memory()
            
            return decision
            
        except Exception as e:
            logger.error(f"Error making intelligent decision: {str(e)}")
            return {
                "action_type": "command",
                "commands": [f"nmap -sV {self.target_url}"],
                "analysis": f"Error in LLM decision making: {str(e)}",
                "next_steps": ["Continue with basic reconnaissance"],
                "confidence": 0.3,
                "priority": "low"
            }

    def extract_commands_from_text(self, text):
        """Extract commands from unstructured text response"""
        commands = []
        lines = text.split('\n')
        
        for line in lines:
            line = line.strip()
            # Look for lines that look like commands
            if any(tool in line.lower() for tool in ['nmap', 'sqlmap', 'nikto', 'curl', 'wget']):
                # Clean up the command
                if line.startswith('$ '):
                    line = line[2:]
                elif line.startswith('> '):
                    line = line[2:]
                elif line.startswith('- '):
                    line = line[2:]
                
                commands.append(line)
        
        return commands

    def analyze_findings(self, new_findings):
        """Analyze new findings for vulnerabilities and insights"""
        analysis_prompt = f"""
Analyze the following penetration testing findings for vulnerabilities, especially SQL injection:

NEW FINDINGS:
{new_findings}

PREVIOUS VULNERABILITIES:
{json.dumps(self.memory.get('vulnerabilities', []), indent=2)}

Identify:
1. Potential SQL injection points
2. Other web vulnerabilities  
3. Open ports and services
4. Technology stack information
5. Attack vectors

Respond in JSON format:
{{
    "vulnerabilities": [
        {{
            "type": "SQL Injection",
            "location": "parameter/URL",
            "severity": "high|medium|low",
            "description": "detailed description",
            "exploit_suggestion": "how to exploit"
        }}
    ],
    "insights": ["insight1", "insight2"],
    "attack_vectors": ["vector1", "vector2"],
    "recommendations": ["rec1", "rec2"]
}}
"""
        
        try:
            response = self.llm.generate(analysis_prompt)
            analysis = json.loads(response)
            
            # Update vulnerabilities in memory
            if 'vulnerabilities' in analysis:
                self.memory['vulnerabilities'].extend(analysis['vulnerabilities'])
                self.save_memory()
            
            return analysis
            
        except Exception as e:
            logger.error(f"Error analyzing findings: {str(e)}")
            return {
                "vulnerabilities": [],
                "insights": [f"Analysis error: {str(e)}"],
                "attack_vectors": [],
                "recommendations": ["Continue manual analysis"]
            }

    def update_findings(self, finding):
        """Update findings and trigger analysis"""
        self.memory["findings"].append({
            "content": finding,
            "timestamp": time.time(),
            "stage": self.current_stage
        })
        
        # Analyze new findings
        if len(finding) > 100:  # Only analyze substantial findings
            analysis = self.analyze_findings(finding)
            self.memory["findings"].append({
                "content": f"ANALYSIS: {json.dumps(analysis, indent=2)}",
                "timestamp": time.time(),
                "stage": f"{self.current_stage}_analysis"
            })
        
        self.save_memory()

    def update_tools_used(self, tool_name):
        self.memory["tools_used"].append({
            "tool": tool_name,
            "timestamp": time.time(),
            "stage": self.current_stage
        })
        self.save_memory()

    def update_command_history(self, command, output, return_code):
        """Update command history with execution results"""
        self.memory["command_history"].append({
            "command": command,
            "output": output[:1000] + "..." if len(output) > 1000 else output,
            "return_code": return_code,
            "timestamp": time.time(),
            "stage": self.current_stage
        })
        self.save_memory()

    def set_current_stage(self, stage):
        """Set current stage"""
        self.current_stage = stage
        if stage not in self.memory["stage_progress"]:
            self.memory["stage_progress"][stage] = {
                "started": time.time(),
                "status": "in_progress"
            }
        self.save_memory()

    def complete_stage(self, stage):
        """Mark stage as completed"""
        if stage in self.memory["stage_progress"]:
            self.memory["stage_progress"][stage]["status"] = "completed"
            self.memory["stage_progress"][stage]["completed"] = time.time()
        self.save_memory()

    def generate_intelligent_report(self):
        """Generate an intelligent report with LLM analysis"""
        report_prompt = f"""
Generate a comprehensive penetration testing report based on the following data:

TARGET: {self.target_url}

FINDINGS:
{json.dumps(self.memory.get('findings', []), indent=2)}

VULNERABILITIES:
{json.dumps(self.memory.get('vulnerabilities', []), indent=2)}

TOOLS USED:
{json.dumps(self.memory.get('tools_used', []), indent=2)}

COMMAND HISTORY:
{json.dumps([cmd.get('command', '') for cmd in self.memory.get('command_history', [])], indent=2)}

Create a professional penetration testing report in markdown format with:
1. Executive Summary
2. Methodology
3. Findings and Vulnerabilities  
4. Risk Assessment
5. Recommendations
6. Technical Details
7. Appendices

Focus on SQL injection vulnerabilities and web application security.
"""
        
        try:
            report = self.llm.generate(report_prompt)
            
            # Add metadata
            metadata = f"""
# Penetration Testing Report
**Target:** {self.target_url}
**Date:** {time.ctime()}
**Agent:** Dynamic AI Penetration Testing Agent
**Total Commands Executed:** {len(self.memory.get('command_history', []))}
**Vulnerabilities Found:** {len(self.memory.get('vulnerabilities', []))}

---

"""
            
            full_report = metadata + report
            
            self.memory["reports"].append({
                "report": full_report,
                "timestamp": time.time(),
                "type": "intelligent_report"
            })
            self.save_memory()
            
            return full_report
            
        except Exception as e:
            logger.error(f"Error generating intelligent report: {str(e)}")
            return self.generate_basic_report()

    def generate_basic_report(self):
        """Generate basic report as fallback"""
        report_md = f"# Penetration Testing Report\n\n"
        report_md += f"**Target:** {self.target_url}\n"
        report_md += f"**Date:** {time.ctime()}\n\n"
        
        report_md += "## Findings\n"
        for finding in self.memory.get("findings", []):
            content = finding.get("content", str(finding))
            report_md += f"- {content[:200]}...\n"
        
        report_md += "\n## Tools Used\n"
        for tool in set([t.get("tool", str(t)) for t in self.memory.get("tools_used", [])]):
            report_md += f"- {tool}\n"
        
        report_md += "\n## Vulnerabilities\n"
        for vuln in self.memory.get("vulnerabilities", []):
            report_md += f"- **{vuln.get('type', 'Unknown')}**: {vuln.get('description', 'No description')}\n"
        
        return report_md
