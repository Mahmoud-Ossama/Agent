# Project Understanding Prompt for Copilot Agent

## Project Overview
You are working with an **Enhanced Multi-Terminal MCP Penetration Testing Agent** that conducts parallel penetration testing across multiple visible terminal windows. This is a sophisticated AI-powered security testing tool designed to simulate professional penetration testing methodology.

## Core Architecture

### 1. Project Structure
```
agent/
├── enhanced_mcp_agent.py          # Main parallel execution engine
├── mcp_agent.py                   # MCP mode controller
├── main_agent.py                  # Primary agent logic
├── dynamic_agent.py               # Dynamic testing logic
├── chains/
│   ├── attack_chain.py            # Attack sequence management
│   └── intelligent_chain.py       # AI-powered analysis
├── memory/
│   └── agent_memory.json         # Persistent memory storage
└── prompts/
    ├── dynamic_prompt.txt         # Main AI instructions
    └── parallel_prompt.txt        # Parallel execution instructions

execution/
└── run_enhanced_agent.py         # Main execution script

llm/
└── llm_interface.py              # LLM integration (OpenAI, Gemini, Ollama)

results/                          # All test results and reports
├── reconnaissance_results.json
├── enumeration_results.json  
├── vulnerability_analysis_results.json
├── exploitation_results.json
├── terminal_logs/               # Individual terminal session logs
├── terminal_scripts/            # Generated terminal scripts
└── parallel_pentest_report.md  # Final comprehensive report
```

### 2. Execution Modes
- **mcp_parallel**: Multi-terminal parallel execution with visible terminals
- **mcp**: Standard MCP mode
- **dynamic**: Dynamic testing mode
- **standard**: Basic execution mode

### 3. Core Functionality

#### **Multi-Terminal Parallel Execution**
The system opens **4 visible terminal windows simultaneously** and executes penetration testing commands in parallel following professional methodology:

**Stage Dependencies:**
```
Reconnaissance → Enumeration → Vulnerability Analysis → Exploitation
```

**Parallel Execution Per Stage:**
- **Reconnaissance**: All 4 terminals execute simultaneously (no dependencies)
- **Enumeration**: All 4 terminals execute after reconnaissance data available
- **Vulnerability Analysis**: All 4 terminals execute after service enumeration
- **Exploitation**: 3 terminals execute after vulnerabilities identified

#### **Human-Like Terminal Simulation**
Each visible terminal window displays:
- Terminal setup with target information
- Thinking delays (3 seconds) before command execution
- Typing simulation delays (2 seconds)
- Real command execution with live output
- Professional formatting and window titles

### 4. Key Classes and Methods

#### **MultiTerminalController**
```python
class MultiTerminalController:
    def __init__(self, target_url: str, max_terminals: int = 4)
    def initialize_terminals()                    # Setup visible terminal sessions
    def get_stage_commands(stage: str)           # Get commands for each stage
    def execute_command_in_terminal(cmd)         # Execute in visible terminal
    def execute_stage_parallel(stage: str)       # Run entire stage in parallel
    def run_full_parallel_assessment()          # Complete penetration test
```

#### **TerminalSession**
```python
@dataclass
class TerminalSession:
    terminal_id: int
    process: subprocess.Popen           # Visible terminal process
    window_title: str                   # Terminal window title
    script_file: str                    # Generated script path
    session_history: List[Dict]         # Command history
```

#### **ParallelCommand**
```python
@dataclass  
class ParallelCommand:
    command: str                        # Shell command to execute
    stage: str                         # Stage name (reconnaissance, etc.)
    terminal_id: int                   # Which terminal (0-3)
    expected_duration: float           # Expected execution time
    category: str                      # Command category (port_scan, etc.)
```

### 5. Stage Execution Details

#### **Reconnaissance Stage (4 terminals parallel)**
```python
Terminal 0: whois {domain}
Terminal 1: nslookup {domain}  
Terminal 2: dig {domain} ANY
Terminal 3: theHarvester -d {domain} -b all -l 50
```

#### **Enumeration Stage (4 terminals parallel)**
```python
Terminal 0: nmap -sS -Pn -T4 {domain}
Terminal 1: nmap -sV -T4 {domain}
Terminal 2: nmap -sC -T4 {domain}
Terminal 3: whatweb {url}
```

#### **Vulnerability Analysis Stage (4 terminals parallel)**
```python
Terminal 0: nmap --script vuln -T4 {domain}
Terminal 1: nikto -h {url} -maxtime 300
Terminal 2: dirb {url}/ -w
Terminal 3: sqlmap -u '{url}' --batch --crawl=2 --timeout=60 --retries=0
```

#### **Exploitation Stage (3 terminals parallel)**
```python
Terminal 0: msfconsole -q -x 'search {domain}; exit'
Terminal 1: searchsploit apache
Terminal 2: hydra -l admin -P /usr/share/wordlists/rockyou.txt {domain} http-get -t 4 -W 30
```

### 6. Result Management

#### **Mandatory Result Files Generated:**
- `results/reconnaissance_results.json` - Complete reconnaissance data
- `results/enumeration_results.json` - Service discovery and attack surface
- `results/vulnerability_analysis_results.json` - Security vulnerabilities with risk assessment
- `results/exploitation_results.json` - Exploitation attempts and impact analysis
- `results/parallel_pentest_report.md` - Final comprehensive report

#### **JSON Structure for Each Stage:**
```json
{
  "stage": "stage_name",
  "completed": true,
  "total_commands": number,
  "successful_commands": number, 
  "total_execution_time": seconds,
  "timestamp": unix_timestamp,
  "target_url": "target",
  "terminals_used": 4,
  "results": [
    {
      "command": "executed_command",
      "terminal_id": number,
      "category": "command_category", 
      "success": boolean,
      "stdout": "command_output",
      "execution_time": seconds,
      "visible_terminal": true
    }
  ],
  "findings_summary": ["key_findings"],
  "vulnerabilities_found": [
    {
      "type": "vulnerability_type",
      "severity": "High/Medium/Low", 
      "location": "where_found",
      "description": "detailed_description"
    }
  ],
  "next_stage_recommendations": ["recommendations"]
}
```

### 7. LLM Integration
The system integrates with multiple LLM providers:
- **OpenAI**: GPT-4, GPT-3.5-turbo
- **Google Gemini**: gemini-pro, gemini-1.5-pro
- **Ollama**: Local models (llama2, mistral, etc.)

### 8. Environment Requirements
- **Platform**: Kali Linux VM (primary deployment)
- **Python**: 3.8+ with virtual environment
- **Terminal Emulators**: gnome-terminal, xterm, konsole
- **Dependencies**: subprocess, threading, concurrent.futures, json, time, logging

### 9. Execution Command
```bash
python execution/run_enhanced_agent.py --target http://testphp.vulnweb.com --mode mcp_parallel --max-terminals 4
```

### 10. Key Features
- ✅ **Visible Terminal Windows**: Real terminal windows open with human-like typing
- ✅ **Parallel Execution**: Multiple commands run simultaneously per stage
- ✅ **Professional Methodology**: Follows industry-standard penetration testing phases
- ✅ **Comprehensive Reporting**: JSON and markdown reports with detailed findings
- ✅ **AI-Powered Analysis**: Intelligent analysis and recommendations
- ✅ **Cross-Stage Correlation**: Data flows between stages for enhanced testing
- ✅ **Result Persistence**: All outputs saved for compliance and analysis

### 11. Current Issues to Address
The main issue is that **visible terminal windows are not opening** as expected. The system should launch 4 visible terminal windows simultaneously for each stage, but currently commands may be running in background processes instead of visible terminals.

**Expected Behavior**: User should see 4 terminal windows pop up with titles like "MCP Terminal 0 - RECONNAISSANCE" and watch commands being executed with human-like typing simulation.

**Current Behavior**: Commands may be executing in background without visible terminal windows.

This is a sophisticated penetration testing automation platform designed to provide both efficiency through parallel execution and visual transparency through visible terminal windows, making it suitable for educational, demonstration, and professional security assessment purposes.
