# MCP-Enhanced Kali Linux Control

## Model Context Protocol Integration for Human-like Penetration Testing

This document explains the MCP (Model Context Protocol) features that enable human-like control of Kali Linux tools for penetration testing.

## 🎯 What is MCP Mode?

MCP mode transforms the penetration testing agent from using static tools to dynamically controlling Kali Linux through intelligent decision-making. Instead of pre-programmed tool sequences, the LLM decides what commands to execute based on real-time analysis.

### Key Features:
- **Human-like Typing Simulation**: Realistic typing patterns with delays and occasional corrections
- **Intelligent Tool Selection**: LLM chooses appropriate tools based on findings
- **Dynamic Command Construction**: Commands built dynamically with proper parameters
- **Context-Aware Decisions**: Each decision considers previous findings and current stage
- **Safety Controls**: Command validation and execution limits

## 🚀 Available MCP Modes

### 1. MCP Basic Mode (`mcp_basic`)
- Clean MCP server integration
- Tool-based approach with structured parameters
- Good for systematic, methodical testing

### 2. MCP Human Mode (`mcp_human`)
- Simulates human typing behaviors
- Includes thinking pauses and analysis time
- Realistic command execution flow
- Most human-like experience

## 🛠️ MCP Tools Available

### Reconnaissance Tools
- `nmap_basic` - Basic port scanning
- `nmap_aggressive` - Comprehensive port scanning
- `whatweb_scan` - Web technology identification
- `whois_lookup` - Domain information lookup

### Enumeration Tools
- `dirb_scan` - Directory brute forcing
- `gobuster_dir` - Fast directory/file discovery
- `curl_request` - Custom HTTP requests

### Scanning Tools
- `nikto_scan` - Web vulnerability scanning
- Advanced nmap configurations

### Vulnerability Assessment
- `sqlmap_detect` - SQL injection detection
- `sqlmap_exploit` - SQL injection exploitation

## 🎮 Usage Examples

### Basic MCP Mode
```bash
python execution/run_enhanced_agent.py --target http://example.com --mode mcp_basic
```

### Human-like MCP Mode
```bash
python execution/run_enhanced_agent.py --target http://example.com --mode mcp_human
```

### With Custom Settings
```bash
python execution/run_enhanced_agent.py \
  --target http://vulnerable-app.com \
  --mode mcp_human \
  --log-level DEBUG \
  --max-iterations 3
```

## 🧠 How MCP Decision Making Works

### 1. Context Analysis
The LLM analyzes:
- Current penetration testing stage
- Previous command results
- Discovered vulnerabilities
- Target technology stack

### 2. Tool Selection
Based on context, the LLM chooses:
- Most appropriate tool for current situation
- Optimal parameters for the tool
- Expected outcomes

### 3. Human Simulation (mcp_human mode)
- Realistic typing speeds and patterns
- Thinking pauses before commands
- Analysis time after command execution
- Occasional typing corrections

### 4. Execution and Learning
- Command executed safely with timeouts
- Results analyzed for new findings
- Context updated for next decision
- Process repeats until stage completion

## 📊 MCP Workflow Example

```
Stage: Reconnaissance
├── LLM Decision: "Need to identify open ports"
├── Tool Selected: nmap_basic
├── Parameters: {"target": "example.com", "scan_type": "-sV"}
├── Human Typing: Simulates typing "execute nmap_basic target=example.com scan_type=-sV"
├── Execution: nmap -sV example.com
├── Analysis: "Found ports 80, 443, 22 open"
├── Next Decision: "Should scan web services"
└── Tool Selected: whatweb_scan
```

## 🔧 MCP Configuration

### Environment Variables
```env
# MCP-specific settings
MCP_MAX_ITERATIONS=5
MCP_COMMAND_TIMEOUT=300
MCP_ENABLE_HUMAN_SIMULATION=true
MCP_TYPING_SPEED=normal
MCP_THINKING_TIME=2.0
```

### Human Typing Configuration
```python
typing_speeds = {
    'fast': 0.05,    # Professional typist
    'normal': 0.1,   # Average user
    'slow': 0.2,     # Cautious typing
    'thinking': 0.5  # Considering options
}
```

## 🛡️ Security Features

### Command Validation
- Whitelist of allowed penetration testing tools
- Blacklist of dangerous system commands
- Parameter sanitization
- Execution timeouts

### Safe Execution Environment
- Sandboxed command execution
- Resource usage monitoring
- Automatic cleanup of temporary files
- Process termination on timeout

## 📈 Output and Reporting

### MCP-Specific Reports
- `mcp_full_report.json` - Complete session data
- `mcp_readable_report.md` - Human-readable analysis
- `human_mcp_detailed_report.json` - Human simulation details
- Tool-specific output files

### Session Logging
- All LLM decisions recorded
- Command typing simulations logged
- Execution times and results tracked
- Full audit trail maintained

## 🎛️ Advanced MCP Features

### Custom Tool Integration
Add new tools to the MCP server:
```python
tools['custom_tool'] = MCPTool(
    name="custom_tool",
    description="Custom penetration testing tool",
    parameters={"target": {"type": "string"}},
    category="custom",
    risk_level="medium"
)
```

### Stage-based Tool Recommendations
MCP automatically suggests tools based on current stage:
- Reconnaissance: nmap, whatweb, whois
- Enumeration: dirb, gobuster, curl
- Scanning: nikto, nmap aggressive
- Vulnerability Assessment: sqlmap detection
- Exploitation: sqlmap exploitation

## 🚨 Best Practices

### For MCP Human Mode
- Use with authorized targets only
- Monitor resource usage during long scans
- Review typing simulation logs for realism
- Adjust typing speed based on scenario

### For MCP Basic Mode
- Good for automated, systematic testing
- Suitable for CI/CD integration
- Reliable for consistent results
- Less resource intensive

## 🔍 Troubleshooting MCP Issues

### Common Problems
1. **LLM Decision Errors**: Check API keys and connectivity
2. **Tool Execution Failures**: Verify tool installation
3. **Typing Simulation Issues**: Check timing configurations
4. **Memory Issues**: Reduce max iterations or clear memory

### Debug Mode
```bash
python execution/run_enhanced_agent.py \
  --target http://example.com \
  --mode mcp_human \
  --log-level DEBUG
```

## 🤝 Contributing to MCP Features

### Adding New Tools
1. Define tool in `mcp_server.py`
2. Add command building logic
3. Test with various parameters
4. Update documentation

### Improving Human Simulation
1. Analyze real typing patterns
2. Add realistic error patterns
3. Implement context-aware pauses
4. Test with different user profiles

## 📚 MCP Protocol References

The MCP implementation follows standard patterns:
- Structured tool definitions
- Parameter validation
- Result standardization
- Error handling protocols

For more details on MCP, visit: [Model Context Protocol Documentation](https://spec.modelcontextprotocol.io/)

---

**Note**: MCP mode is designed for authorized penetration testing only. Always ensure proper authorization before testing any target system.
