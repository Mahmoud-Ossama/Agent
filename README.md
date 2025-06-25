# Enhanced AI-Powered Penetration Testing Agent

An intelligent penetration testing agent that uses Large Language Models (LLM) to dynamically decide which commands to execute during security testing. Instead of static, pre-defined tools, this agent asks the LLM what commands to run based on current findings and context.

## 🌟 Key Features

### Dynamic Command Execution
- **AI-Driven Decisions**: LLM analyzes findings and decides next actions
- **Context-Aware**: Commands chosen based on current stage and discoveries
- **Adaptive Strategy**: Changes approach based on results
- **No Static Tools**: All commands are dynamically generated

### Intelligent Analysis
- **Real-time Vulnerability Analysis**: AI analyzes outputs for vulnerabilities
- **SQL Injection Focus**: Specialized in detecting and exploiting SQL injection
- **Risk Assessment**: Automatic severity classification
- **Smart Reporting**: AI-generated comprehensive reports

### Two Operating Modes

#### 1. Intelligent Mode (Recommended)
- LLM makes strategic decisions about testing approach
- Analyzes findings between commands
- Provides insights and recommendations
- Generates professional reports

#### 2. Dynamic Mode
- Focuses on command execution
- LLM suggests specific terminal commands
- Executes commands safely with validation
- Maintains detailed command history

## 🚀 Quick Start

### Prerequisites
```bash
pip install -r requirements.txt
```

### Environment Setup
Create a `.env` file with your LLM provider configuration:

```env
# Choose your LLM provider
LLM_PROVIDER=gemini  # or openai, ollama

# API Keys (depending on provider)
GEMINI_API_KEY=your_gemini_api_key_here
OPENAI_API_KEY=your_openai_api_key_here

# Optional: Ollama local server
OLLAMA_URL=http://localhost:11434
```

### Basic Usage

#### Intelligent Mode (Default)
```bash
python execution/run_enhanced_agent.py --target http://example.com
```

#### Dynamic Mode
```bash
python execution/run_enhanced_agent.py --target example.com --mode dynamic
```

```
pentest-agent-sqli/
├── agent/
│   ├── main_agent.py
│   ├── dynamic_agent.py
│   ├── mcp_agent.py
│   ├── prompts/
│   │   ├── sqli_prompt.txt
│   │   └── dynamic_prompt.txt
│   ├── chains/
│   │   ├── attack_chain.py
│   │   └── intelligent_chain.py
│   └── memory/
│       └── agent_memory.json
├── llm/
│   └── llm_interface.py
├── execution/
│   └── run_enhanced_agent.py
├── mcp_server.py
├── results/
├── execution/
│   └── run_enhanced_agent.py
├── run_agent.bat
├── run_agent.sh
├── requirements.txt
├── .env.template
├── mcp.yaml
├── README.md
├── MCP_README.md
└── EXAMPLES.md
```
```

## Getting Started

1. Install dependencies:

```bash
pip install -r requirements.txt
```

2. Configure your LLM API keys and settings in `configs/.env`.

3. Build and run the Docker container (optional):

```bash
docker build -t pentest-agent-sqli .
docker run --rm -it pentest-agent-sqli
```

4. Run the agent against a target:

```bash
python execution/run_agent.py --target https://testphp.vulnweb.com
```

5. View generated reports in the `results/` folder.

## Notes

- The agent uses dynamic reasoning chains and memory to simulate human-like penetration testing.
- It supports multiple LLM backends and can be extended with new tools easily.
- The agent is designed for high reliability and realism with no static branching logic.

## License

MIT License
