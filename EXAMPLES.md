# Enhanced AI Penetration Testing Agent - Usage Examples

## Quick Start Examples

### 1. Basic Intelligent Mode
```bash
python execution/run_enhanced_agent.py --target http://testphp.vulnweb.com
```

### 2. Dynamic Command Mode
```bash
python execution/run_enhanced_agent.py --target http://demo.testfire.net --mode dynamic
```

### 3. Local Target Testing
```bash
python execution/run_enhanced_agent.py --target http://localhost:8080/webapp --mode intelligent
```

### 4. Debug Mode with Custom Output
```bash
python execution/run_enhanced_agent.py \
  --target http://vulnerable-app.local \
  --mode intelligent \
  --log-level DEBUG \
  --output-dir ./test_results_$(date +%Y%m%d)
```

## Using the Batch/Shell Scripts

### Windows
```cmd
# Basic usage
run_agent.bat http://example.com

# With specific mode
run_agent.bat http://testsite.com dynamic
```

### Linux/Mac
```bash
# Make executable first
chmod +x run_agent.sh

# Basic usage
./run_agent.sh http://example.com

# With specific mode
./run_agent.sh http://testsite.com intelligent
```

## Environment Configuration Examples

### Example .env file for Gemini
```env
LLM_PROVIDER=gemini
GEMINI_API_KEY=AIzaSyD_your_actual_api_key_here
```

### Example .env file for OpenAI
```env
LLM_PROVIDER=openai
OPENAI_API_KEY=sk-your_actual_api_key_here
OPENAI_ENGINE=gpt-4
OPENAI_MAX_TOKENS=2000
OPENAI_TEMPERATURE=0.7
```

### Example .env file for Local Ollama
```env
LLM_PROVIDER=ollama
OLLAMA_URL=http://localhost:11434
```

## Expected Output Structure

After running the agent, you'll find:

```
results/
├── intelligent_pentest_report.md    # Main AI-generated report
├── complete_memory.json             # Full memory dump
├── command_history.json             # All executed commands
├── reconnaissance_intelligent.txt   # Stage-specific outputs
├── enumeration_intelligent.txt
├── scanning_intelligent.txt
├── vulnerability_assessment_intelligent.txt
├── exploitation_intelligent.txt
└── pentest_YYYYMMDD_HHMMSS.log     # Detailed logs
```

## Testing Against Safe Targets

### Recommended Practice Targets
- http://testphp.vulnweb.com (Acunetix test site)
- http://demo.testfire.net (IBM Security test site)
- http://zero.webappsecurity.com (Zero Bank test site)
- Local DVWA installation
- Local bWAPP installation

### Sample Session Flow

1. **Start with reconnaissance**
   - Agent runs: `nmap -sV target.com`
   - Agent runs: `whatweb target.com`

2. **Move to enumeration**
   - Agent runs: `dirb http://target.com`
   - Agent runs: `nikto -h target.com`

3. **Vulnerability scanning**
   - Agent runs: `sqlmap -u "http://target.com/page.php?id=1" --batch`
   - Agent analyzes results and decides next steps

4. **Exploitation (if applicable)**
   - Agent attempts safe SQL injection demonstration
   - Documents findings and impact

5. **Report generation**
   - AI analyzes all findings
   - Generates comprehensive report
   - Provides remediation recommendations

## Customization Examples

### Custom Prompts
Edit `agent/prompts/dynamic_prompt.txt` to customize AI behavior:

```
You are a specialized SQL injection tester focusing on:
- E-commerce applications
- Payment processing systems
- User authentication bypasses
```

### Stage-specific Focus
You can modify the intelligent chain to focus on specific stages:

```python
# In your custom script
agent = EnhancedPenTestAgent(target_url)
agent.max_iterations_per_stage = 3  # Limit iterations
agent.run_intelligent_stage("vulnerability_assessment")  # Run specific stage
```

## Troubleshooting Common Issues

### LLM API Issues
```bash
# Test your API key
python -c "
from llm.llm_interface import get_llm
llm = get_llm()
print(llm.generate('Hello'))
"
```

### Command Execution Issues
- Ensure you're running on Linux/WSL for best tool compatibility
- Check that tools like nmap, sqlmap are installed
- Verify target is reachable: `ping target.com`

### Memory Issues
- Clear memory between tests: `rm agent/memory/agent_memory.json`
- Reduce max iterations for large targets
- Use `--log-level ERROR` to reduce output

## Advanced Usage

### Integration with CI/CD
```yaml
# .github/workflows/security-test.yml
name: Security Test
on: [push]
jobs:
  pentest:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Run Penetration Test
        run: |
          python execution/run_enhanced_agent.py \
            --target ${{ secrets.TEST_TARGET }} \
            --mode intelligent
```

### Batch Testing Multiple Targets
```bash
# test_multiple.sh
#!/bin/bash
targets=("http://target1.com" "http://target2.com" "http://target3.com")

for target in "${targets[@]}"; do
    echo "Testing $target"
    python execution/run_enhanced_agent.py \
      --target "$target" \
      --output-dir "results_$(basename $target)"
done
```

Remember: Always ensure you have proper authorization before testing any target!
