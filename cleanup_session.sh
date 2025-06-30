#!/bin/bash

echo "========================================"
echo "    Session Cleanup Utility"
echo "  AI Penetration Testing Agent"
echo "========================================"
echo

echo "🧹 Cleaning up previous session files..."
echo

# Results directory cleanup
if [ -d "results" ]; then
    echo "📁 Cleaning results directory..."
    rm -f results/*.txt results/*.md results/*.html results/*.json results/*.xml results/*.csv 2>/dev/null
    rm -f results/reconnaissance_* results/enumeration_* results/vulnerability_analysis_* 2>/dev/null
    rm -f results/exploitation_* results/reporting_* results/*_latest.md 2>/dev/null
    echo "    ✅ Results directory cleaned"
else
    echo "    ℹ️  Results directory doesn't exist"
fi

# Agent memory cleanup
if [ -f "agent/memory/agent_memory.json" ]; then
    echo "🧠 Clearing agent memory..."
    rm -f agent/memory/agent_memory.json
    echo "    ✅ Agent memory cleared"
else
    echo "    ℹ️  Agent memory file doesn't exist"
fi

# Main directory report files
echo "📄 Cleaning main directory reports..."
rm -f dynamic_pentest_report.md security_report.html executive_summary.md EXECUTIVE_SUMMARY.md 2>/dev/null
rm -f pentest_report_*.md pentest_report_*.html 2>/dev/null
echo "    ✅ Main directory reports cleaned"

# Tool output files
echo "🔧 Cleaning tool output files..."
rm -f nmap_results.txt nikto_results.txt sqlmap_results.txt dirb_results.txt 2>/dev/null
rm -f whatweb_results.txt curl_results.txt *_output.txt *_scan.txt 2>/dev/null
echo "    ✅ Tool output files cleaned"

# Log files
echo "📋 Cleaning log files..."
rm -f mcp_server.log agent.log pentest.log *.log 2>/dev/null
echo "    ✅ Log files cleaned"

# Python cache cleanup
echo "🐍 Cleaning Python cache files..."
if [ -d "__pycache__" ]; then
    rm -rf __pycache__
    echo "    ✅ Main __pycache__ removed"
fi
if [ -d "agent/__pycache__" ]; then
    rm -rf agent/__pycache__
    echo "    ✅ Agent __pycache__ removed"
fi
if [ -d "agent/chains/__pycache__" ]; then
    rm -rf agent/chains/__pycache__
    echo "    ✅ Chains __pycache__ removed"
fi
if [ -d "llm/__pycache__" ]; then
    rm -rf llm/__pycache__
    echo "    ✅ LLM __pycache__ removed"
fi
if [ -d "execution/__pycache__" ]; then
    rm -rf execution/__pycache__
    echo "    ✅ Execution __pycache__ removed"
fi

# Find and remove any .pyc files
echo "🗑️  Removing compiled Python files..."
find . -name "*.pyc" -delete 2>/dev/null
echo "    ✅ .pyc files removed"

# Temporary session files
echo "🗂️  Cleaning temporary session files..."
rm -f command_history.json session_*.json temp_*.txt tmp_*.txt 2>/dev/null
echo "    ✅ Temporary files cleaned"

# Terminal simulation files (MCP mode)
echo "🖥️  Cleaning terminal simulation files..."
rm -f terminal_session_*.txt mcp_session_*.log 2>/dev/null
echo "    ✅ Terminal simulation files cleaned"

# Make sure results directory exists for next session
if [ ! -d "results" ]; then
    mkdir -p results
    echo "    📁 Results directory recreated"
fi

# Make sure agent memory directory exists
if [ ! -d "agent/memory" ]; then
    mkdir -p agent/memory
    echo "    🧠 Agent memory directory recreated"
fi

echo
echo "========================================"
echo "✨ Session cleanup completed successfully!"
echo "========================================"
echo
echo "🚀 Ready for new penetration testing session"
echo "💡 Use: ./run_agent.sh <target> [mode]"
echo
