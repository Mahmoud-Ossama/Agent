#!/bin/bash

# Test script for Enhanced MCP Agent with VISIBLE TERMINAL WINDOWS
# This script tests the enhanced agent that opens multiple visible terminal windows

echo "🔧 Testing Enhanced MCP Agent with VISIBLE TERMINAL WINDOWS..."
echo "🎯 Target: http://testphp.vulnweb.com"
echo "🖥️  Mode: mcp_parallel (with visible terminals)"
echo ""
echo "⚠️  IMPORTANT: This test will open multiple terminal windows!"
echo "   You will see 4 terminal windows opening with human-like typing simulation"
echo "   Each terminal will show:"
echo "   - Terminal setup and target information"
echo "   - Thinking delay simulation"
echo "   - Typing delay simulation" 
echo "   - Command execution with real output"
echo ""

# Set working directory
cd "$(dirname "$0")"

# Check if in correct directory
if [ ! -f "execution/run_enhanced_agent.py" ]; then
    echo "❌ Error: Please run this script from the agent directory"
    exit 1
fi

# Check if virtual environment is active
if [[ "$VIRTUAL_ENV" != "" ]]; then
    echo "✅ Virtual environment active: $VIRTUAL_ENV"
else
    echo "⚠️  Warning: No virtual environment detected"
    echo "   Consider activating venv before running tests"
fi

# Create results directory
mkdir -p results
echo "📁 Results directory prepared"

# Run the enhanced agent
echo ""
echo "🚀 Starting Enhanced MCP Agent test..."
echo "⏱️  This test will run with improved timeouts and error handling"
echo ""

# Run with timeout protection
timeout 1800 python execution/run_enhanced_agent.py \
    --target http://testphp.vulnweb.com \
    --mode mcp_parallel \
    --max-terminals 4

# Check exit status
exit_status=$?

echo ""
echo "🏁 Test completed with exit status: $exit_status"

# Check results
if [ -d "results" ] && [ "$(ls -A results)" ]; then
    echo "📊 Results generated:"
    echo "   📁 Directory: results/"
    ls -la results/ | head -10
    
    echo ""
    echo "📄 JSON result files:"
    find results/ -name "*.json" -exec basename {} \; 2>/dev/null || echo "   No JSON files found"
    
    echo ""
    echo "📄 Report files:"
    find results/ -name "*.md" -exec basename {} \; 2>/dev/null || echo "   No markdown files found"
    
    echo ""
    echo "📋 Log files:"
    find results/terminal_logs/ -name "*.log" -exec basename {} \; 2>/dev/null || echo "   No log files found"
    
else
    echo "❌ No results generated"
fi

# Exit status explanation
case $exit_status in
    0)
        echo ""
        echo "✅ Test completed successfully!"
        ;;
    124)
        echo ""
        echo "⏰ Test timed out after 30 minutes (safety limit)"
        echo "   This is expected for comprehensive testing"
        ;;
    130)
        echo ""
        echo "⚠️  Test interrupted by user (Ctrl+C)"
        ;;
    *)
        echo ""
        echo "❌ Test failed with exit code $exit_status"
        ;;
esac

echo ""
echo "🔍 To examine detailed results:"
echo "   cat results/parallel_pentest_report.md"
echo "   cat results/reconnaissance_results.json"
echo ""
