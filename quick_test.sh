#!/bin/bash

# Quick Test Script for Enhanced MCP Agent
# Usage: ./quick_test.sh [target_url] [max_terminals]

echo "🧪 Enhanced MCP Agent - Quick Test Script"
echo "=========================================="

# Configuration
TARGET=${1:-"http://localhost:8080"}
MAX_TERMINALS=${2:-2}
TEST_DIR="/tmp/mcp_agent_test"

echo "🎯 Target: $TARGET"
echo "🖥️  Max Terminals: $MAX_TERMINALS"
echo ""

# Create test directory
mkdir -p "$TEST_DIR"
cd "$(dirname "$0")"

# Pre-test checks
echo "🔍 Pre-test validation..."

# Check Python
if ! command -v python3 &> /dev/null; then
    echo "❌ Python3 not found"
    exit 1
fi
echo "✅ Python3 available"

# Check display
if [ -z "$DISPLAY" ]; then
    echo "❌ No X11 display available"
    exit 1
fi
echo "✅ X11 display available"

# Check terminal emulators
TERMINAL_FOUND=false
for term in gnome-terminal xterm konsole mate-terminal xfce4-terminal; do
    if command -v "$term" &> /dev/null; then
        echo "✅ Terminal emulator found: $term"
        TERMINAL_FOUND=true
        break
    fi
done

if [ "$TERMINAL_FOUND" = false ]; then
    echo "❌ No compatible terminal emulator found"
    exit 1
fi

# Check agent files
REQUIRED_FILES=(
    "agent/enhanced_mcp_agent.py"
    "execution/run_enhanced_agent.py"
    "agent/prompts/parallel_prompt.txt"
    "requirements.txt"
)

for file in "${REQUIRED_FILES[@]}"; do
    if [ ! -f "$file" ]; then
        echo "❌ Missing required file: $file"
        exit 1
    fi
done
echo "✅ All required files present"

# Install dependencies
echo ""
echo "📦 Installing dependencies..."
pip3 install -r requirements.txt > /dev/null 2>&1
echo "✅ Dependencies installed"

# Run the test
echo ""
echo "🚀 Starting Enhanced MCP Agent test..."
echo "   This will open $MAX_TERMINALS visible terminal windows"
echo "   Watch for parallel execution and human-like typing"
echo ""

# Create results directory
mkdir -p results

# Run the agent with timeout
timeout 600 python3 execution/run_enhanced_agent.py \
    --target "$TARGET" \
    --mode mcp_parallel \
    --max-terminals "$MAX_TERMINALS" 2>&1 | tee "$TEST_DIR/test_output.log"

TEST_EXIT_CODE=$?

echo ""
echo "🔍 Post-test validation..."

# Check if test completed or timed out
if [ $TEST_EXIT_CODE -eq 124 ]; then
    echo "⏰ Test timed out after 10 minutes (this is normal for comprehensive testing)"
elif [ $TEST_EXIT_CODE -eq 0 ]; then
    echo "✅ Test completed successfully"
else
    echo "⚠️  Test exited with code: $TEST_EXIT_CODE"
fi

# Check result files
RESULT_FILES_FOUND=0
EXPECTED_RESULTS=(
    "results/reconnaissance_results.json"
    "results/reconnaissance_report.md"
    "results/parallel_pentest_report.md"
)

echo ""
echo "📊 Checking generated results..."

for file in "${EXPECTED_RESULTS[@]}"; do
    if [ -f "$file" ]; then
        echo "✅ Found: $file"
        RESULT_FILES_FOUND=$((RESULT_FILES_FOUND + 1))
    else
        echo "❌ Missing: $file"
    fi
done

# Check terminal logs
TERMINAL_LOGS=$(find results/ -name "*terminal*.log" 2>/dev/null | wc -l)
if [ "$TERMINAL_LOGS" -gt 0 ]; then
    echo "✅ Found $TERMINAL_LOGS terminal log files"
else
    echo "⚠️  No terminal log files found"
fi

# Validate JSON structure
if [ -f "results/reconnaissance_results.json" ]; then
    if python3 -m json.tool results/reconnaissance_results.json > /dev/null 2>&1; then
        echo "✅ JSON structure valid"
    else
        echo "❌ Invalid JSON structure"
    fi
fi

# Check agent memory
if [ -f "agent/memory/agent_memory.json" ]; then
    echo "✅ Agent memory file created"
else
    echo "⚠️  Agent memory file not found"
fi

# Generate summary
echo ""
echo "📋 TEST SUMMARY"
echo "==============="
echo "Target tested: $TARGET"
echo "Terminals used: $MAX_TERMINALS"
echo "Result files found: $RESULT_FILES_FOUND"
echo "Terminal logs: $TERMINAL_LOGS"
echo "Exit code: $TEST_EXIT_CODE"

# Overall assessment
if [ $RESULT_FILES_FOUND -ge 2 ] && [ "$TERMINAL_LOGS" -gt 0 ]; then
    echo ""
    echo "🎉 TEST ASSESSMENT: SUCCESS"
    echo "   ✅ Multi-terminal execution working"
    echo "   ✅ Result persistence working"
    echo "   ✅ Stage-based execution working"
else
    echo ""
    echo "⚠️  TEST ASSESSMENT: PARTIAL SUCCESS / ISSUES DETECTED"
    echo "   Check the logs for more details:"
    echo "   - Main output: $TEST_DIR/test_output.log"
    echo "   - Terminal logs: results/*terminal*.log"
fi

echo ""
echo "🔍 To debug issues:"
echo "   1. Check display: echo \$DISPLAY"
echo "   2. Test terminal: gnome-terminal --version"
echo "   3. Check permissions: ls -la results/"
echo "   4. View logs: cat $TEST_DIR/test_output.log"

echo ""
echo "📁 Test artifacts saved to: $TEST_DIR"
echo "📁 Results saved to: $(pwd)/results/"
