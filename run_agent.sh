#!/bin/bash

echo "========================================"
echo "Enhanced AI Penetration Testing Agent"
echo "   MCP-Enabled Kali Linux Control"
echo "========================================"
echo

# Check if Python is installed
if ! command -v python3 &> /dev/null; then
    echo "ERROR: Python 3 is not installed"
    echo "Please install Python 3.8+ and try again"
    exit 1
fi

# Check if target is provided
if [ $# -eq 0 ]; then
    echo "Usage: ./run_agent.sh <target_url> [mode]"
    echo
    echo "Available Modes:"
    echo "  intelligent  - AI-driven strategic decisions (default)"
    echo "  dynamic      - Direct command execution focus"
    echo "  mcp_basic    - MCP-controlled basic mode"
    echo "  mcp_human    - MCP with human-like typing simulation"
    echo
    echo "Examples:"
    echo "  ./run_agent.sh http://example.com"
    echo "  ./run_agent.sh example.com intelligent"
    echo "  ./run_agent.sh 192.168.1.100 mcp_human"
    echo "  ./run_agent.sh vulnerable-app.local dynamic"
    echo
    exit 1
fi

TARGET=$1
MODE=${2:-intelligent}

echo "Target: $TARGET"
echo "Mode: $MODE"
echo

# Create virtual environment if it doesn't exist
if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv venv
fi

echo "Activating virtual environment..."
source venv/bin/activate

echo "Installing/updating requirements..."
pip install -r requirements.txt

echo
echo "Starting penetration test with $MODE mode..."
echo "========================================"
echo

# Display mode information
case $MODE in
    "mcp_human")
        echo "🤖 Running MCP Human-like Mode"
        echo "This mode simulates human typing and behavior"
        echo
        ;;
    "mcp_basic")
        echo "🔌 Running MCP Basic Mode"
        echo "This mode uses Model Context Protocol"
        echo
        ;;
    "dynamic")
        echo "⚡ Running Dynamic Mode"
        echo "This mode focuses on direct command execution"
        echo
        ;;
    *)
        echo "🧠 Running Intelligent Mode"
        echo "This mode uses AI-driven strategic decisions"
        echo
        ;;
esac

# Run the agent
python execution/run_enhanced_agent.py --target "$TARGET" --mode "$MODE"

echo
echo "========================================"
echo "Penetration test completed!"
echo "Check the 'results' folder for outputs"
echo "========================================"
