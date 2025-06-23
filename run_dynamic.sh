#!/bin/bash
echo "============================================="
echo "Dynamic AI Penetration Testing Agent"
echo "============================================="

if [ -z "$1" ]; then
    echo "Usage: $0 <target>"
    echo "Example: $0 http://example.com"
    exit 1
fi

TARGET="$1"
echo "Target: $TARGET"

cd "$(dirname "$0")"

# Check if virtual environment exists and activate it
if [ -d "venv" ]; then
    echo "Activating virtual environment..."
    source venv/bin/activate
else
    echo "Warning: Virtual environment not found. Run ./setup_kali.sh first"
    echo "Continuing with system Python..."
fi

# Run the agent
python3 execution/run_dynamic_agent.py --target "$TARGET"
