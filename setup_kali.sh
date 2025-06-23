#!/bin/bash
echo "============================================="
echo "Setting up Dynamic AI Penetration Testing Agent"
echo "============================================="

# Create virtual environment
echo "Creating virtual environment..."
python3 -m venv venv

# Activate virtual environment
echo "Activating virtual environment..."
source venv/bin/activate

# Upgrade pip
echo "Upgrading pip..."
pip install --upgrade pip

# Install Python dependencies
echo "Installing Python dependencies..."
pip install -r requirements.txt

# Fix dependency conflicts
echo "Fixing dependency conflicts..."
pip uninstall -y genai
pip install google-generativeai --upgrade

# Make scripts executable
chmod +x run_dynamic.sh
chmod +x setup_kali.sh

echo "============================================="
echo "Setup completed successfully!"
echo "============================================="
echo ""
echo "To run the agent:"
echo "./run_dynamic.sh https://testphp.vulnweb.com"
echo ""
echo "Or manually activate the environment:"
echo "source venv/bin/activate"
echo "python execution/run_dynamic_agent.py --target https://testphp.vulnweb.com"
