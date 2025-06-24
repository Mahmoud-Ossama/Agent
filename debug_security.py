#!/usr/bin/env python3

# Debug script to test security filtering
import sys
import os

# Add the project root to the Python path
sys.path.insert(0, os.path.abspath('.'))

from agent.dynamic_agent import DynamicPenTestAgent

def test_security_filter():
    """Test the security filter with sample commands"""
    agent = DynamicPenTestAgent("https://example.com")
    
    test_commands = [
        "whatweb https://dulms.deltauniv.edu.eg/login.aspx",
        "nmap -sV -sC -A -p- https://dulms.deltauniv.edu.eg/login.aspx", 
        "sqlmap -u 'https://dulms.deltauniv.edu.eg/login.aspx' --batch",
        "nikto -h https://dulms.deltauniv.edu.eg/login.aspx",
        "gobuster dir -u https://dulms.deltauniv.edu.eg/",
        "curl -I https://example.com",
        "rm -rf /",  # Should be blocked
        "ls -la"     # Should be allowed
    ]
    
    print("🔍 Testing Security Filter:")
    print("="*50)
    
    for cmd in test_commands:
        result = agent.is_safe_command(cmd)
        first_word = cmd.split()[0] if cmd.split() else ""
        status = "✅ ALLOWED" if result else "❌ BLOCKED"
        print(f"{status}: {cmd}")
        print(f"   First word: '{first_word}'")
        print()

if __name__ == "__main__":
    test_security_filter()
