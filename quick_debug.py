#!/usr/bin/env python3

# Quick debug of the commands being blocked
test_commands = [
    "whatweb https://dulms.deltauniv.edu.eg/login.aspx",
    "nmap -sV -sC -A -p- https://dulms.deltauniv.edu.eg/login.aspx", 
    "sqlmap -u 'https://dulms.deltauniv.edu.eg/login.aspx' --batch",
    "nikto -h https://dulms.deltauniv.edu.eg/login.aspx",
    "gobuster dir -u https://dulms.deltauniv.edu.eg/"
]

allowed_tools = [
    'nmap', 'sqlmap', 'nikto', 'dirb', 'gobuster', 'whatweb', 'waybackurls',
    'curl', 'wget', 'netcat', 'nc', 'hydra', 'john', 'hashcat',
    'wpscan', 'enum4linux', 'smbclient', 'dig', 'host', 'whois',
    'ping', 'traceroute', 'masscan', 'wfuzz', 'ffuf', 'grep',
    'cat', 'head', 'tail', 'ls', 'find', 'sort', 'uniq'
]

print("🔍 Command Analysis:")
print("="*60)

for cmd in test_commands:
    first_word = cmd.split()[0] if cmd.split() else ""
    is_allowed = first_word in allowed_tools
    status = "✅ SHOULD BE ALLOWED" if is_allowed else "❌ SHOULD BE BLOCKED"
    
    print(f"Command: {cmd}")
    print(f"First word: '{first_word}'")
    print(f"In allowed list: {first_word in allowed_tools}")
    print(f"Status: {status}")
    print("-" * 60)

print(f"\nAllowed tools list: {allowed_tools}")
