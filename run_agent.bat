@echo off
echo ========================================
echo Enhanced AI Penetration Testing Agent
echo    MCP-Enabled Kali Linux Control  
echo ========================================
echo.

REM Check if Python is installed
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: Python is not installed or not in PATH
    echo Please install Python 3.8+ and try again
    pause
    exit /b 1
)

REM Check if target is provided
if "%1"=="" (
    echo Usage: run_agent.bat ^<target_url^> [mode]
    echo.
    echo Available Modes:
    echo   intelligent  - AI-driven strategic decisions (default)
    echo   dynamic      - Direct command execution focus
    echo   mcp_basic    - MCP-controlled basic mode
    echo   mcp_human    - MCP with human-like typing simulation
    echo.
    echo Examples:
    echo   run_agent.bat http://example.com
    echo   run_agent.bat example.com intelligent
    echo   run_agent.bat 192.168.1.100 mcp_human
    echo   run_agent.bat vulnerable-app.local dynamic
    echo.
    pause
    exit /b 1
)

set TARGET=%1
set MODE=%2

if "%MODE%"=="" set MODE=intelligent

echo Target: %TARGET%
echo Mode: %MODE%
echo.

REM Install requirements if needed
if not exist "venv\" (
    echo Creating virtual environment...
    python -m venv venv
)

echo Activating virtual environment...
call venv\Scripts\activate.bat

echo Installing/updating requirements...
pip install -r requirements.txt

echo.
echo Starting penetration test with %MODE% mode...
echo ========================================
echo.

REM Run the agent with appropriate mode
if "%MODE%"=="mcp_human" (
    echo 🤖 Running MCP Human-like Mode
    echo This mode simulates human typing and behavior
    echo.
) else if "%MODE%"=="mcp_basic" (
    echo 🔌 Running MCP Basic Mode  
    echo This mode uses Model Context Protocol
    echo.
) else if "%MODE%"=="dynamic" (
    echo ⚡ Running Dynamic Mode
    echo This mode focuses on direct command execution
    echo.
) else (
    echo 🧠 Running Intelligent Mode
    echo This mode uses AI-driven strategic decisions
    echo.
)

python execution\run_enhanced_agent.py --target %TARGET% --mode %MODE%

echo.
echo ========================================
echo Penetration test completed!
echo Check the 'results' folder for outputs
echo ========================================
pause
