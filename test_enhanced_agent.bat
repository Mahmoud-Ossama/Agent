@echo off
REM Test script for Enhanced MCP Agent with VISIBLE TERMINAL WINDOWS
REM This script tests the enhanced agent that opens multiple visible terminal windows

echo 🔧 Testing Enhanced MCP Agent with VISIBLE TERMINAL WINDOWS...
echo 🎯 Target: http://testphp.vulnweb.com
echo 🖥️  Mode: mcp_parallel (with visible terminals)
echo.
echo ⚠️  IMPORTANT: This test will open multiple terminal windows!
echo    You will see 4 terminal windows opening with human-like typing simulation
echo    Each terminal will show:
echo    - Terminal setup and target information
echo    - Thinking delay simulation
echo    - Typing delay simulation
echo    - Command execution with real output
echo.

REM Check if in correct directory
if not exist "execution\run_enhanced_agent.py" (
    echo ❌ Error: Please run this script from the agent directory
    pause
    exit /b 1
)

REM Check if virtual environment is active
if defined VIRTUAL_ENV (
    echo ✅ Virtual environment active: %VIRTUAL_ENV%
) else (
    echo ⚠️  Warning: No virtual environment detected
    echo    Consider activating venv before running tests
)

REM Create results directory
if not exist "results" mkdir results
echo 📁 Results directory prepared

REM Run the enhanced agent
echo.
echo 🚀 Starting Enhanced MCP Agent test...
echo ⏱️  This test will run with improved timeouts and error handling
echo.

python execution\run_enhanced_agent.py --target http://testphp.vulnweb.com --mode mcp_parallel --max-terminals 4

echo.
echo 🏁 Test completed

REM Check results
if exist "results" (
    echo 📊 Results generated:
    echo    📁 Directory: results\
    dir /b results | findstr /c:".json" /c:".md" /c:".log" >nul 2>&1
    if errorlevel 1 (
        echo    No result files found
    ) else (
        echo    📄 Result files found in results\ directory
    )
) else (
    echo ❌ No results directory found
)

echo.
echo 🔍 To examine detailed results:
echo    type results\parallel_pentest_report.md
echo    type results\reconnaissance_results.json
echo.
pause
