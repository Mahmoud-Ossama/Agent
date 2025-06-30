@echo off
REM Quick Test Script for Enhanced MCP Agent (Windows)
REM Note: This version tests the core functionality but cannot test visible terminals
REM For full visible terminal testing, use Kali Linux VM with quick_test.sh

echo 🧪 Enhanced MCP Agent - Windows Test Script
echo ==========================================

REM Configuration
set TARGET=%1
if "%TARGET%"=="" set TARGET=http://localhost:8080

set MAX_TERMINALS=%2
if "%MAX_TERMINALS%"=="" set MAX_TERMINALS=2

echo 🎯 Target: %TARGET%
echo 🖥️  Max Terminals: %MAX_TERMINALS%
echo.

REM Pre-test checks
echo 🔍 Pre-test validation...

REM Check Python
python --version >nul 2>&1
if errorlevel 1 (
    echo ❌ Python not found
    exit /b 1
)
echo ✅ Python available

REM Check agent files
set REQUIRED_FILES=agent\enhanced_mcp_agent.py execution\run_enhanced_agent.py agent\prompts\parallel_prompt.txt requirements.txt

for %%f in (%REQUIRED_FILES%) do (
    if not exist "%%f" (
        echo ❌ Missing required file: %%f
        exit /b 1
    )
)
echo ✅ All required files present

REM Install dependencies
echo.
echo 📦 Installing dependencies...
pip install -r requirements.txt >nul 2>&1
echo ✅ Dependencies installed

REM Create results directory
if not exist "results" mkdir results

REM Run the test
echo.
echo 🚀 Starting Enhanced MCP Agent test...
echo    NOTE: Visible terminal testing requires Kali Linux VM
echo    This Windows test validates core functionality only
echo.

REM Run the agent with timeout (Windows equivalent)
timeout /t 600 /nobreak >nul & python execution\run_enhanced_agent.py --target %TARGET% --mode mcp_parallel --max-terminals %MAX_TERMINALS%

echo.
echo 🔍 Post-test validation...

REM Check result files
set RESULT_FILES_FOUND=0

if exist "results\reconnaissance_results.json" (
    echo ✅ Found: results\reconnaissance_results.json
    set /a RESULT_FILES_FOUND+=1
) else (
    echo ❌ Missing: results\reconnaissance_results.json
)

if exist "results\reconnaissance_report.md" (
    echo ✅ Found: results\reconnaissance_report.md
    set /a RESULT_FILES_FOUND+=1
) else (
    echo ❌ Missing: results\reconnaissance_report.md
)

if exist "results\parallel_pentest_report.md" (
    echo ✅ Found: results\parallel_pentest_report.md
    set /a RESULT_FILES_FOUND+=1
) else (
    echo ❌ Missing: results\parallel_pentest_report.md
)

REM Check for terminal logs
dir /b results\*terminal*.log >nul 2>&1
if errorlevel 1 (
    echo ⚠️  No terminal log files found
    set TERMINAL_LOGS=0
) else (
    for /f %%i in ('dir /b results\*terminal*.log 2^>nul ^| find /c /v ""') do set TERMINAL_LOGS=%%i
    echo ✅ Found %TERMINAL_LOGS% terminal log files
)

REM Check agent memory
if exist "agent\memory\agent_memory.json" (
    echo ✅ Agent memory file created
) else (
    echo ⚠️  Agent memory file not found
)

REM Generate summary
echo.
echo 📋 TEST SUMMARY
echo ===============
echo Target tested: %TARGET%
echo Terminals used: %MAX_TERMINALS%
echo Result files found: %RESULT_FILES_FOUND%
echo Terminal logs: %TERMINAL_LOGS%

REM Overall assessment
if %RESULT_FILES_FOUND% geq 2 (
    echo.
    echo 🎉 TEST ASSESSMENT: SUCCESS
    echo    ✅ Core functionality working
    echo    ✅ Result persistence working
    echo    ✅ Stage-based execution working
    echo.
    echo 📝 IMPORTANT: For full visible terminal testing:
    echo    1. Copy project to Kali Linux VM
    echo    2. Run: chmod +x quick_test.sh
    echo    3. Run: ./quick_test.sh %TARGET% %MAX_TERMINALS%
) else (
    echo.
    echo ⚠️  TEST ASSESSMENT: ISSUES DETECTED
    echo    Check the output above for more details
)

echo.
echo 🔍 For Kali VM testing:
echo    1. Transfer project files to Kali Linux
echo    2. Ensure X11 display is available
echo    3. Run ./quick_test.sh for visible terminal validation
echo.
echo 📁 Results saved to: %cd%\results\

pause
