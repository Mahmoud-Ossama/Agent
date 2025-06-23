@echo off
echo =============================================
echo Dynamic AI Penetration Testing Agent
echo =============================================

if "%~1"=="" (
    echo Usage: run_agent.bat ^<target^>
    echo Example: run_agent.bat http://example.com
    exit /b 1
)

set TARGET=%~1
echo Target: %TARGET%

cd /d "%~dp0"
python execution/run_dynamic_agent.py --target "%TARGET%"
pause
