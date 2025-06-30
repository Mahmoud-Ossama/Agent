@echo off
echo.
echo ================================================================
echo    Enhanced AI-Powered Penetration Testing Agent - Parallel Mode
echo ================================================================
echo.
echo This script runs the agent in multi-terminal parallel mode
echo for maximum efficiency and professional pentesting methodology.
echo.

if "%1"=="" (
    echo Usage: run_parallel_agent.bat ^<target^> [terminals]
    echo.
    echo Examples:
    echo   run_parallel_agent.bat http://example.com
    echo   run_parallel_agent.bat example.com 8
    echo   run_parallel_agent.bat 192.168.1.100 2
    echo.
    goto :end
)

set TARGET=%1
set TERMINALS=%2

if "%TERMINALS%"=="" (
    set TERMINALS=4
)

echo Target: %TARGET%
echo Parallel Terminals: %TERMINALS%
echo Mode: MCP Parallel Execution
echo.
echo Starting parallel penetration test...
echo.

python execution/run_enhanced_agent.py --target "%TARGET%" --mode mcp_parallel --max-terminals %TERMINALS%

echo.
echo ================================================================
echo Parallel penetration test completed!
echo Check the 'results' folder for detailed reports.
echo ================================================================

:end
pause
