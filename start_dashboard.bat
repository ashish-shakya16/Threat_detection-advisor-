@echo off
REM Quick Start Script for Cybersecurity Threat Advisor Dashboard

echo ======================================================================
echo   Cybersecurity Threat Advisor - Dashboard Launcher
echo ======================================================================
echo.

REM Activate virtual environment
echo [1/2] Activating virtual environment...
call venv\Scripts\activate.bat

REM Start dashboard
echo [2/2] Starting web dashboard...
echo.
echo Dashboard will be available at: http://localhost:5000
echo Press CTRL+C to stop the server
echo.
python src\dashboard\app.py
