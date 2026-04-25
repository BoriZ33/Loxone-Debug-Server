@echo off
cd /d "%~dp0"
echo Installiere Abhaengigkeiten...
"C:\Users\silas\AppData\Local\Python\pythoncore-3.14-64\python.exe" -m pip install flask -q
echo.
echo Starte Loxone Debug Server...
"C:\Users\silas\AppData\Local\Python\pythoncore-3.14-64\python.exe" udp_logger.py
pause
