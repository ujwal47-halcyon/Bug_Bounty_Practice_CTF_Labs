@echo off
echo =======================================================
echo NexusCloud 2026 - Stored XSS CTF Lab
echo =======================================================
echo.
echo Installing dependencies...
pip install -r requirements.txt
echo.
echo Starting server...
python app.py
pause
