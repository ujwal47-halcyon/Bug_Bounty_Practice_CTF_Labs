@echo off
echo.
echo ============================================================
echo  SkillForge XSS Lab - Starting...
echo ============================================================
echo.
echo Installing dependencies...
pip install -r requirements.txt
echo.
echo Starting Flask application...
echo.
python app.py
pause
