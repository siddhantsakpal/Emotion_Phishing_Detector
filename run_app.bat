@echo off

cd /d "%~dp0"

call venv\Scripts\activate

cd web

python app.py

pause