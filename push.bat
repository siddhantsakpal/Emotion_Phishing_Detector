@echo off
cd /d "%~dp0"
echo.
echo ================================
echo   Pushing to GitHub...
echo ================================
echo.
git add .
git commit -m "Update project files"
git push origin main
echo.
echo ================================
echo   Done! Check GitHub to verify
echo ================================
pause
