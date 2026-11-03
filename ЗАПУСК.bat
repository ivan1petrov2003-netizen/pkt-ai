@echo off
rem pkt-ai server launcher (ASCII only for cmd compatibility)
title pkt-ai server
cd /d "%~dp0service"
if not exist .env (
  echo File service\.env not found. Put OPENAI_API_KEY=your_key there.
  echo OPENAI_API_KEY=> .env
  echo Template .env created. Put your key in it and run again.
  pause
  exit /b
)
echo ================================================
echo   pkt-ai server starting...
echo   Browser will open in 5 seconds.
echo   To stop: close this window.
echo ================================================
start "" /min cmd /c "timeout /t 5 /nobreak >nul && start http://127.0.0.1:8317"
python -m uvicorn app:app --host 127.0.0.1 --port 8317
echo.
echo Server stopped.
pause
