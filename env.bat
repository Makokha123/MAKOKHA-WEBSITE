@echo off
REM Create and activate Python virtual environment in this project
REM Usage in Command Prompt (cmd.exe):
REM   call env.bat

if not exist "myenv\Scripts\python.exe" (
  echo [creating virtual environment at myenv]
  where py >nul 2>nul
  if %ERRORLEVEL%==0 (
    py -3 -m venv myenv
  ) else (
    python -m venv myenv
  )
)

call "myenv\Scripts\activate"
echo.
echo [myenv activated]
python -V
where python
echo.
echo To deactivate, run: deactivate
