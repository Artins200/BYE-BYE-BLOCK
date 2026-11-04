@echo off
setlocal EnableExtensions DisableDelayedExpansion
title Build BYE-BYE-BLOCK.exe

set "BBB_ROOT=%~dp0"
set "BBB_PYTHON=%BBB_ROOT%.venv\Scripts\python.exe"

if not exist "%BBB_PYTHON%" (
    echo [ERROR] Run start.bat --setup-only first to create .venv.
    goto :finished_error
)

"%BBB_PYTHON%" -m pip install --upgrade pyinstaller
if errorlevel 1 goto :finished_error

"%BBB_PYTHON%" -m PyInstaller --noconfirm --clean --onefile --windowed ^
  --name BYE-BYE-BLOCK ^
  --icon "%BBB_ROOT%assets\icon.ico" ^
  --add-data "%BBB_ROOT%assets\icon.png;assets" ^
  --collect-submodules byebyeblock ^
  "%BBB_ROOT%desktop.py"
if errorlevel 1 goto :finished_error

echo.
echo Built: %BBB_ROOT%dist\BYE-BYE-BLOCK.exe
set "BBB_EXIT=0"
goto :finished

:finished_error
set "BBB_EXIT=1"

:finished
if "%BBB_NO_PAUSE%"=="1" exit /b %BBB_EXIT%
echo.
pause
exit /b %BBB_EXIT%
