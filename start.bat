@echo off
setlocal EnableExtensions DisableDelayedExpansion
title BYE-BYE-BLOCK

rem Double-click launcher. No administrator rights or system proxy changes.
rem Keep this file ASCII-only so it works with any Windows console code page.
set "BBB_ROOT=%~dp0"
set "BBB_HELPER=%BBB_ROOT%scripts\launch.py"

if not exist "%BBB_HELPER%" (
    echo [ERROR] Missing scripts\launch.py. Extract the whole repository first.
    goto :finished_error
)

call :find_python
if errorlevel 1 goto :missing_python

%BBB_PYTHON% "%BBB_HELPER%" %*
set "BBB_EXIT=%ERRORLEVEL%"
if "%BBB_EXIT%"=="0" goto :finished
if "%BBB_EXIT%"=="130" goto :finished

echo.
echo [ERROR] BYE-BYE-BLOCK stopped with code %BBB_EXIT%.
echo Read the message above. The window stays open so you can copy it.

:finished
if "%BBB_NO_PAUSE%"=="1" exit /b %BBB_EXIT%
echo.
pause
exit /b %BBB_EXIT%

:finished_error
set "BBB_EXIT=1"
goto :finished

:missing_python
echo.
echo [ERROR] Python 3.11 or newer was not found.
echo Install it from https://www.python.org/downloads/windows/
echo Enable "Add python.exe to PATH" in the installer, then run start.bat again.
echo Administrator rights are NOT required by this launcher.
set "BBB_EXIT=1"
goto :finished

:find_python
rem Prefer an existing project environment, then the Python launcher, then PATH.
if exist "%BBB_ROOT%.venv\Scripts\python.exe" (
    set "BBB_PYTHON="%BBB_ROOT%.venv\Scripts\python.exe""
    call :python_is_supported
    if not errorlevel 1 exit /b 0
)

where py.exe >nul 2>&1
if not errorlevel 1 (
    set "BBB_PYTHON=py.exe -3"
    call :python_is_supported
    if not errorlevel 1 exit /b 0
)

where python.exe >nul 2>&1
if not errorlevel 1 (
    set "BBB_PYTHON=python.exe"
    call :python_is_supported
    if not errorlevel 1 exit /b 0
)

where python3.exe >nul 2>&1
if not errorlevel 1 (
    set "BBB_PYTHON=python3.exe"
    call :python_is_supported
    if not errorlevel 1 exit /b 0
)
exit /b 1

:python_is_supported
%BBB_PYTHON% -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)" >nul 2>&1
exit /b %ERRORLEVEL%
