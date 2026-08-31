@echo off

py -3 "%USERPROFILE%\.codex\hooks\pre_tool_use_secrets.py"

set "rc=%ERRORLEVEL%"

if "%rc%"=="0" (
    exit /b 0
)

>&2 echo BLOCKED: security hook failed to execute correctly. Python exit code: %rc%
exit /b 2