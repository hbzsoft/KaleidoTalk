@echo off
chcp 65001 >nul
echo ============================================
echo   KaleidoTalk - Reset All Data and Keys
echo ============================================
echo.
echo This will DELETE the following:
echo.
echo   [Server Keys Directory]
echo     server_keys\  (entire folder)
echo.
echo   [Client Keys Directory]
echo     local_keys\  (entire folder)
echo.
echo   [Server Data Files]
echo     users.json
echo     user_keys.json
echo     invite_codes.json
echo     bans.json
echo     server.log
echo     config.json
echo.
echo   [Other Runtime Files]
echo     *.tmp, *.enc, *.pem, *.key, *.crt (in root)
echo.
set /p confirm=Are you sure you want to delete all files above? (y/N): 
if /i not "%confirm%"=="y" (
    echo Canceled.
    pause
    exit /b 1
)

echo.
echo Deleting files and directories...

:: Delete server_keys directory (and all contents)
if exist "server_keys" (
    rmdir /s /q "server_keys"
    echo   Deleted server_keys\
)

:: Delete local_keys directory (and all contents)
if exist "local_keys" (
    rmdir /s /q "local_keys"
    echo   Deleted local_keys\
)

:: Delete root data files
if exist "users.json"          del "users.json"
if exist "user_keys.json"      del "user_keys.json"
if exist "invite_codes.json"   del "invite_codes.json"
if exist "bans.json"           del "bans.json"
if exist "server.log"          del "server.log"
if exist "config.json"         del "config.json"

:: Delete any temporary or key files in root (optional)
del /q "*.tmp" 2>nul
del /q "*.enc" 2>nul
del /q "*.pem" 2>nul
del /q "*.key" 2>nul
del /q "*.crt" 2>nul

echo.
echo Done. All keys, data, and log files have been removed.
echo.
pause