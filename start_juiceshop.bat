@echo off
REM =============================================================
REM  start_juiceshop.bat
REM  Arranca o OWASP Juice Shop numa nova janela do terminal.
REM  Requisito: setup_juiceshop.bat ja ter sido executado antes.
REM =============================================================

set SCRIPT_DIR=%~dp0
set JUICE_DIR=%SCRIPT_DIR%..\juice-shop

if not exist "%JUICE_DIR%\app.ts" (
    echo ERRO: Juice Shop nao encontrado em %JUICE_DIR%
    echo Corre primeiro: setup_juiceshop.bat
    pause
    exit /b 1
)

echo [Start] A arrancar o Juice Shop em nova janela...
start "OWASP Juice Shop" cmd /k "cd /d "%JUICE_DIR%" && npx tsx app.ts"

echo [Start] Juice Shop a arrancar...
echo [Start] Disponivel em: http://localhost:3000
echo [Start] (aguarda ~10 segundos ate estar pronto)
