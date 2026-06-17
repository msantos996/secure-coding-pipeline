@echo off
REM =============================================================
REM  stop_services.bat
REM  Para todos os servicos do projeto (Juice Shop na porta 3000).
REM =============================================================

echo [Stop] A procurar processo na porta 3000 (Juice Shop)...

for /f "tokens=5" %%p in ('netstat -ano ^| findstr ":3000 " ^| findstr "LISTENING"') do (
    echo [Stop] A terminar PID %%p...
    taskkill /PID %%p /F >nul 2>&1
    echo [Stop] Juice Shop terminado.
    goto :done
)

echo [Stop] Nenhum processo encontrado na porta 3000.

:done
echo [Stop] Concluido.
pause
