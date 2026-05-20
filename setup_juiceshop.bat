@echo off
REM =============================================================
REM  setup_juiceshop.bat
REM  Clona e compila o OWASP Juice Shop para uso com o pipeline.
REM  Executar a partir da pasta onde este script se encontra.
REM  Requisitos: Node.js 22+, Git, npm
REM =============================================================

setlocal

set SCRIPT_DIR=%~dp0
set JUICE_DIR=%SCRIPT_DIR%..\juice-shop

echo [1/6] A verificar dependencias...
where node >nul 2>&1 || (echo ERRO: Node.js nao encontrado. Instala em https://nodejs.org && exit /b 1)
where git  >nul 2>&1 || (echo ERRO: Git nao encontrado. Instala em https://git-scm.com && exit /b 1)
echo       Node.js OK  /  Git OK

echo [2/6] A clonar o Juice Shop...
if exist "%JUICE_DIR%" (
    echo       Pasta juice-shop ja existe, a saltar clone.
) else (
    git clone https://github.com/juice-shop/juice-shop --depth=1 "%JUICE_DIR%"
    if errorlevel 1 (echo ERRO: Falha no clone. && exit /b 1)
)

echo [3/6] A instalar dependencias do backend...
cd /d "%JUICE_DIR%"
npm install --ignore-scripts
if errorlevel 1 (echo ERRO: npm install falhou. && exit /b 1)

echo [4/6] A compilar modulos nativos (sqlite3, libxmljs2)...
npm rebuild sqlite3 libxmljs2
if errorlevel 1 (echo AVISO: Falha em modulos nativos opcionais, continuando...)

echo [5/6] A instalar e compilar o frontend Angular...
cd /d "%JUICE_DIR%\frontend"
npm install
if errorlevel 1 (echo ERRO: npm install do frontend falhou. && exit /b 1)
npx ng build --configuration production
if errorlevel 1 (echo ERRO: Build do frontend falhou. && exit /b 1)

echo [6/6] A compilar o servidor TypeScript...
cd /d "%JUICE_DIR%"
npx tsc
if errorlevel 1 (echo ERRO: Compilacao TypeScript falhou. && exit /b 1)

echo.
echo =============================================================
echo  Juice Shop pronto!
echo  Para arrancar: cd ..\juice-shop ^& npx tsx app.ts
echo  Acessivel em:  http://localhost:3000
echo =============================================================
endlocal
