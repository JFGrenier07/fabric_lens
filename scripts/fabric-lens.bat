@echo off
setlocal EnableExtensions
rem ===========================================================================
rem  Fabric Lens - recuperation des donnees
rem ---------------------------------------------------------------------------
rem  Fait rouler fl_extract.py sur le RHEL et rapatrie UN fichier :
rem  fabriclens-data.json. Ensuite, dans fabric-lens.html : bouton "Fichier".
rem
rem  Les chemins des fabriques sont dans le fichier scripts\remote\fabric_path.
rem  Une ligne par fabrique. Ajoute ou retire au besoin.
rem
rem  Prerequis : plink.exe et pscp.exe (PuTTY) dans le PATH, une session PuTTY
rem  Kerberos qui fonctionne.
rem ===========================================================================

rem --- A REGLER : le nom EXACT de ta session PuTTY -------------------------
set "SESSION=RHEL-BACKUPS"

set "REMOTE=~/.fabric-lens"
set "LOCAL=%~dp0..\data"
rem ------------------------------------------------------------------------

set "HERE=%~dp0"
if not exist "%LOCAL%" mkdir "%LOCAL%"

echo.
echo   Fabric Lens - recuperation
echo   ==========================
echo   Session : %SESSION%
echo.

echo [1/3] Envoi des scripts...
plink -batch "%SESSION%" "mkdir -p %REMOTE%" || goto :err
pscp -batch -q "%HERE%remote\fl_extract.py" "%SESSION%:%REMOTE%/fl_extract.py" || goto :err
pscp -batch -q "%HERE%remote\fabric_path"   "%SESSION%:%REMOTE%/fabric_path" || goto :err
pscp -batch -q "%HERE%..\fabriclens\resolve.py" "%SESSION%:%REMOTE%/resolve.py" || goto :err

echo [2/3] Extraction ^(les chemins sont dans fl_extract.py^)...
plink -batch "%SESSION%" "cd %REMOTE% && python3 fl_extract.py" || goto :err

echo [3/3] Rapatriement de fabriclens-data.json...
pscp -batch -p "%SESSION%:%REMOTE%/fabriclens-data.json" "%LOCAL%\" || goto :err

echo.
echo   ==========================
echo   Termine : %LOCAL%\fabriclens-data.json
echo.
echo   Ouvre fabric-lens.html, bouton "Fichier", choisis ce .json.
echo.
endlocal & exit /b 0

:err
echo.
echo   ECHEC. Verifie : le nom de session PuTTY, le ticket Kerberos ^(klist^),
echo   et les chemins dans scripts\remote\fabric_path.
echo.
endlocal & exit /b 1
