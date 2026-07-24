@echo off
setlocal EnableExtensions
rem ===========================================================================
rem  Fabric Lens - version SIMPLE pour les premiers tests
rem ---------------------------------------------------------------------------
rem  Fait rouler fl_extract.py sur le RHEL et rapatrie UN fichier :
rem  fabriclens-data.json. Ensuite, dans le webui (fabric-lens.html deja ouvert),
rem  bouton "Fichier" -> choisir ce .json.
rem
rem  Les chemins des fabriques sont HARDCODES dans le bloc FABRICS en tete de
rem  scripts\remote\fl_extract.py. Ajoute ou retire une ligne au besoin.
rem
rem  Prerequis : plink.exe et pscp.exe (PuTTY) dans le PATH, une session PuTTY
rem  Kerberos qui fonctionne, un ticket valide.
rem ===========================================================================

rem --- A REGLER : le nom EXACT de ta session PuTTY -------------------------
set "SESSION=RHEL-BACKUPS"

rem  Dossier de travail sur le RHEL (cree au besoin) et sortie locale
set "REMOTE=~/.fabric-lens-simple"
set "LOCAL=%~dp0..\data"
rem ------------------------------------------------------------------------

set "HERE=%~dp0"
if not exist "%LOCAL%" mkdir "%LOCAL%"

echo.
echo   Fabric Lens - recuperation simple
echo   =================================
echo   Session : %SESSION%
echo.

echo [1/3] Envoi des scripts sur le RHEL...
plink -batch "%SESSION%" "mkdir -p %REMOTE%" || goto :err
pscp -batch -q "%HERE%remote\fl_extract.py" "%SESSION%:%REMOTE%/fl_extract.py" || goto :err
pscp -batch -q "%HERE%..\fabriclens\resolve.py" "%SESSION%:%REMOTE%/resolve.py" || goto :err

echo [2/3] Extraction des backups ^(les chemins sont dans fl_extract.py^)...
plink -batch "%SESSION%" "cd %REMOTE% && python3 fl_extract.py --bundle fabriclens-data.json" || goto :err

echo [3/3] Rapatriement de fabriclens-data.json...
pscp -batch -p "%SESSION%:%REMOTE%/fabriclens-data.json" "%LOCAL%\" || goto :err

echo.
echo   =================================
echo   Termine.
echo   Fichier : %LOCAL%\fabriclens-data.json
echo.
echo   Ouvre fabric-lens.html, clique "Fichier", et choisis ce .json.
echo.
endlocal & exit /b 0

:err
echo.
echo   ECHEC. Verifie : le nom de session PuTTY, le ticket Kerberos ^(klist^),
echo   et les chemins du bloc FABRICS dans fl_extract.py.
echo.
endlocal & exit /b 1
