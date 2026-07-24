@echo off
setlocal EnableExtensions EnableDelayedExpansion
rem ===========================================================================
rem  Fabric Lens - recuperation des backups ACI
rem ---------------------------------------------------------------------------
rem  Pousse les scripts sur le serveur RHEL, l'y fait distiller les exports APIC
rem  du jour ET assembler l'application complete, puis rapatrie UN SEUL FICHIER :
rem  fabric-lens.html. Aucun Python, aucun serveur, aucun reseau cote Windows -
rem  on double-clique le fichier et ca marche, meme hors ligne.
rem
rem  Authentification : session PuTTY sauvegardee avec Kerberos (GSSAPI/SSPI).
rem  Aucun mot de passe, aucune cle dans ce fichier - la session porte tout.
rem
rem  Prerequis : plink.exe et pscp.exe dans le PATH ou dans PUTTY_DIR,
rem              un ticket Kerberos valide (kinit / ouverture de session AD).
rem
rem  USAGE
rem    fabric-lens-fetch.bat          execution normale
rem    fabric-lens-fetch.bat test     MODE TEST : verifie la connexion, teste
rem                                   l'extracteur sur une archive synthetique,
rem                                   et liste les backups repereS.
rem                                   N'extrait rien, n'ecrit rien, ne
rem                                   telecharge rien. A lancer en premier.
rem ===========================================================================

rem --- CONFIGURATION --------------------------------------------------------
rem  Nom EXACT de la session PuTTY sauvegardee (celle qui marche deja).
set "PUTTY_SESSION=RHEL-BACKUPS"

rem  Repertoire d'installation de PuTTY. Laisser vide si plink/pscp sont dans le PATH.
set "PUTTY_DIR="

rem  OU SONT TES FABRICS ?
rem  Ca se declare dans le bloc FABRICS en tete de remote\fl_extract.py -
rem  une ligne par fabric, c'est le seul endroit a editer. Ce fichier-la est
rem  renvoye sur le RHEL a chaque execution, donc tu edites cote Windows et
rem  le serveur suit tout seul.
rem
rem  REMOTE_BACKUP_ROOT ci-dessous ne sert que dans deux cas :
rem    - le bloc FABRICS contient des chemins RELATIFS (ils partent de la) ;
rem    - le bloc FABRICS est vide et on auto-decouvre un sous-repertoire
rem      par fabric la-dedans.
rem  Avec des chemins absolus partout dans FABRICS, cette valeur est ignoree.
set "REMOTE_BACKUP_ROOT=/data/backups/aci"

rem  Ou Fabric Lens pose ses fichiers de travail sur le RHEL.
set "REMOTE_WORK_DIR=~/.fabric-lens"

rem  Motif des archives. Les exports APIC sortent en ce2_<policy>-<timestamp>.tar.gz
set "BACKUP_PATTERN=*.tar.gz"

rem  Cote Windows : ou atterrit l'application. C'est ce fichier qu'on ouvre.
set "LOCAL_OUT=%~dp0..\data"

rem  Inventaire des fabrics (optionnel). Si le fichier existe il est pousse et
rem  utilise ; sinon on auto-decouvre un sous-repertoire par fabric.
set "INVENTORY=%~dp0fabrics.csv"
rem --- FIN DE LA CONFIGURATION ----------------------------------------------

set "SCRIPT_DIR=%~dp0"
set "PLINK=plink.exe"
set "PSCP=pscp.exe"
if defined PUTTY_DIR (
    set "PLINK=%PUTTY_DIR%\plink.exe"
    set "PSCP=%PUTTY_DIR%\pscp.exe"
)

set "TEST_MODE="
if /i "%~1"=="test" set "TEST_MODE=1"
if /i "%~1"=="--test" set "TEST_MODE=1"
if /i "%~1"=="/test" set "TEST_MODE=1"

echo.
echo   ============================================
if defined TEST_MODE (
    echo    Fabric Lens - MODE TEST ^(lecture seule^)
) else (
    echo    Fabric Lens - recuperation des backups ACI
)
echo   ============================================
echo.
echo    Session PuTTY  : %PUTTY_SESSION%
echo    Backups (RHEL) : %REMOTE_BACKUP_ROOT%
echo    Sortie (local) : %LOCAL_OUT%
echo.

rem === 1. Verifications prealables ==========================================
echo [1/6] Verifications prealables...

where /q "%PLINK%" 2>nul
if errorlevel 1 (
    if not exist "%PLINK%" (
        echo    ERREUR : plink.exe introuvable.
        echo            Ajoutez PuTTY au PATH, ou renseignez PUTTY_DIR en tete de ce fichier.
        goto :fail
    )
)
where /q "%PSCP%" 2>nul
if errorlevel 1 (
    if not exist "%PSCP%" (
        echo    ERREUR : pscp.exe introuvable.
        goto :fail
    )
)

if not exist "%SCRIPT_DIR%remote\fl_extract.py" (
    echo    ERREUR : %SCRIPT_DIR%remote\fl_extract.py est absent.
    goto :fail
)

rem Ticket Kerberos : on avertit sans bloquer. Selon la configuration, plink
rem peut obtenir un ticket depuis la session Windows sans qu'il apparaisse ici.
klist >nul 2>&1
if errorlevel 1 (
    echo    Note : impossible de lister les tickets Kerberos ^(klist^).
    echo           Si la connexion echoue, lancez "klist" puis "kinit" ^(ou reouvrez votre session^).
) else (
    echo    Tickets Kerberos presents.
)

if not exist "%LOCAL_OUT%" mkdir "%LOCAL_OUT%" 2>nul
if not exist "%LOCAL_OUT%" (
    echo    ERREUR : impossible de creer %LOCAL_OUT%
    goto :fail
)
echo    OK.
echo.

rem === 2. Test de connexion =================================================
echo [2/6] Connexion a %PUTTY_SESSION%...
"%PLINK%" -batch "%PUTTY_SESSION%" "echo FL-CONNECT-OK; uname -n" > "%TEMP%\fl_connect.txt" 2>&1
if errorlevel 1 (
    echo    ERREUR : connexion impossible. Detail :
    type "%TEMP%\fl_connect.txt"
    echo.
    echo    Pistes : la session "%PUTTY_SESSION%" existe-t-elle exactement sous ce nom ?
    echo             le ticket Kerberos est-il valide ^(klist^) ?
    goto :fail
)
findstr /C:"FL-CONNECT-OK" "%TEMP%\fl_connect.txt" >nul
if errorlevel 1 (
    echo    ERREUR : reponse inattendue du serveur :
    type "%TEMP%\fl_connect.txt"
    goto :fail
)
for /f "skip=1 delims=" %%H in ('type "%TEMP%\fl_connect.txt"') do (
    if not defined REMOTE_HOST set "REMOTE_HOST=%%H"
)
echo    Connecte a !REMOTE_HOST!.
echo.

rem === 3. Preparation du repertoire de travail distant ======================
echo [3/6] Preparation du repertoire de travail distant...
"%PLINK%" -batch "%PUTTY_SESSION%" "mkdir -p %REMOTE_WORK_DIR%/out && echo FL-MKDIR-OK" > "%TEMP%\fl_mkdir.txt" 2>&1
findstr /C:"FL-MKDIR-OK" "%TEMP%\fl_mkdir.txt" >nul
if errorlevel 1 (
    echo    ERREUR : impossible de creer %REMOTE_WORK_DIR% :
    type "%TEMP%\fl_mkdir.txt"
    goto :fail
)
echo    OK.
echo.

rem === 4. Envoi de l'extracteur =============================================
rem  Pousse a chaque execution : le script distant est toujours a jour,
rem  il n'y a rien a installer ni a maintenir sur le RHEL.
echo [4/6] Envoi des scripts...
rem  La RHEL assemble desormais la page complete : il lui faut l'extracteur, le
rem  resolveur, l'assembleur, les deux modules JS et le gabarit HTML. Tout est
rem  repousse a chaque execution : rien a installer ni a maintenir la-bas.
"%PLINK%" -batch "%PUTTY_SESSION%" "mkdir -p %REMOTE_WORK_DIR%/web" >nul 2>&1
for %%F in (
    "remote\fl_extract.py=fl_extract.py"
    "..\fabriclens\resolve.py=resolve.py"
    "..\fabriclens\build_page.py=build_page.py"
    "..\web\resolve.js=web/resolve.js"
    "..\web\selfcheck.js=web/selfcheck.js"
    "..\web\gabarit.html=gabarit.html"
) do (
    for /f "tokens=1,2 delims==" %%A in ("%%~F") do (
        if not exist "%SCRIPT_DIR%%%A" (
            echo    ERREUR : %SCRIPT_DIR%%%A est absent.
            goto :fail
        )
        "%PSCP%" -batch -q "%SCRIPT_DIR%%%A" "%PUTTY_SESSION%:%REMOTE_WORK_DIR%/%%B"
        if errorlevel 1 (
            echo    ERREUR : envoi de %%A echoue.
            goto :fail
        )
    )
)

set "REMOTE_INV="
if exist "%INVENTORY%" (
    "%PSCP%" -batch -q "%INVENTORY%" "%PUTTY_SESSION%:%REMOTE_WORK_DIR%/fabrics.csv"
    if errorlevel 1 (
        echo    ERREUR : envoi de l'inventaire echoue.
        goto :fail
    )
    set "REMOTE_INV=--inventory %REMOTE_WORK_DIR%/fabrics.csv"
    echo    Extracteur + inventaire envoyes.
) else (
    echo    Extracteur envoye ^(pas d'inventaire : auto-decouverte^).
)
echo.

rem === MODE TEST : autotest + reperage, puis on s'arrete ====================
if not defined TEST_MODE goto :normal_run

echo [5/6] Autotest de l'extracteur sur le serveur...
echo.
"%PLINK%" -batch "%PUTTY_SESSION%" "python3 %REMOTE_WORK_DIR%/fl_extract.py --selftest"
if errorlevel 1 (
    echo.
    echo    ECHEC de l'autotest : l'extracteur ne fonctionne pas correctement
    echo    avec le python3 de ce serveur. Transmettez la sortie ci-dessus.
    goto :fail
)

echo.
echo [6/6] Reperage des backups ^(aucune archive n'est ouverte^)...
echo.
"%PLINK%" -batch "%PUTTY_SESSION%" "python3 %REMOTE_WORK_DIR%/fl_extract.py --root '%REMOTE_BACKUP_ROOT%' --pattern '%BACKUP_PATTERN%' %REMOTE_INV% --dry-run"
set "DRY_RC=!errorlevel!"
echo.
if !DRY_RC! GEQ 2 (
    echo    Aucun backup repere.
    echo    Corrigez REMOTE_BACKUP_ROOT en tete de ce fichier, ou fabrics.csv,
    echo    puis relancez :  fabric-lens-fetch.bat test
    goto :fail
)

echo   ============================================
echo    MODE TEST termine - rien n'a ete modifie.
echo   ============================================
echo.
echo    Si la liste ci-dessus est juste, lancez sans argument :
echo        fabric-lens-fetch.bat
echo.
endlocal & exit /b 0

:normal_run
rem === 5. Extraction sur le serveur =========================================
echo [5/6] Extraction et assemblage sur le serveur ^(plusieurs minutes^)...
echo.
"%PLINK%" -batch "%PUTTY_SESSION%" "python3 %REMOTE_WORK_DIR%/fl_extract.py --root '%REMOTE_BACKUP_ROOT%' --out %REMOTE_WORK_DIR%/out --pattern '%BACKUP_PATTERN%' %REMOTE_INV%"
set "EXTRACT_RC=!errorlevel!"
if !EXTRACT_RC! LSS 2 (
    echo.
    echo    Assemblage de la page...
    echo.
    "%PLINK%" -batch "%PUTTY_SESSION%" "cd %REMOTE_WORK_DIR% && python3 build_page.py --distilled out --template gabarit.html --js-dir web --out fabric-lens.html"
    if errorlevel 1 (
        echo    ERREUR : l'assemblage de la page a echoue. Rien n'a ete rapatrie.
        goto :fail
    )
)
echo.
if !EXTRACT_RC! GEQ 2 (
    echo    ERREUR : l'extraction a echoue ^(code !EXTRACT_RC!^). Rien n'a ete rapatrie.
    goto :fail
)
if !EXTRACT_RC! EQU 1 (
    echo    Avertissement : certains fabrics ont echoue, les autres sont exploitables.
)
echo.

rem === 6. Rapatriement ======================================================
rem  Un SEUL fichier a rapatrier desormais : la page complete. Pas de wildcard
rem  cote serveur (pscp les refuse, et -unsafe laisse le serveur choisir ou
rem  ecrire sur le disque local).
echo [6/6] Rapatriement de l'application...
"%PSCP%" -batch -p "%PUTTY_SESSION%:%REMOTE_WORK_DIR%/fabric-lens.html" "%LOCAL_OUT%\"
if errorlevel 1 (
    echo    ERREUR : rapatriement de fabric-lens.html echoue.
    goto :fail
)
"%PSCP%" -batch -q -p "%PUTTY_SESSION%:%REMOTE_WORK_DIR%/out/manifest.json" "%LOCAL_OUT%\" 2>nul

echo   ============================================
echo    Termine.
echo   ============================================
echo    Application prete : %LOCAL_OUT%\fabric-lens.html
echo    Double-cliquez ce fichier. Aucun Python, aucun serveur, aucun reseau.
echo.
if !EXTRACT_RC! EQU 1 (
    echo    Rappel : au moins un fabric n'a pas pu etre extrait, voir le journal ci-dessus.
)
endlocal & exit /b 0

:copyfail
echo    ERREUR : la copie d'un fichier distille a echoue.
echo             !N_COPIED! fichier^(s^) copie^(s^) avant l'echec.

:fail
echo.
echo   ============================================
echo    ECHEC - rien n'a ete modifie localement.
echo   ============================================
echo.
endlocal & exit /b 1
