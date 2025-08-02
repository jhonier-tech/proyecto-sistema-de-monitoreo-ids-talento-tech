@echo off
echo ===================================
echo    Verificacion de Compatibilidad con WinPcap
echo ===================================
echo.

REM Verificar privilegios de administrador
>nul 2>&1 "%SYSTEMROOT%\system32\cacls.exe" "%SYSTEMROOT%\system32\config\system"
if %errorlevel% neq 0 (
    echo [ADVERTENCIA] Se recomienda ejecutar esta herramienta como administrador.
    echo [INFO] Solicitando elevacion de privilegios...
    echo.
    
    choice /C SN /M "¿Desea continuar con privilegios de administrador?"
    if %errorlevel% equ 1 (
        echo Set UAC = CreateObject^("Shell.Application"^) > "%temp%\getadmin.vbs"
        echo UAC.ShellExecute "%~s0", "", "", "runas", 1 >> "%temp%\getadmin.vbs"
        "%temp%\getadmin.vbs"
        del "%temp%\getadmin.vbs"
        exit /B
    ) else (
        echo [ADVERTENCIA] Algunas funciones pueden no estar disponibles sin privilegios de administrador.
    )
) else (
    echo [OK] Ejecutando con privilegios de administrador.
)

echo.
echo Esta herramienta verificara si Npcap esta configurado correctamente
echo en modo compatible con WinPcap, lo cual es esencial para NetSniffer.
echo.

python tools\verificar_winpcap.py

echo.
if %errorlevel% equ 0 (
    echo ===================================
    echo    VERIFICACION EXITOSA
    echo ===================================
    echo.
    echo Npcap esta configurado correctamente con compatibilidad WinPcap.
    echo NetSniffer deberia funcionar sin problemas.
    echo.
    echo Puede proceder a ejecutar test_ping_mejorado.bat para verificar
    echo la captura de paquetes ICMP.
) else (
    echo ===================================
    echo    VERIFICACION FALLIDA
    echo ===================================
    echo.
    echo Se han detectado problemas con la compatibilidad WinPcap.
    echo.
    echo Para solucionar este problema:
    echo 1. Ejecute desinstalar_npcap.bat
    echo 2. Reinicie el sistema
    echo 3. Ejecute instalar_npcap_compatible.bat
    echo.
    echo Estos scripts le guiaran paso a paso en el proceso.
)

echo.
pause
