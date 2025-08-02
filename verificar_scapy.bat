@echo off
echo ===================================
echo    Verificacion de compatibilidad de Scapy con WinPcap
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
echo Esta herramienta verificara si Scapy puede acceder a las interfaces de red,
echo lo que indica que la compatibilidad con WinPcap esta funcionando correctamente.
echo.

python tools\verificar_scapy.py

echo.
if %errorlevel% equ 0 (
    echo ===================================
    echo    VERIFICACION EXITOSA
    echo ===================================
    echo.
    echo Scapy puede acceder correctamente a las interfaces de red.
    echo La compatibilidad con WinPcap esta funcionando.
    echo NetSniffer deberia poder capturar paquetes ICMP sin problemas.
    echo.
    echo Puede proceder a ejecutar test_ping_simple.bat para verificar
    echo la captura de paquetes ICMP.
) else (
    echo ===================================
    echo    VERIFICACION FALLIDA
    echo ===================================
    echo.
    echo Se han detectado problemas con Scapy y la compatibilidad WinPcap.
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
