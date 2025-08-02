@echo off
echo ===================================
echo    Verificacion y Reparacion de Npcap
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
echo Esta herramienta verificara y tratara de solucionar problemas comunes de Npcap,
echo que es esencial para la captura de paquetes en NetSniffer.
echo.

python tools\verificar_npcap.py

echo.
echo Si la herramienta no pudo solucionar los problemas, considere:
echo 1. Desinstalar Npcap completamente
echo 2. Reiniciar el sistema
echo 3. Instalar la ultima version de Npcap desde https://npcap.com/
echo 4. Durante la instalacion, marcar "Install Npcap in WinPcap API-compatible Mode"
echo.

pause
