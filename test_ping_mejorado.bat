@echo off
echo ===================================
echo    Prueba Mejorada de Captura de Ping (ICMP)
echo ===================================
echo.

REM Verificar privilegios de administrador
>nul 2>&1 "%SYSTEMROOT%\system32\cacls.exe" "%SYSTEMROOT%\system32\config\system"
if %errorlevel% neq 0 (
    echo [ADVERTENCIA] Esta prueba requiere privilegios de administrador.
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
        echo [ERROR] La captura de paquetes requiere privilegios de administrador.
        echo [INFO] Por favor, ejecute este script como administrador.
        pause
        exit /B 1
    )
) else (
    echo [OK] Ejecutando con privilegios de administrador.
)

echo.
echo Esta herramienta probara si su sistema puede capturar paquetes ICMP (ping).
echo.

REM Verificar si Npcap está instalado
if not exist "C:\Windows\System32\Npcap" (
    echo [ERROR] Npcap no esta instalado o no se encuentra en la ruta esperada.
    echo [INFO] Npcap es esencial para la captura de paquetes.
    echo.
    echo Por favor, instale Npcap desde https://npcap.com/
    echo Durante la instalacion, marque "Install Npcap in WinPcap API-compatible Mode".
    echo.
    
    choice /C SN /M "¿Desea abrir la pagina de descarga de Npcap?"
    if %errorlevel% equ 1 (
        start https://npcap.com/
    )
    
    pause
    exit /B 1
)

REM Verificar archivos específicos de Npcap
if not exist "C:\Windows\System32\Npcap\wpcap.dll" (
    echo [ERROR] El archivo wpcap.dll no se encuentra en la carpeta Npcap.
    echo [INFO] Esto sugiere una instalacion incompleta o incorrecta de Npcap.
    echo.
    echo Por favor, reinstale Npcap desde https://npcap.com/
    echo Asegurándose de marcar "Install Npcap in WinPcap API-compatible Mode".
    echo.
    pause
    exit /B 1
)

echo [OK] Instalacion de Npcap verificada correctamente.
echo.

echo [1/3] Verificando interfaces de red...

REM Abrir una ventana para mostrar las interfaces
start "Interfaces de Red" cmd /c "ipconfig & echo. & echo Presione una tecla para cerrar... & pause > nul"

echo.
echo [2/3] Ejecutando prueba mejorada de captura ICMP...
echo.
echo IMPORTANTE:
echo - Esta ventana mostrara mensajes cuando capture paquetes ICMP.
echo - En otra ventana de comandos, ejecute: ping 8.8.8.8 -t (o cualquier IP activa)
echo - Si ve mensajes de "PAQUETE ICMP DETECTADO", la captura funciona.
echo - Presione Ctrl+C para detener la prueba cuando termine.
echo.
echo Iniciando captura...
echo.

REM Ejecutar el script de prueba mejorado
python tools\test_ping_mejorado.py

echo.
echo [3/3] Prueba finalizada.
echo.
echo Si ha visto mensajes "PAQUETE ICMP DETECTADO" durante la prueba:
echo   ✓ La captura de paquetes ICMP funciona correctamente
echo.
echo Si NO ha visto esos mensajes:
echo   ✗ Posibles problemas:
echo     - Npcap no esta configurado correctamente
echo     - No se selecciono la interfaz de red correcta
echo     - El firewall esta bloqueando la captura
echo     - Se necesita ejecutar como administrador
echo.

echo Recomendaciones para NetSniffer:
echo 1. Asegurese de ejecutar NetSniffer como administrador
echo 2. Seleccione la interfaz de red correcta (la conectada a internet)
echo 3. Si utiliza WiFi, asegurese de seleccionar la interfaz WiFi
echo 4. Desactive temporalmente el firewall si sospecha que esta bloqueando

echo.
pause
