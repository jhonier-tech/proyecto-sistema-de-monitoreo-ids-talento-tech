@echo off
echo ===================================
echo    Instalacion manual de dependencias para NetSniffer
echo ===================================
echo.

REM Verificar privilegios de administrador
>nul 2>&1 "%SYSTEMROOT%\system32\cacls.exe" "%SYSTEMROOT%\system32\config\system"
if %errorlevel% neq 0 (
    echo [ADVERTENCIA] Para una instalacion completa, se recomienda ejecutar como administrador.
    echo [INFO] Solicitando elevacion de privilegios...
    echo.
    
    choice /C SN /M "¿Desea continuar con privilegios de administrador?"
    if %errorlevel% equ 1 (
        echo Set UAC = CreateObject^("Shell.Application"^) > "%temp%\getadmin.vbs"
        echo UAC.ShellExecute "%~s0", "", "", "runas", 1 >> "%temp%\getadmin.vbs"
        "%temp%\getadmin.vbs"
        del "%temp%\getadmin.vbs"
        exit /B
    )
) else (
    echo [OK] Ejecutando con privilegios de administrador.
)

REM Verificar que Python está instalado
where python >nul 2>nul
if %errorlevel% neq 0 (
    echo [ERROR] Python no esta instalado o no se encuentra en el PATH.
    echo [INFO] Por favor, instale Python 3.8 o superior desde https://www.python.org/downloads/
    echo.
    pause
    exit /B 1
)

echo.
echo [INFO] Instalando dependencias de Python...
echo.

echo [1/8] Instalando Scapy...
pip install scapy>=2.5.0
if %errorlevel% neq 0 (
    echo [ERROR] Error al instalar Scapy. Intente manualmente: pip install scapy>=2.5.0
) else (
    echo [OK] Scapy instalado correctamente.
)
echo.

echo [2/8] Instalando PyQt5...
pip install pyqt5>=5.15.9
if %errorlevel% neq 0 (
    echo [ERROR] Error al instalar PyQt5. Intente manualmente: pip install pyqt5>=5.15.9
) else (
    echo [OK] PyQt5 instalado correctamente.
)
echo.

echo [3/8] Instalando pyqtgraph...
pip install pyqtgraph>=0.13.3
if %errorlevel% neq 0 (
    echo [ERROR] Error al instalar pyqtgraph. Intente manualmente: pip install pyqtgraph>=0.13.3
) else (
    echo [OK] pyqtgraph instalado correctamente.
)
echo.

echo [4/8] Instalando colorama...
pip install colorama>=0.4.6
if %errorlevel% neq 0 (
    echo [ERROR] Error al instalar colorama. Intente manualmente: pip install colorama>=0.4.6
) else (
    echo [OK] colorama instalado correctamente.
)
echo.

echo [5/8] Instalando psutil...
pip install psutil>=5.9.5
if %errorlevel% neq 0 (
    echo [ERROR] Error al instalar psutil. Intente manualmente: pip install psutil>=5.9.5
) else (
    echo [OK] psutil instalado correctamente.
)
echo.

echo [6/8] Instalando netifaces...
pip install netifaces>=0.11.0
if %errorlevel% neq 0 (
    echo [ADVERTENCIA] Error al instalar netifaces. Esto puede requerir Microsoft Visual C++ Build Tools.
    echo [INFO] Se intentara usar una version precompilada...
    pip install --only-binary :all: netifaces>=0.11.0
    if %errorlevel% neq 0 (
        echo [ERROR] Fallo la instalacion de netifaces.
    ) else (
        echo [OK] netifaces instalado correctamente.
    )
) else (
    echo [OK] netifaces instalado correctamente.
)
echo.

echo [7/8] Instalando matplotlib...
pip install matplotlib>=3.7.2
if %errorlevel% neq 0 (
    echo [ERROR] Error al instalar matplotlib. Intente manualmente: pip install matplotlib>=3.7.2
) else (
    echo [OK] matplotlib instalado correctamente.
)
echo.

echo [8/8] Instalando pandas...
pip install pandas>=2.0.3
if %errorlevel% neq 0 (
    echo [ERROR] Error al instalar pandas. Intente manualmente: pip install pandas>=2.0.3
) else (
    echo [OK] pandas instalado correctamente.
)
echo.

echo [INFO] Verificando instalacion de Npcap (necesario para capturar paquetes)...
if exist "C:\Windows\System32\Npcap" (
    echo [OK] Npcap parece estar instalado.
    
    echo [INFO] Verificando la configuracion de Npcap...
    if exist "C:\Windows\System32\Npcap\wpcap.dll" (
        echo [OK] Archivo wpcap.dll encontrado.
    ) else (
        echo [ADVERTENCIA] No se encontro el archivo wpcap.dll en la carpeta Npcap.
        echo [INFO] Esto puede indicar una instalacion incompleta de Npcap.
    )
    
    echo [INFO] Para verificar y solucionar problemas con Npcap, ejecute verificar_npcap.bat
) else (
    echo [ADVERTENCIA] No se detecto instalacion de Npcap.
    echo [INFO] Npcap es ESENCIAL para la captura de paquetes en Windows.
    echo.
    
    choice /C SN /M "¿Desea abrir la pagina de descarga de Npcap?"
    if %errorlevel% equ 1 (
        echo [INFO] Abriendo pagina de descarga de Npcap...
        start https://npcap.com/
        echo [INFO] Durante la instalacion, marque la opcion 'Install Npcap in WinPcap API-compatible Mode'
    )
)

echo.
echo [INFO] Verificando todas las dependencias...
python tools\verificar_dependencias.py

echo.
echo [INFO] Verificando compatibilidad con WinPcap...
python tools\verificar_scapy.py

echo.
echo ===================================
echo    Instalacion de dependencias completada
echo ===================================
echo.

echo Para probar NetSniffer:
echo 1. Si instalo Npcap, reinicie el sistema ahora
echo 2. Ejecute NetSniffer con 'iniciar_netsniffer.bat' como administrador
echo.

pause
