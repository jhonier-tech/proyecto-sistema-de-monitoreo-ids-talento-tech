@echo off
echo ===================================
echo    Instalacion de Npcap con Compatibilidad WinPcap
echo ===================================
echo.

REM Verificar privilegios de administrador
>nul 2>&1 "%SYSTEMROOT%\system32\cacls.exe" "%SYSTEMROOT%\system32\config\system"
if %errorlevel% neq 0 (
    echo [ADVERTENCIA] Esta herramienta requiere privilegios de administrador.
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
        echo [ERROR] Se requieren privilegios de administrador.
        pause
        exit /B 1
    )
) else (
    echo [OK] Ejecutando con privilegios de administrador.
)

echo.
echo Esta herramienta le guiara a traves del proceso de instalacion de Npcap
echo con soporte para compatibilidad con WinPcap, necesario para NetSniffer.
echo.

REM Verificar si ya existe Npcap
if exist "C:\Windows\System32\Npcap" (
    echo [ADVERTENCIA] Npcap parece estar ya instalado.
    echo [INFO] Se recomienda desinstalar primero antes de continuar.
    echo.
    
    choice /C SN /M "¿Desea ejecutar la herramienta de desinstalacion?"
    if %errorlevel% equ 1 (
        call desinstalar_npcap.bat
    )
)

echo [1/3] Descargando la ultima version de Npcap...
echo.
echo ===================================
echo    INSTRUCCIONES DE DESCARGA
echo ===================================
echo.
echo 1. Se abrira el navegador en la pagina de descarga de Npcap
echo 2. Descargue la ultima version (boton "Download Npcap")
echo 3. Guarde el archivo en una ubicacion que recuerde (por ej. Descargas)
echo 4. Cuando termine la descarga, vuelva a esta ventana
echo.
echo Presione cualquier tecla para abrir la pagina de descarga...
pause > nul

start https://npcap.com/

echo.
echo ===================================
echo Cuando termine la descarga, presione cualquier tecla para continuar...
echo ===================================
pause > nul

echo.
echo [2/3] Instalando Npcap con compatibilidad WinPcap...
echo.
echo ===================================
echo    INSTRUCCIONES DE INSTALACION CRUCIALES
echo ===================================
echo.
echo 1. Busque y ejecute el instalador de Npcap que acaba de descargar
echo 2. Siga el asistente de instalacion
echo 3. IMPORTANTE: Durante la instalacion, ASEGURESE de marcar:
echo    - "Install Npcap in WinPcap API-compatible Mode"
echo    - Esta opcion es CRUCIAL para que NetSniffer funcione correctamente
echo 4. Recomendado: Tambien marque "Support raw 802.11 traffic"
echo 5. Complete la instalacion y vuelva a esta ventana
echo.
echo Presione cualquier tecla cuando este listo para buscar el instalador...
pause > nul

start %USERPROFILE%\Downloads

echo.
echo ===================================
echo Cuando termine la instalacion de Npcap, presione cualquier tecla para continuar...
echo ===================================
pause > nul

echo.
echo [3/3] Verificando la instalacion...
echo.

if exist "C:\Windows\System32\Npcap\wpcap.dll" (
    echo [OK] wpcap.dll encontrado - componente esencial instalado.
) else (
    echo [ERROR] wpcap.dll no encontrado. La instalacion parece haber fallado.
    echo [INFO] Intente instalar manualmente y asegurese de tener los permisos correctos.
    goto error
)

if exist "C:\Windows\System32\wpcap.dll" (
    echo [OK] Enlace simbolico wpcap.dll encontrado - modo compatible con WinPcap activado.
) else (
    echo [ADVERTENCIA] Enlace simbolico wpcap.dll no encontrado.
    echo [INFO] El modo compatible con WinPcap podria no estar activado.
    echo [INFO] Intente reinstalar y asegurese de marcar la opcion de compatibilidad.
)

echo.
echo [INFO] Verificando servicio Npcap...
sc query npcap > nul 2>&1
if %errorlevel% equ 0 (
    echo [OK] Servicio Npcap registrado correctamente.
    
    sc query npcap | find "RUNNING" > nul 2>&1
    if %errorlevel% equ 0 (
        echo [OK] Servicio Npcap esta en ejecucion.
    ) else (
        echo [INFO] Iniciando servicio Npcap...
        sc start npcap
    )
) else (
    echo [ERROR] Servicio Npcap no encontrado. La instalacion podria haber fallado.
    goto error
)

echo.
echo ===================================
echo    Instalacion completada con exito
echo ===================================
echo.
echo Se recomienda REINICIAR el sistema para asegurar que todos los
echo componentes de Npcap esten cargados correctamente.
echo.
echo ¿Desea reiniciar el sistema ahora?
choice /C SN /M "Reiniciar ahora"
if %errorlevel% equ 1 (
    echo [INFO] Reiniciando sistema...
    shutdown /r /t 10 /c "Reinicio para completar la instalacion de Npcap"
    echo El sistema se reiniciara en 10 segundos. Guarde su trabajo.
    timeout /t 10
) else (
    echo [INFO] Se recomienda reiniciar manualmente antes de continuar.
)

goto end

:error
echo.
echo [ERROR] Se encontraron problemas durante la instalacion.
echo [INFO] Por favor, intente reinstalar Npcap manualmente y asegurese de:
echo 1. Ejecutar el instalador como administrador
echo 2. Marcar la opcion "Install Npcap in WinPcap API-compatible Mode"
echo.

:end
echo.
echo Despues de reiniciar, ejecute test_ping_mejorado.bat para verificar
echo que la captura de paquetes ICMP funciona correctamente.
echo.
pause
