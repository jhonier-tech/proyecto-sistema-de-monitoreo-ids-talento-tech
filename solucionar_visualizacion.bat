@echo off
REM Script para solucionar problemas de visualización de paquetes

echo ======================================================
echo Solucionando problemas de visualización de paquetes...
echo ======================================================

REM Crear directorio de logs si no existe
if not exist logs mkdir logs

REM Ejecutar script de solución
python solucionar_visualizacion_paquetes.py

if %ERRORLEVEL% NEQ 0 (
    echo.
    echo Error al ejecutar el script de solución
    echo Por favor, asegúrate de tener todas las dependencias instaladas
    echo.
    pause
    exit /b 1
)

echo.
echo ======================================================
echo Solución completada exitosamente!
echo.
echo Puedes probar la visualización ejecutando:
echo python probar_visualizacion_paquetes.py
echo.
echo Para iniciar NetSniffer normalmente, usa:
echo iniciar_netsniffer.bat
echo ======================================================
echo.

pause
