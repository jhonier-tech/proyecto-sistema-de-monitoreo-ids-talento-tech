# Herramientas de diagnóstico y solución para NetSniffer

Este documento describe las herramientas auxiliares incluidas en NetSniffer para diagnosticar y solucionar problemas relacionados con la captura de paquetes, especialmente para paquetes ICMP (ping).

## Herramientas de verificación

### 1. `verificar_npcap.bat`

Esta herramienta verifica la instalación de Npcap en el sistema.

**Funcionalidad:**
- Comprueba si Npcap está instalado
- Verifica la presencia de archivos clave (wpcap.dll, Packet.dll)
- Muestra información sobre la versión instalada

**Uso:**
```
verificar_npcap.bat
```

### 2. `verificar_winpcap.bat`

Verifica si Npcap está instalado en modo compatible con WinPcap.

**Funcionalidad:**
- Comprueba la presencia de los enlaces simbólicos necesarios en System32
- Verifica si las aplicaciones pueden acceder a Npcap a través de la API de WinPcap
- Genera un reporte detallado del estado de compatibilidad

**Uso:**
```
verificar_winpcap.bat
```

### 3. `verificar_scapy.bat`

Comprueba si Scapy puede acceder a las interfaces de red y capturar paquetes correctamente.

**Funcionalidad:**
- Verifica la instalación de Scapy
- Enumera las interfaces de red disponibles
- Comprueba si se pueden capturar paquetes

**Uso:**
```
verificar_scapy.bat
```

## Herramientas de prueba

### 1. `test_ping_simple.bat`

Una prueba básica para verificar la captura de paquetes ICMP.

**Funcionalidad:**
- Inicia una captura de paquetes ICMP en todas las interfaces
- Muestra los paquetes ICMP detectados en tiempo real
- Útil para verificar rápidamente si la detección de ICMP funciona

**Uso:**
```
test_ping_simple.bat
```

Durante la ejecución, abre otro terminal y ejecuta: `ping 8.8.8.8 -t`

### 2. `test_ping_mejorado.bat`

Una versión avanzada de la prueba de ping con más información y opciones.

**Funcionalidad:**
- Enumera todas las interfaces disponibles
- Permite seleccionar la interfaz a probar
- Muestra información detallada de los paquetes ICMP
- Proporciona estadísticas y tiempos de respuesta

**Uso:**
```
test_ping_mejorado.bat
```

## Herramientas de solución

### 1. `solucionar_winpcap.bat`

Una solución todo-en-uno para problemas de compatibilidad con WinPcap.

**Funcionalidad:**
- Diagnostica automáticamente problemas de compatibilidad
- Guía paso a paso para:
  - Desinstalar Npcap (si es necesario)
  - Descargar la versión correcta de Npcap
  - Instalar Npcap con modo de compatibilidad WinPcap
  - Verificar que la instalación se realizó correctamente
  - Probar la captura de paquetes ICMP

**Uso:**
```
solucionar_winpcap.bat
```

### 2. `desinstalar_npcap.bat`

Utilidad para desinstalar completamente Npcap del sistema.

**Funcionalidad:**
- Detiene servicios relacionados con Npcap
- Ejecuta el desinstalador de Npcap
- Elimina archivos residuales
- Prepara el sistema para una instalación limpia

**Uso:**
```
desinstalar_npcap.bat
```

### 3. `instalar_npcap_compatible.bat`

Instala Npcap en modo compatible con WinPcap.

**Funcionalidad:**
- Descarga la última versión de Npcap
- Instala Npcap con las opciones adecuadas para compatibilidad con WinPcap
- Verifica que la instalación se completó correctamente

**Uso:**
```
instalar_npcap_compatible.bat
```

## Utilidad integrada en NetSniffer

### `src/utils/winpcap_check.py`

Este módulo está integrado en NetSniffer y proporciona verificación automática de compatibilidad.

**Funcionalidad:**
- Se ejecuta automáticamente al iniciar NetSniffer
- Verifica privilegios de administrador
- Comprueba la instalación de Npcap
- Verifica la compatibilidad con WinPcap
- Comprueba el acceso a las interfaces de red
- Valida el soporte para ICMP en Scapy
- Proporciona instrucciones si se detectan problemas

**Nota:** Si se detectan problemas durante el inicio de NetSniffer, se mostrará un mensaje de advertencia con instrucciones para ejecutar `solucionar_winpcap.bat`.

## Uso recomendado

Para usuarios que experimentan problemas con la detección de paquetes ICMP (ping):

1. Ejecuta `verificar_winpcap.bat` para diagnosticar el problema
2. Si se detectan problemas, ejecuta `solucionar_winpcap.bat`
3. Verifica que la solución funcionó con `test_ping_simple.bat`
4. Inicia NetSniffer normalmente mediante `iniciar_netsniffer.bat`

## Información adicional

Para información más detallada sobre la captura de paquetes ICMP y solución de problemas, consulta:
- [Guía de captura ICMP](captura_icmp.md)
- [Solución de problemas ICMP](solucion_problemas_icmp.md)
