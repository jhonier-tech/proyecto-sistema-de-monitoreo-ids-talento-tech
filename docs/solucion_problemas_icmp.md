# NetSniffer - Guía para problemas de detección de paquetes ICMP (ping)

Si tienes problemas con la detección de paquetes ICMP (ping) en NetSniffer, sigue esta guía paso a paso para resolverlos.

## Requisitos previos

1. **Privilegios de administrador**: NetSniffer y las herramientas de diagnóstico deben ejecutarse como administrador.
2. **Npcap instalado correctamente**: Npcap es esencial para la captura de paquetes en Windows.
3. **Compatibilidad con WinPcap**: Npcap debe instalarse en modo compatible con WinPcap.

## Solución Todo-en-Uno

La forma más sencilla de solucionar problemas de compatibilidad es ejecutar:

```
solucionar_winpcap.bat
```

Este script te guiará a través de todo el proceso, incluyendo:
- Verificación de la instalación actual
- Desinstalación de Npcap (si es necesario)
- Instalación de Npcap con compatibilidad WinPcap
- Prueba de captura de paquetes ICMP

## Diagnóstico y solución de problemas paso a paso

Si prefieres un enfoque más manual, sigue estos pasos:

### 1. Verificar la instalación de Npcap y compatibilidad WinPcap

Ejecuta el archivo `verificar_winpcap.bat` para comprobar si Npcap está instalado correctamente con compatibilidad WinPcap:

```
verificar_winpcap.bat
```

### 2. Desinstalar Npcap

Si se detectan problemas, desinstala Npcap:

```
desinstalar_npcap.bat
```

Después de desinstalar, **reinicia tu sistema**.

### 3. Instalar Npcap con compatibilidad WinPcap

Instala Npcap con la configuración correcta:

```
instalar_npcap_compatible.bat
```

Este script te guiará para:
- Descargar la última versión de Npcap
- Instalarla con la opción "Install Npcap in WinPcap API-compatible Mode" activada
- Verificar que la instalación se realizó correctamente

### 4. Prueba de detección de paquetes ICMP

Ejecuta la prueba mejorada de detección de paquetes ICMP:

```
test_ping_mejorado.bat
```

Esta herramienta:
- Verificará tus interfaces de red
- Probará la captura de paquetes ICMP en todas las interfaces disponibles
- Recomendará la mejor interfaz para usar con NetSniffer

Durante la prueba, abre otra ventana de comando y ejecuta:
```
ping 8.8.8.8 -t
```

## ¿Por qué es importante la compatibilidad con WinPcap?

Scapy y otras bibliotecas de captura de paquetes en Python fueron diseñadas originalmente para trabajar con WinPcap. Npcap es el sucesor moderno de WinPcap, pero necesita estar en modo compatible para que estas bibliotecas funcionen correctamente. Sin este modo de compatibilidad, la captura de paquetes ICMP puede fallar silenciosamente.

## Solución de problemas comunes

Si sigues sin detectar paquetes ICMP:

1. **Firewall**: Verifica que el firewall no esté bloqueando la captura
   ```
   netsh advfirewall firewall add rule name="NetSniffer" dir=in action=allow program="C:\ruta\a\NetSniffer\iniciar_netsniffer.bat" enable=yes
   ```

2. **Selección de interfaz**: Asegúrate de seleccionar la interfaz de red correcta en NetSniffer
   - Si usas WiFi, selecciona la interfaz WiFi
   - Si usas conexión por cable, selecciona la interfaz Ethernet

3. **Modo de captura**: En la configuración de NetSniffer, habilita el modo de captura "promiscuo" si está disponible

4. **Actualizaciones de Windows**: Asegúrate de tener Windows actualizado, ya que algunas actualizaciones pueden afectar la funcionalidad de Npcap

## Contacto y soporte

Si después de seguir estos pasos sigues teniendo problemas, por favor reporta el problema con la siguiente información:

1. Versión de Windows
2. Resultado de `verificar_winpcap.bat`
3. Resultado de `test_ping_mejorado.bat`
4. Cualquier mensaje de error específico que veas

## Contribuciones

Las contribuciones para mejorar la detección de paquetes ICMP son bienvenidas. Por favor, envía un pull request o abre un issue en el repositorio del proyecto.
