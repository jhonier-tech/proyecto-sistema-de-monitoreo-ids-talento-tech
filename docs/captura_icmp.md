# Guía de captura de paquetes ICMP en NetSniffer

Este documento proporciona instrucciones detalladas sobre cómo asegurar que la captura de paquetes ICMP (ping) funcione correctamente en NetSniffer.

## Requisitos previos

Para la captura correcta de paquetes ICMP (ping) en Windows, se requiere:

1. **Npcap instalado en modo compatible con WinPcap**
2. **Privilegios de administrador**
3. **Selección correcta de la interfaz de red**

## Verificación de compatibilidad

NetSniffer incluye herramientas para verificar y solucionar problemas de compatibilidad con WinPcap:

### Verificación automática

Al iniciar NetSniffer, se realiza automáticamente una verificación de compatibilidad. Si se detectan problemas, se mostrará un mensaje y se ofrecerá la opción de ejecutar el solucionador.

### Verificación manual

También puedes verificar la compatibilidad manualmente ejecutando:

```
verificar_scapy.bat
```

o

```
verificar_winpcap.bat
```

## Solución de problemas

Si experimentas problemas con la captura de paquetes ICMP, sigue estos pasos:

### 1. Ejecuta el solucionador todo-en-uno

```
solucionar_winpcap.bat
```

Este script te guiará a través de todo el proceso de solución, incluyendo:
- Verificación de la instalación actual
- Desinstalación de Npcap (si es necesario)
- Instalación de Npcap con compatibilidad WinPcap
- Prueba de captura de paquetes ICMP

### 2. Prueba la captura de paquetes ICMP

Después de ejecutar el solucionador, puedes verificar si la captura de paquetes ICMP funciona correctamente ejecutando:

```
test_ping_simple.bat
```

Durante la prueba, abre otra ventana de comando y ejecuta:
```
ping 8.8.8.8 -t
```

Si ves mensajes "PAQUETE ICMP DETECTADO", la captura está funcionando correctamente.

## Detalles técnicos

### ¿Por qué es importante la compatibilidad con WinPcap?

Scapy (la biblioteca que utiliza NetSniffer para capturar paquetes) fue diseñada originalmente para trabajar con WinPcap. Npcap es el sucesor moderno de WinPcap, pero necesita estar en modo compatible para que Scapy funcione correctamente. Sin este modo de compatibilidad, la captura de paquetes ICMP puede fallar silenciosamente.

### Archivos clave para la compatibilidad

Para que la compatibilidad funcione correctamente, los siguientes archivos deben existir:

1. `C:\Windows\System32\Npcap\wpcap.dll`
2. `C:\Windows\System32\Npcap\Packet.dll`
3. `C:\Windows\System32\wpcap.dll` (enlace simbólico)
4. `C:\Windows\System32\Packet.dll` (enlace simbólico)

Los dos últimos son enlaces simbólicos que permiten a las aplicaciones que buscan las DLLs de WinPcap encontrarlas en la ubicación estándar.

## Soporte

Si después de seguir todos los pasos sigues experimentando problemas con la captura de paquetes ICMP, por favor reporta el problema con la siguiente información:

1. Versión de Windows
2. Resultado de `verificar_scapy.bat`
3. Contenido del archivo de registro `logs/winpcap_check.log`
4. Cualquier mensaje de error específico que veas en la aplicación
