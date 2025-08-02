# sistema de monitoreo ids - Analizador de Red

Un analiza1. **Prueba la captura de paquetes ICMP** (opcional):
   ```
   test_ping_simple.bat
   ```
   Mientras se ejecuta la prueba, abre otro terminal y ejecuta: `ping 8.8.8.8 -t`
   Para más información sobre las herramientas de diagnóstico, consulta la [guía de herramientas](docs/herramientas_diagnostico.md).e paquetes de red con interfaz gráfica potente similar a Wireshark, desarrollado en Python, que permite capturar y analizar tráfico de red en tiempo real.

## Características

- **Captura de paquetes en tiempo real**: Captura paquetes en cualquier interfaz de red disponible.
- **Análisis detallado de protocolos**: Soporte para TCP, UDP, ICMP, HTTP, HTTPS, DNS, ARP y muchos otros.
- **Interfaz gráfica intuitiva**: Diseño moderno e intuitivo con múltiples vistas.
- **Filtrado avanzado**: Filtros por protocolo, dirección IP, puerto, etc.
- **Visualización de detalles**: Vista en árbol de los detalles de cada paquete.
- **Vista hexadecimal**: Visualización hexadecimal y ASCII del contenido del paquete.
- **Estadísticas en tiempo real**: Gráficos y estadísticas de tráfico.
- **Exportación e importación**: Guarda y carga capturas en formato PCAP.
- **Personalizable**: Temas claro y oscuro, preferencias configurables.

## ⚠️ Requisitos importantes

- **Python 3.8 o superior**
- **Bibliotecas necesarias** (instalables vía `pip install -r requirements.txt`):
  - scapy (>=2.5.0): Para captura de paquetes
  - PyQt5: Para la interfaz gráfica
  - pyqtgraph: Para visualizaciones
  - netifaces: Para detección de interfaces
  - Otras dependencias listadas en requirements.txt
- **Npcap en modo compatible con WinPcap**: En Windows, Npcap debe instalarse con la opción "Install Npcap in WinPcap API-compatible Mode" activada
- **Privilegios de administrador**: Imprescindibles para capturar paquetes de red
- **Configuración correcta para ICMP**: La captura de paquetes ICMP (ping) requiere una configuración especial en Windows (ver [documentación detallada](docs/captura_icmp.md))

### Documentación adicional

- [Guía de captura ICMP](docs/captura_icmp.md) - Instrucciones para asegurar la captura de paquetes ICMP
- [Solución de problemas ICMP](docs/solucion_problemas_icmp.md) - Guía para resolver problemas de detección de pings
- [Herramientas de diagnóstico](docs/herramientas_diagnostico.md) - Descripción de las herramientas auxiliares incluidas

## Instalación

1. **Descargar o clonar** este repositorio
2. **Instalar dependencias**:
   ```
   instalar_dependencias.bat    # En Windows
   pip install -r requirements.txt   # En Linux/macOS
   ```
3. **Verificar compatibilidad WinPcap** (sólo Windows):
   ```
   verificar_winpcap.bat
   ```
   Si hay problemas, ejecuta:
   ```
   solucionar_winpcap.bat
   ```
   Para más información, consulta la [guía de solución de problemas](docs/solucion_problemas_icmp.md).
4. **Probar la captura de paquetes ICMP** (opcional):
   ```
   test_ping_simple.bat
   ```
   Mientras se ejecuta la prueba, abre otro terminal y ejecuta: `ping 8.8.8.8 -t`
5. **Ejecutar la aplicación** (con privilegios de administrador):
   - En Windows: Usa el archivo `iniciar_netsniffer.bat` (hace elevación de privilegios automáticamente)
   - En Linux/macOS: `sudo python src/main.py`

## Guía de uso

### Captura básica de paquetes

1. **Inicia la aplicación con privilegios de administrador**
   - Sin estos privilegios, la captura de paquetes no funcionará correctamente
   
2. **Selecciona una interfaz de red**
   - Haz clic en el botón "Interfaces" en la barra de herramientas
   - Selecciona la interfaz de red que quieras monitorizar
   
3. **Inicia la captura**
   - Haz clic en el botón "Iniciar" en la barra de herramientas
   - Comenzarás a ver los paquetes capturados en la tabla principal

4. **Examina los paquetes**
   - Haz clic en cualquier paquete para ver sus detalles
   - La vista de detalles muestra la estructura completa del paquete
   - La vista hexadecimal muestra el contenido binario

### Uso de filtros

1. **Filtrado básico**
   - Escribe en la barra de filtros (ejemplos: "tcp", "icmp", "port 80")
   - Haz clic en "Aplicar" o presiona Enter

2. **Filtros avanzados**
   - Usa sintaxis similar a Wireshark:
     - `tcp` - Muestra solo paquetes TCP
     - `ip.src==192.168.1.1` - Paquetes desde una IP específica
     - `tcp.port==80` - Paquetes con puerto TCP 80

### Análisis y estadísticas

- Haz clic en el botón "Estadísticas" para ver gráficos de distribución de protocolos
- Las estadísticas se actualizan en tiempo real durante la captura

### Guardado y carga de capturas

- Usa el menú "Archivo" → "Guardar captura" para guardar en formato PCAP
- Usa "Archivo" → "Abrir captura" para cargar capturas guardadas previamente

## Resolución de problemas

### La aplicación no captura paquetes

1. **Verifica los privilegios**: La aplicación debe ejecutarse como administrador
2. **Comprueba la interfaz**: Asegúrate de haber seleccionado la interfaz correcta
3. **Verifica el tráfico**: Asegúrate de que hay tráfico en la red (prueba con un ping)
4. **Revisa el firewall**: Puede estar bloqueando la captura de paquetes

### Problemas con detección de ICMP (ping)

Si no puedes ver los paquetes ICMP (ping) en la captura:

1. **Verifica Npcap**: Ejecuta `verificar_winpcap.bat` para comprobar que Npcap está instalado correctamente
2. **Solución automática**: Ejecuta `solucionar_winpcap.bat` que realizará todos los pasos necesarios
3. **Prueba la captura**: Usa `test_ping_simple.bat` para verificar específicamente la captura ICMP
4. **Documentación detallada**: Consulta la [guía de solución de problemas ICMP](docs/solucion_problemas_icmp.md) y la [guía de herramientas de diagnóstico](docs/herramientas_diagnostico.md)

### Mensajes de error comunes

- **"No se pudo iniciar la captura"**: Falta de privilegios o interfaz no disponible
- **"No se ha podido resolver la importación"**: Dependencias no instaladas correctamente

## Estructura del proyecto

```
NetSniffer/
├── assets/              # Recursos (iconos, imágenes)
├── docs/                # Documentación
│   ├── captura_icmp.md  # Guía para captura ICMP
│   └── solucion_problemas_icmp.md # Solución de problemas
├── logs/                # Archivos de registro
├── src/                 # Código fuente
│   ├── analyzer/        # Análisis de paquetes
│   ├── capture/         # Captura de paquetes
│   ├── gui/             # Interfaz gráfica
│   ├── protocols/       # Implementaciones de protocolos
│   ├── utils/           # Utilidades
│   │   └── winpcap_check.py # Comprobación de compatibilidad
│   └── main.py          # Punto de entrada
├── tools/               # Herramientas auxiliares
│   ├── test_ping.py     # Prueba de captura ICMP
│   ├── verificar_npcap.py # Verificación de Npcap
│   └── verificar_winpcap.py # Verificación de WinPcap
├── iniciar_netsniffer.bat  # Script de inicio para Windows
├── solucionar_winpcap.bat  # Solucionador de problemas ICMP
├── requirements.txt     # Dependencias
└── README.md            # Este archivo
```

## Licencia

Este proyecto es software libre y de código abierto.
# proyecto-sistema-de-monitoreo-ids-talento-tech
