<!-- Use this file to provide workspace-specific custom instructions to Copilot. For more details, visit https://code.visualstudio.com/docs/copilot/copilot-customization#_use-a-githubcopilotinstructionsmd-file -->

# NetSniffer - Instrucciones para Copilot

## Contexto del proyecto
Este proyecto es un analizador de paquetes de red con interfaz gráfica similar a Wireshark, desarrollado en Python. Utiliza bibliotecas como Scapy para la captura de paquetes y PyQt5 para la interfaz gráfica.

## Tecnologías principales
- Python 3.8+
- Scapy: Captura y análisis de paquetes
- PyQt5: Interfaz gráfica
- PyQtGraph: Visualización de datos
- Matplotlib/Pandas: Análisis y visualización estadística

## Convenciones de código
- Seguir PEP 8 para el estilo de código Python
- Utilizar nombres descriptivos para clases, métodos y variables
- Documentar todas las funciones con docstrings
- Mantener un enfoque modular y orientado a objetos
- Utilizar tipado estático (type hints) siempre que sea posible

## Consideraciones de seguridad
- El código debe ejecutarse con privilegios elevados para la captura de paquetes
- No almacenar información sensible en texto plano
- Validar todas las entradas del usuario

## Consideraciones de rendimiento
- Optimizar el procesamiento de paquetes para captura en tiempo real
- Utilizar estructuras de datos eficientes para el almacenamiento de paquetes
- Implementar paginación para grandes conjuntos de datos
- Considerar procesamiento en segundo plano para tareas intensivas
