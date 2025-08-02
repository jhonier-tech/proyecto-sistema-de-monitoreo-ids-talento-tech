#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Sistema de monitoreo IDS - Analizador de paquetes de red con interfaz gráfica
Punto de entrada principal de la aplicación
"""

import sys
import os
import logging
from PyQt5.QtWidgets import QApplication
from PyQt5.QtGui import QIcon, QFont
from PyQt5.QtCore import Qt

# Asegurarse de que el directorio src esté en el path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Importar componentes de la aplicación
from gui.main_window import MainWindow
from utils.logger import setup_logger

def check_privileges():
    """Verifica si la aplicación tiene privilegios de administrador"""
    try:
        is_admin = False
        if os.name == 'nt':  # Windows
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:  # Unix/Linux/MacOS
            is_admin = os.geteuid() == 0
            
        return is_admin
    except Exception as e:
        logging.warning(f"No se pudieron verificar los privilegios: {e}")
        return False

def main():
    """Función principal para iniciar la aplicación"""
    # Determinar si estamos en modo optimizado
    optimized_mode = os.environ.get("PYTHONOPTIMIZE", "0") != "0"
    
    # Configurar el logger con el modo apropiado
    setup_logger(optimized_mode=optimized_mode)
    
    # Log inicial
    if optimized_mode:
        logging.warning("Sistema de monitoreo IDS iniciado en modo optimizado para mejor rendimiento")
    else:
        logging.info("Sistema de monitoreo IDS iniciado en modo normal")
    
    # Verificar privilegios de administrador
    if not check_privileges():
        logging.warning("La aplicación no se está ejecutando con privilegios de administrador. "
                      "Algunas funciones de captura de paquetes pueden no funcionar correctamente.")
    
    # Verificar compatibilidad con WinPcap para captura de paquetes ICMP
    try:
        from utils.winpcap_check import quick_winpcap_check
        winpcap_ok = quick_winpcap_check()
        if not winpcap_ok:
            logging.warning("Se detectaron problemas con la compatibilidad WinPcap.")
            logging.warning("La captura de paquetes ICMP puede no funcionar correctamente.")
            logging.warning("Ejecute 'solucionar_winpcap.bat' para resolver este problema.")
    except Exception as e:
        logging.error(f"Error al verificar compatibilidad WinPcap: {e}")
    
    # Iniciar la aplicación Qt
    QApplication.setAttribute(Qt.AA_EnableHighDpiScaling, True)
    QApplication.setAttribute(Qt.AA_UseHighDpiPixmaps, True)
    app = QApplication(sys.argv)
    app.setApplicationName("Sistema de monitoreo IDS")
    app.setApplicationVersion("1.0.0")
    
    # Establecer el icono de la aplicación
    from utils.icons import get_icon_path
    app_icon = QIcon(get_icon_path("app_icon"))
    app.setWindowIcon(app_icon)
    
    # Configurar estilo y fuente
    font = QFont("Segoe UI", 9)
    app.setFont(font)
    
    # Iniciar la ventana principal
    main_window = MainWindow()
    main_window.show()
    
    # Ejecutar el bucle de eventos
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
