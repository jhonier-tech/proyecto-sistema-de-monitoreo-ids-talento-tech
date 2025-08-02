#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Utilidad para configurar y manejar el registro de eventos de la aplicación
"""

import os
import logging
import datetime
import platform
from logging.handlers import RotatingFileHandler

def setup_logger(optimized_mode=False):
    """Configura el logger de la aplicación
    
    Args:
        optimized_mode (bool): Si es True, reduce el nivel de logging para mejorar rendimiento
    """
    # Crear directorio de logs si no existe
    log_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "logs")
    os.makedirs(log_dir, exist_ok=True)
    
    # Nombre del archivo de log con timestamp
    today = datetime.datetime.now().strftime("%Y-%m-%d")
    log_file = os.path.join(log_dir, f"sistema_monitoreo_ids_{today}.log")
    
    # Verificar si estamos en modo optimizado
    python_optimize = os.environ.get("PYTHONOPTIMIZE", "0")
    if python_optimize != "0" or optimized_mode:
        optimized_mode = True
    
    # Configuración del formato
    log_format = logging.Formatter(
        '%(asctime)s [%(levelname)s] - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # Configuración del logger principal
    root_logger = logging.getLogger()
    
    # En modo optimizado, usar niveles más altos para reducir I/O
    if optimized_mode:
        root_logger.setLevel(logging.WARNING)
        file_level = logging.WARNING
        console_level = logging.ERROR
    else:
        root_logger.setLevel(logging.INFO)
        file_level = logging.INFO
        console_level = logging.WARNING
    
    # Handler para archivo (rotación de 5MB, mantener 3 backups)
    file_handler = RotatingFileHandler(log_file, maxBytes=5*1024*1024, backupCount=3)
    file_handler.setFormatter(log_format)
    file_handler.setLevel(file_level)
    
    # Handler para consola
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(log_format)
    console_handler.setLevel(console_level)
    
    # Agregar handlers al logger
    root_logger.addHandler(file_handler)
    root_logger.addHandler(console_handler)
    
    # Reducir la verbosidad de algunas bibliotecas externas
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
    logging.getLogger("PIL").setLevel(logging.ERROR)
    logging.getLogger("matplotlib").setLevel(logging.ERROR)
    
    # Log inicial
    system_info = platform.system() + " " + platform.release()
    if optimized_mode:
        logging.warning(f"Logger inicializado en modo optimizado ({system_info})")
    else:
        logging.info(f"Logger inicializado ({system_info})")
    
    return root_logger
