#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Utilidad para gestionar iconos de la aplicación
"""

import os
from PyQt5.QtGui import QIcon, QPixmap

# Directorio base de iconos
ICON_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "assets", "icons")

# Caché de iconos para mejorar rendimiento
ICON_CACHE = {}

# Diccionario de iconos
ICONS = {
    "app_icon": "app_icon.ico",
    "start": "start.png",
    "stop": "stop.png",
    "interface": "interface.png",
    "clear": "clear.png",
    "save": "save.png",
    "statistics": "statistics.png",
    "filter": "filter.png",
    "preferences": "preferences.png",
    "about": "about.png",
    "help": "help.png",
    "export": "export.png",
    "import": "import.png",
    "zoom_in": "zoom_in.png",
    "zoom_out": "zoom_out.png",
    "zoom_reset": "zoom_reset.png",
    # Iconos de protocolos
    "protocol_ethernet": "protocol_ethernet.png",
    "protocol_ip": "protocol_ip.png",
    "protocol_tcp": "protocol_tcp.png",
    "protocol_udp": "protocol_udp.png",
    "protocol_http": "protocol_http.png",
    "protocol_https": "protocol_https.png",
    "protocol_dns": "protocol_dns.png",
    "protocol_icmp": "protocol_icmp.png",
    "protocol_unknown": "protocol_unknown.png",
}

def get_icon_path(name):
    """Obtiene la ruta completa a un icono
    
    Args:
        name (str): Nombre del icono en el diccionario ICONS
        
    Returns:
        str: Ruta completa al archivo del icono o None si no existe
    """
    if name not in ICONS:
        return None
        
    icon_path = os.path.join(ICON_DIR, ICONS[name])
    
    # Si el icono no existe, crear directorio e icono de fallback
    if not os.path.exists(icon_path):
        os.makedirs(os.path.dirname(icon_path), exist_ok=True)
        
        # Usar un icono por defecto para desarrollo
        return None
        
    return icon_path

def get_icon(name):
    """Obtiene un objeto QIcon cacheado para mejorar rendimiento
    
    Args:
        name (str): Nombre del icono en el diccionario ICONS
        
    Returns:
        QIcon: Icono cargado o un icono vacío si no existe
    """
    # Verificar si el icono ya está en el caché
    if name in ICON_CACHE:
        return ICON_CACHE[name]
        
    # Obtener la ruta al icono
    icon_path = get_icon_path(name)
    
    # Si no existe la ruta, devolver un icono vacío
    if not icon_path:
        ICON_CACHE[name] = QIcon()
        return ICON_CACHE[name]
    
    # Cargar el icono y guardarlo en caché
    try:
        icon = QIcon(icon_path)
        ICON_CACHE[name] = icon
        return icon
    except Exception:
        # En caso de error, devolver un icono vacío
        ICON_CACHE[name] = QIcon()
        return ICON_CACHE[name]

def initialize_icons():
    """Inicializa el directorio de iconos creando la estructura si no existe"""
    if not os.path.exists(ICON_DIR):
        os.makedirs(ICON_DIR, exist_ok=True)
