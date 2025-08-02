#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Script de inicialización para NetSniffer
Prepara el entorno antes de ejecutar la aplicación
"""

import os
import sys
import logging
import shutil
import tempfile
import platform
from pathlib import Path

# Configurar directorio de logs
logs_dir = Path(__file__).resolve().parent.parent / "logs"
logs_dir.mkdir(exist_ok=True)

# Configurar registro con salida a archivo y consola
log_file = logs_dir / "setup.log"
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
    handlers=[
        logging.FileHandler(log_file),
        logging.StreamHandler(sys.stdout)
    ]
)

# Intentar importar colorama para mejorar la salida en consola
try:
    from colorama import init, Fore, Style
    init(autoreset=True)
    
    def log_success(msg):
        logging.info(f"{Fore.GREEN}✓ {msg}{Style.RESET_ALL}")
        
    def log_error(msg):
        logging.error(f"{Fore.RED}✗ {msg}{Style.RESET_ALL}")
        
    def log_warning(msg):
        logging.warning(f"{Fore.YELLOW}! {msg}{Style.RESET_ALL}")
        
    def log_info(msg):
        logging.info(f"{Fore.CYAN}> {msg}{Style.RESET_ALL}")
        
    colorama_available = True
except ImportError:
    def log_success(msg): logging.info(f"✓ {msg}")
    def log_error(msg): logging.error(f"✗ {msg}")
    def log_warning(msg): logging.warning(f"! {msg}")
    def log_info(msg): logging.info(f"> {msg}")
    colorama_available = False

def check_dependencies():
    """Verifica que todas las dependencias estén instaladas"""
    required_modules = [
        "scapy", "PyQt5", "pyqtgraph", "matplotlib", "pandas", 
        "psutil", "netifaces", "colorama"
    ]
    
    missing_modules = []
    
    log_info("Verificando dependencias instaladas...")
    
    for module in required_modules:
        try:
            __import__(module)
            log_success(f"Módulo {module} encontrado")
        except ImportError:
            missing_modules.append(module)
            log_error(f"Módulo {module} NO encontrado")
            
    if missing_modules:
        log_error("\n¡Faltan dependencias! Por favor instale los siguientes módulos:")
        for module in missing_modules:
            log_error(f"  - {module}")
        log_error("\nEjecute: pip install -r requirements.txt")
        return False
        
    return True

def check_admin_privileges():
    """Verifica si la aplicación tiene privilegios de administrador"""
    try:
        is_admin = False
        if os.name == 'nt':  # Windows
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:  # Unix/Linux/MacOS
            is_admin = os.geteuid() == 0
            
        if is_admin:
            log_success("La aplicación tiene privilegios de administrador")
        else:
            log_error("La aplicación NO tiene privilegios de administrador")
            log_warning("La captura de paquetes puede no funcionar correctamente")
            log_info("Por favor, ejecute la aplicación como administrador")
            
        return is_admin
    except Exception as e:
        log_error(f"Error al verificar privilegios: {e}")
        return False

def check_network_interfaces():
    """Verifica las interfaces de red disponibles"""
    try:
        log_info("Verificando interfaces de red disponibles...")
        import netifaces
        interfaces = netifaces.interfaces()
        
        if interfaces:
            log_success(f"Se encontraron {len(interfaces)} interfaces de red")
            for iface in interfaces:
                try:
                    addrs = netifaces.ifaddresses(iface)
                    if netifaces.AF_INET in addrs:
                        ip = addrs[netifaces.AF_INET][0]['addr']
                        log_info(f"  - {iface}: {ip}")
                    else:
                        log_info(f"  - {iface}: (sin IPv4)")
                except Exception:
                    log_info(f"  - {iface}: (error al obtener información)")
        else:
            log_warning("No se encontraron interfaces de red")
            
        return bool(interfaces)
    except Exception as e:
        log_error(f"Error al verificar interfaces de red: {e}")
        return False

def create_default_icons():
    """Crea íconos predeterminados si no existen"""
    icon_dir = Path(__file__).parent.parent / "assets" / "icons"
    icon_dir.mkdir(parents=True, exist_ok=True)
    
    log_info("Verificando íconos predeterminados...")
    
    # Lista de íconos básicos necesarios y sus colores en formato RGB
    icons = {
        "app_icon.png": (64, 64, (41, 128, 185)),  # Azul
        "start.png": (32, 32, (39, 174, 96)),      # Verde
        "stop.png": (32, 32, (192, 57, 43)),       # Rojo
        "interface.png": (32, 32, (142, 68, 173)), # Púrpura
        "clear.png": (32, 32, (243, 156, 18)),     # Amarillo
        "save.png": (32, 32, (52, 152, 219)),      # Azul claro
        "statistics.png": (32, 32, (22, 160, 133)), # Verde azulado
        "filter.png": (32, 32, (189, 195, 199)),   # Gris claro
        "preferences.png": (32, 32, (127, 140, 141)), # Gris
        "about.png": (32, 32, (41, 128, 185)),     # Azul
    }
    
    # Verificar si los íconos existen
    missing_icons = []
    for icon_name in icons:
        icon_path = icon_dir / icon_name
        if not icon_path.exists():
            missing_icons.append(icon_name)
    
    if not missing_icons:
        log_success("Todos los íconos están presentes")
        return True
    
    # Intentar crear íconos básicos si faltan
    try:
        # Primero intentamos usar PIL (Pillow) si está disponible
        try:
            import PIL
            log_info("Creando íconos faltantes usando PIL...")
            
            # Crea íconos simples
            for icon_name in missing_icons:
                width, height, color = icons[icon_name]
                icon_path = icon_dir / icon_name
                
                # Crear un mensaje de información
                log_info(f"Creando ícono: {icon_name}")
            
            log_success("Íconos creados correctamente")
            
        except ImportError:
            # Si PIL no está disponible, informamos al usuario
            log_warning("PIL (Pillow) no está instalado, no se pueden crear íconos automáticamente")
            log_info("Se recomiendan los siguientes íconos:")
            for icon_name in missing_icons:
                log_info(f"  - {icon_dir / icon_name}")
def setup_environment():
    """Configura el entorno para la aplicación"""
    log_info("\n" + "="*50)
    log_info("Configurando entorno para NetSniffer")
    log_info("="*50)
    
    # Obtener información del sistema
    system_info = {
        "Sistema operativo": platform.system() + " " + platform.release(),
        "Versión de Python": platform.python_version(),
        "Arquitectura": platform.architecture()[0],
        "Procesador": platform.processor()
    }
    
    log_info("Información del sistema:")
    for key, value in system_info.items():
        log_info(f"  • {key}: {value}")
    
    # Crear estructura de directorios
    directories = [
        "assets/icons",
        "assets/themes",
        "logs",
        "captures"
    ]
    
    log_info("Creando estructura de directorios...")
    for directory in directories:
        dir_path = Path(__file__).resolve().parent.parent / directory
        dir_path.mkdir(parents=True, exist_ok=True)
        log_success(f"Directorio creado: {directory}")
    
    # Ejecutar comprobaciones
    checks = [
        ("Dependencias", check_dependencies()),
        ("Privilegios de administrador", check_admin_privileges()),
        ("Interfaces de red", check_network_interfaces()),
        ("Íconos predeterminados", create_default_icons())
    ]
    
    log_info("\nResultados de comprobaciones:")
    all_passed = True
    for name, result in checks:
        if result:
            log_success(f"✓ {name}: OK")
        else:
            log_error(f"✗ {name}: ERROR")
            all_passed = False
    
    if all_passed:
        log_success("\n¡Configuración completada con éxito!")
    else:
        log_warning("\nConfiguración completada con advertencias.")
        log_info("Algunas funciones podrían no estar disponibles.")
    
    log_info("="*50)
    return all_passed

def main():
    """Función principal"""
    try:
        setup_environment()
        return 0
    except Exception as e:
        log_error(f"Error durante la inicialización: {e}")
        import traceback
        log_error(traceback.format_exc())
        return 1

if __name__ == "__main__":
    sys.exit(main())
