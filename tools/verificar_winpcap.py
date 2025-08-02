#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Script para verificar si Npcap está correctamente configurado en modo compatible con WinPcap
"""

import os
import sys
import ctypes
import platform
import logging
import subprocess

# Configuración de logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

def is_admin():
    """Verifica si se está ejecutando con privilegios de administrador"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except:
        return False

def check_npcap_files():
    """Verifica si los archivos de Npcap están presentes y los enlaces simbólicos para WinPcap"""
    npcap_dir = "C:\\Windows\\System32\\Npcap"
    if not os.path.exists(npcap_dir):
        logging.error(f"❌ Directorio Npcap no encontrado: {npcap_dir}")
        return False
    
    # Verificar archivos esenciales
    essential_files = {
        "wpcap.dll": os.path.join(npcap_dir, "wpcap.dll"),
        "Packet.dll": os.path.join(npcap_dir, "Packet.dll")
    }
    
    for name, path in essential_files.items():
        if os.path.exists(path):
            logging.info(f"✅ Archivo encontrado: {name}")
        else:
            logging.error(f"❌ Archivo no encontrado: {name}")
            return False
    
    # Verificar enlaces simbólicos (modo compatible con WinPcap)
    symlinks = {
        "wpcap.dll": "C:\\Windows\\System32\\wpcap.dll",
        "Packet.dll": "C:\\Windows\\System32\\Packet.dll"
    }
    
    winpcap_mode = True
    for name, path in symlinks.items():
        if os.path.exists(path):
            logging.info(f"✅ Enlace WinPcap encontrado: {name}")
        else:
            logging.error(f"❌ Enlace WinPcap no encontrado: {name}")
            winpcap_mode = False
    
    return winpcap_mode

def check_npcap_service():
    """Verifica si el servicio Npcap está instalado y en ejecución"""
    try:
        # Verificar si el servicio existe
        result = subprocess.run(["sc", "query", "npcap"], 
                               capture_output=True, 
                               text=True, 
                               check=False)
        
        if result.returncode != 0:
            logging.error("❌ Servicio Npcap no encontrado")
            return False
        
        # Verificar si está en ejecución
        if "RUNNING" in result.stdout:
            logging.info("✅ Servicio Npcap está en ejecución")
            return True
        else:
            logging.warning("⚠️ Servicio Npcap no está en ejecución")
            return False
    except Exception as e:
        logging.error(f"❌ Error al verificar el servicio Npcap: {e}")
        return False

def test_winpcap_compatibility():
    """Prueba si la API de WinPcap está accesible desde Python"""
    try:
        logging.info("Probando compatibilidad WinPcap desde Python...")
        
        # Intentar importar y usar la API de WinPcap a través de Scapy
        from scapy.all import conf
        
        # Listar interfaces disponibles (esto usa la API de WinPcap)
        if_list = conf.ifaces.data.keys()
        if_count = len(list(if_list))
        
        logging.info(f"✅ API de WinPcap accesible. Se encontraron {if_count} interfaces")
        return True
    except ImportError:
        logging.error("❌ No se pudo importar Scapy. Instale Scapy con: pip install scapy")
        return False
    except Exception as e:
        logging.error(f"❌ Error al probar la API de WinPcap: {e}")
        return False

def main():
    """Función principal"""
    if platform.system() != "Windows":
        logging.error("Este script solo es compatible con Windows")
        return 1
    
    logging.info("=== Verificación de Compatibilidad WinPcap ===")
    
    if not is_admin():
        logging.warning("⚠️ No se está ejecutando con privilegios de administrador")
        logging.warning("Algunas comprobaciones pueden fallar sin permisos adecuados")
    
    # Verificar archivos y enlaces WinPcap
    winpcap_files_ok = check_npcap_files()
    
    # Verificar servicio
    service_ok = check_npcap_service()
    
    # Verificar compatibilidad desde Python
    try:
        winpcap_api_ok = test_winpcap_compatibility()
    except Exception:
        winpcap_api_ok = False
    
    # Resultado general
    logging.info("=== Resultado de la verificación ===")
    
    if winpcap_files_ok and service_ok and winpcap_api_ok:
        logging.info("✅ Npcap está instalado correctamente en modo compatible con WinPcap")
        logging.info("✅ NetSniffer debería poder capturar paquetes ICMP sin problemas")
        return 0
    else:
        logging.error("❌ Se encontraron problemas con la compatibilidad WinPcap")
        logging.info("Recomendaciones:")
        logging.info("1. Ejecute desinstalar_npcap.bat para remover Npcap")
        logging.info("2. Reinicie el sistema")
        logging.info("3. Ejecute instalar_npcap_compatible.bat para reinstalar con compatibilidad WinPcap")
        return 1

if __name__ == "__main__":
    sys.exit(main())
