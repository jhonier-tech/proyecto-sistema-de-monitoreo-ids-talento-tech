#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Script para verificar y solucionar problemas comunes de Npcap
"""

import os
import sys
import platform
import subprocess
import logging
import ctypes
import winreg

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

def check_npcap_installation():
    """Verifica si Npcap está instalado y configurado correctamente"""
    logging.info("Verificando instalación de Npcap...")
    
    # Verificar directorio
    if not os.path.exists("C:\\Windows\\System32\\Npcap"):
        logging.error("❌ El directorio Npcap no existe")
        return False
    
    # Verificar DLLs esenciales
    required_files = ["wpcap.dll", "Packet.dll"]
    for file in required_files:
        if not os.path.exists(f"C:\\Windows\\System32\\Npcap\\{file}"):
            logging.error(f"❌ Archivo esencial no encontrado: {file}")
            return False
        else:
            logging.info(f"✅ Archivo encontrado: {file}")
    
    # Verificar enlaces simbólicos en System32
    system32_links = [
        "C:\\Windows\\System32\\wpcap.dll",
        "C:\\Windows\\System32\\Packet.dll"
    ]
    
    for link in system32_links:
        if not os.path.exists(link):
            logging.warning(f"⚠️ Enlace simbólico no encontrado: {link}")
        else:
            logging.info(f"✅ Enlace simbólico encontrado: {link}")
    
    # Comprobar registro de servicios de Npcap
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services\npcap")
        winreg.CloseKey(key)
        logging.info("✅ Servicio Npcap registrado correctamente")
    except WindowsError:
        logging.error("❌ Servicio Npcap no encontrado en el registro")
        return False
    
    # Comprobar estado del servicio
    try:
        result = subprocess.run(["sc", "query", "npcap"], capture_output=True, text=True)
        if "RUNNING" in result.stdout:
            logging.info("✅ Servicio Npcap está en ejecución")
        else:
            logging.warning("⚠️ Servicio Npcap no está en ejecución")
            return False
    except Exception as e:
        logging.error(f"❌ Error al verificar el estado del servicio: {e}")
        return False
    
    # Comprobar la configuración de WinPcap compatible
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Npcap")
        winpcap_mode = winreg.QueryValueEx(key, "WinPcapCompatible")[0]
        if winpcap_mode == 1:
            logging.info("✅ Npcap está configurado en modo compatible con WinPcap")
        else:
            logging.warning("⚠️ Npcap NO está en modo compatible con WinPcap")
            return False
        winreg.CloseKey(key)
    except WindowsError:
        logging.warning("⚠️ No se pudo verificar el modo de compatibilidad WinPcap")
        return False
    
    return True

def try_fix_npcap():
    """Intenta arreglar problemas comunes de Npcap"""
    if not is_admin():
        logging.error("❌ Se requieren privilegios de administrador para reparar Npcap")
        return False
    
    logging.info("Intentando reparar la instalación de Npcap...")
    
    # Reiniciar servicio
    try:
        logging.info("Reiniciando servicio Npcap...")
        subprocess.run(["sc", "stop", "npcap"], check=True)
        subprocess.run(["sc", "start", "npcap"], check=True)
        logging.info("✅ Servicio Npcap reiniciado correctamente")
    except subprocess.CalledProcessError as e:
        logging.error(f"❌ Error al reiniciar el servicio: {e}")
        return False
    
    # Verificar nuevamente
    if check_npcap_installation():
        logging.info("✅ Reparación exitosa")
        return True
    else:
        logging.error("❌ La reparación no solucionó todos los problemas")
        return False

def main():
    """Función principal"""
    if platform.system() != "Windows":
        logging.error("Este script solo es compatible con Windows")
        return 1
    
    logging.info("=== Verificación y Reparación de Npcap ===")
    
    if not is_admin():
        logging.warning("⚠️ No se está ejecutando con privilegios de administrador")
        logging.warning("Algunas comprobaciones y reparaciones pueden fallar")
    
    if check_npcap_installation():
        logging.info("✅ Npcap está instalado y configurado correctamente")
        return 0
    else:
        logging.warning("⚠️ Se encontraron problemas con la instalación de Npcap")
        
        choice = input("¿Desea intentar reparar estos problemas? (S/N): ")
        if choice.lower() == "s":
            if try_fix_npcap():
                logging.info("✅ Reparación completada con éxito")
                return 0
            else:
                logging.error("❌ No se pudieron solucionar todos los problemas")
                logging.info("Recomendación: Reinstale Npcap desde https://npcap.com/")
                logging.info("Asegúrese de marcar 'Install Npcap in WinPcap API-compatible Mode'")
                return 1
        else:
            logging.info("Operación cancelada por el usuario")
            return 1

if __name__ == "__main__":
    sys.exit(main())
