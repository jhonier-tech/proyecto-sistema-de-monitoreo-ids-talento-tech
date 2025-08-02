#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Módulo para comprobar la compatibilidad de Scapy con WinPcap
y asegurar que la captura de paquetes ICMP funcione correctamente
"""

import os
import sys
import platform
import logging
import subprocess

# Configuración de logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(os.path.join("logs", "winpcap_check.log"))
    ]
)

def check_admin_privileges():
    """Verifica si se está ejecutando con privilegios de administrador
    
    Returns:
        bool: True si se ejecuta como administrador, False en caso contrario
    """
    try:
        if platform.system() == "Windows":
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
            if not is_admin:
                logging.warning("ALERTA: No se está ejecutando con privilegios de administrador")
                logging.warning("La captura de paquetes puede fallar o ser limitada")
            return is_admin
        else:
            is_admin = os.geteuid() == 0
            if not is_admin:
                logging.warning("ALERTA: No se está ejecutando con privilegios de root/sudo")
                logging.warning("La captura de paquetes puede fallar o ser limitada")
            return is_admin
    except Exception as e:
        logging.error(f"Error al verificar privilegios de administrador: {e}")
        return False

def get_detailed_os_info():
    """Obtiene información detallada del sistema operativo"""
    system = platform.system()
    os_info = system
    
    if system == "Windows":
        try:
            os_info = f"Windows {platform.win32_ver()[0]} ({platform.architecture()[0]})"
        except:
            os_info = "Windows"
    elif system == "Linux":
        try:
            # Verificar si es Android
            if "ANDROID_ROOT" in os.environ or os.path.exists("/system/build.prop"):
                # Intentar obtener la versión de Android
                try:
                    import subprocess
                    android_version = subprocess.check_output(["getprop", "ro.build.version.release"]).decode().strip()
                    android_sdk = subprocess.check_output(["getprop", "ro.build.version.sdk"]).decode().strip()
                    os_info = f"Android {android_version} (SDK {android_sdk})"
                except:
                    os_info = "Android"
            else:
                # Es Linux, intentar determinar la distribución
                try:
                    # Intentar leer /etc/os-release
                    if os.path.exists("/etc/os-release"):
                        with open("/etc/os-release", "r") as f:
                            lines = f.readlines()
                        for line in lines:
                            if line.startswith("PRETTY_NAME="):
                                os_info = line.split("=")[1].strip().strip('"\'')
                                break
                except:
                    # Si falla, usar la versión básica de platform
                    os_info = f"Linux {platform.release()}"
        except:
            os_info = "Linux"
    elif system == "Darwin":
        try:
            os_info = f"macOS {platform.mac_ver()[0]}"
        except:
            os_info = "macOS"
    
    return os_info

def check_npcap_installation():
    """Verifica si Npcap está instalado y configurado correctamente"""
    if platform.system() != "Windows":
        # En sistemas no Windows, no se requiere Npcap
        return True
    
    # Uso de caché para evitar verificaciones repetidas
    import time
    from functools import lru_cache
    
    @lru_cache(maxsize=1)
    def _cached_check_npcap(timestamp):
        """Verificación con caché para mejorar rendimiento"""
        # Se ignora el timestamp, solo se usa para invalidar caché si es necesario
        
        # Verificar directorio Npcap
        if not os.path.exists("C:\\Windows\\System32\\Npcap"):
            logging.warning("No se encontró el directorio Npcap")
            return False
        
        # Verificar DLLs esenciales
        required_files = ["wpcap.dll", "Packet.dll"]
        for file in required_files:
            if not os.path.exists(f"C:\\Windows\\System32\\Npcap\\{file}"):
                logging.warning(f"No se encontró el archivo {file}")
                return False
        
        # Verificar enlaces simbólicos (modo compatible con WinPcap)
        winpcap_links = ["C:\\Windows\\System32\\wpcap.dll", "C:\\Windows\\System32\\Packet.dll"]
        for link in winpcap_links:
            if not os.path.exists(link):
                logging.warning(f"No se encontró el enlace simbólico WinPcap: {link}")
                return False
        
        return True
    
    # Usar el timestamp actual redondeado a minutos para permitir una verificación cada minuto como máximo
    current_minute = int(time.time() / 60)
    return _cached_check_npcap(current_minute)

def check_scapy_interface_access():
    """Verifica si Scapy puede acceder a las interfaces de red"""
    try:
        from scapy.all import conf
        
        # Verificar si hay interfaces disponibles
        ifaces = conf.ifaces
        if not ifaces:
            logging.warning("No se encontraron interfaces de red en Scapy")
            return False
        
        logging.info(f"Se encontraron {len(ifaces)} interfaces de red")
        return True
    except ImportError:
        logging.error("No se pudo importar Scapy")
        return False
    except Exception as e:
        logging.error(f"Error al acceder a las interfaces de red: {e}")
        return False

def check_scapy_icmp_support():
    """Verifica si Scapy puede importar las capas ICMP necesarias"""
    try:
        from scapy.all import ICMP, IP
        return True
    except ImportError:
        logging.error("No se pudieron importar las capas ICMP/IP de Scapy")
        return False
    except Exception as e:
        logging.error(f"Error al verificar soporte ICMP: {e}")
        return False

def provide_fix_instructions():
    """Proporciona instrucciones para solucionar problemas detectados"""
    os_info = get_detailed_os_info()
    
    msg = f"""
    ==========================================================
    PROBLEMAS DETECTADOS CON LA CAPTURA DE PAQUETES
    ==========================================================
    
    Sistema operativo detectado: {os_info}
    
    Se han encontrado problemas que pueden afectar la captura de paquetes ICMP.
    Para solucionarlos, siga estos pasos:
    
    1. Cierre NetSniffer
    2. Ejecute el script 'solucionar_winpcap.bat' como administrador
    3. Siga las instrucciones que aparecerán en pantalla
    
    El script solucionará automáticamente los problemas de compatibilidad
    con WinPcap y asegurará que la captura de paquetes ICMP funcione correctamente.
    ==========================================================
    """
    logging.warning(msg)
    return msg

def quick_winpcap_check():
    """
    Realiza una comprobación rápida de la compatibilidad WinPcap
    
    Returns:
        bool: True si todo está configurado correctamente, False si hay problemas
    """
    # Identificar el sistema operativo
    os_info = get_detailed_os_info()
    system_name = platform.system()
    
    logging.info(f"Sistema operativo detectado: {os_info}")
    
    # Solo relevante para Windows
    if system_name != "Windows":
        logging.info(f"Las comprobaciones de WinPcap no son necesarias en {os_info}")
        return True
    
    # Verificar privilegios de administrador
    if not check_admin_privileges():
        logging.warning("No se está ejecutando con privilegios de administrador")
        logging.warning("La captura de paquetes puede fallar sin privilegios elevados")
    
    # Comprobar instalación de Npcap
    npcap_ok = check_npcap_installation()
    if not npcap_ok:
        logging.warning("Problemas detectados con la instalación de Npcap")
    
    # Comprobar acceso a interfaces de red con Scapy
    ifaces_ok = check_scapy_interface_access()
    if not ifaces_ok:
        logging.warning("Problemas detectados con el acceso a interfaces de red")
    
    # Comprobar soporte ICMP en Scapy
    icmp_ok = check_scapy_icmp_support()
    if not icmp_ok:
        logging.warning("Problemas detectados con el soporte ICMP")
    
    # Resultado final
    if npcap_ok and ifaces_ok and icmp_ok:
        logging.info("Compatibilidad WinPcap OK - La captura de paquetes ICMP debería funcionar")
        return True
    else:
        logging.warning(f"Se detectaron problemas con la compatibilidad WinPcap en {os_info}")
        provide_fix_instructions()
        return False

if __name__ == "__main__":
    # Si se ejecuta directamente, mostrar resultado detallado
    try:
        os.makedirs("logs", exist_ok=True)  # Asegurar que existe el directorio de logs
        
        # Obtener información detallada del sistema operativo
        os_info = get_detailed_os_info()
        
        if quick_winpcap_check():
            print(f"\n✅ Sistema operativo: {os_info}")
            print("\n✅ La configuración de captura de paquetes ICMP es correcta")
            sys.exit(0)
        else:
            print(f"\n❌ Sistema operativo: {os_info}")
            print("\n❌ Se detectaron problemas con la captura de paquetes ICMP")
            print("   Ejecute 'solucionar_winpcap.bat' para solucionarlos")
            sys.exit(1)
    except Exception as e:
        logging.error(f"Error durante la comprobación: {e}")
        sys.exit(1)
