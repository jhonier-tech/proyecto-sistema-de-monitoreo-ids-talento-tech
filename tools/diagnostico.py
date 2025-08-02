#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Script para verificar la instalación de Npcap y configuración de Scapy
"""

import os
import sys
import platform
import subprocess
import winreg
import ctypes
import logging

# Configurar logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)

def is_admin():
    """Verifica si el script se está ejecutando con privilegios de administrador"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def check_npcap():
    """Verifica si Npcap está instalado correctamente"""
    print("\n=== Verificando instalación de Npcap ===")
    
    # Verificar directorio de instalación
    npcap_dir = "C:\\Windows\\System32\\Npcap"
    if os.path.exists(npcap_dir):
        print(f"✓ Directorio Npcap encontrado: {npcap_dir}")
    else:
        print(f"✗ Directorio Npcap NO encontrado: {npcap_dir}")
        print("  > Npcap no parece estar instalado correctamente.")
        return False
        
    # Verificar registro de Windows
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Npcap") as key:
            version = winreg.QueryValueEx(key, "Version")[0]
            print(f"✓ Versión de Npcap: {version}")
    except:
        print("✗ No se encontró registro de Npcap en el sistema.")
        print("  > Se recomienda reinstalar Npcap.")
    
    # Verificar archivo DLL principal
    dll_path = os.path.join(npcap_dir, "wpcap.dll")
    if os.path.exists(dll_path):
        print(f"✓ Archivo DLL principal encontrado: {dll_path}")
    else:
        print(f"✗ Archivo DLL principal NO encontrado: {dll_path}")
        print("  > Instalación de Npcap incompleta o corrupta.")
        
    # Verificar Npcap Loopback Adapter
    try:
        output = subprocess.check_output("ipconfig /all", shell=True).decode('latin-1', errors='ignore')
        if "Npcap Loopback Adapter" in output:
            print("✓ Adaptador Loopback de Npcap encontrado")
        else:
            print("! Adaptador Loopback de Npcap no encontrado")
            print("  > Esto podría no ser un problema si no necesitas capturar en loopback.")
    except:
        print("! No se pudo verificar el adaptador de loopback")
    
    return True

def check_scapy_capture():
    """Verifica si Scapy puede capturar paquetes"""
    print("\n=== Verificando capacidades de captura de Scapy ===")
    
    try:
        from scapy.all import conf, get_if_list
        
        # Verificar interfaces de captura
        interfaces = get_if_list()
        if interfaces:
            print(f"✓ Scapy detectó {len(interfaces)} interfaces:")
            for idx, iface in enumerate(interfaces):
                print(f"  {idx+1}. {iface}")
        else:
            print("✗ Scapy no detectó ninguna interfaz de red")
            print("  > Esto indica un problema con la instalación de Npcap o WinPcap.")
            return False
            
        # Verificar configuración de Scapy
        if hasattr(conf, 'use_pcap') and conf.use_pcap:
            print(f"✓ Scapy está configurado para usar pcap: {conf.use_pcap}")
        else:
            print("! Scapy no está configurado para usar pcap")
            print("  > Esto puede causar problemas de captura en Windows.")
            
    except ImportError:
        print("✗ No se pudo importar Scapy")
        print("  > Por favor instala Scapy con: pip install scapy")
        return False
    except Exception as e:
        print(f"✗ Error al verificar Scapy: {e}")
        return False
        
    return True

def install_npcap():
    """Descarga e instala Npcap"""
    print("\n=== Instalación de Npcap ===")
    
    if not is_admin():
        print("✗ Se requieren privilegios de administrador para instalar Npcap")
        print("  > Por favor, ejecute este script como administrador.")
        return False
        
    print("Descargando Npcap desde npcap.com...")
    
    # URL de descarga de Npcap
    npcap_url = "https://nmap.org/npcap/dist/npcap-1.75.exe"
    installer_path = os.path.join(os.environ['TEMP'], "npcap-installer.exe")
    
    try:
        # Importar módulo de descarga
        try:
            from urllib import request
            
            # Descargar instalador
            print(f"Descargando Npcap desde {npcap_url}")
            request.urlretrieve(npcap_url, installer_path)
            
            print(f"Instalador descargado en: {installer_path}")
            print("Ejecutando instalador... (siga las instrucciones en pantalla)")
            
            # Ejecutar instalador
            subprocess.call([installer_path, "/S", "/winpcap_mode=yes"])
            
            print("Instalación de Npcap completada. Por favor reinicie su sistema.")
            return True
            
        except ImportError:
            print("No se pudo importar el módulo urllib para la descarga")
            print(f"Por favor, descargue Npcap manualmente desde: {npcap_url}")
            return False
    except Exception as e:
        print(f"Error durante la instalación de Npcap: {e}")
        print(f"Por favor, descargue Npcap manualmente desde: {npcap_url}")
        return False

def fix_scapy_config():
    """Intenta corregir la configuración de Scapy"""
    print("\n=== Corrigiendo configuración de Scapy ===")
    
    try:
        # Comprobar si existe el directorio de configuración de Scapy
        user_dir = os.path.expanduser("~")
        scapy_dir = os.path.join(user_dir, ".scapy")
        
        if not os.path.exists(scapy_dir):
            os.makedirs(scapy_dir)
            print(f"✓ Directorio de configuración de Scapy creado: {scapy_dir}")
        
        # Crear archivo de configuración para forzar el uso de pcap
        conf_file = os.path.join(scapy_dir, "conf.py")
        
        with open(conf_file, 'w') as f:
            f.write("""# Configuración personalizada para Scapy en Windows
conf.use_pcap = True
conf.use_npcap = True
""")
        print(f"✓ Archivo de configuración creado: {conf_file}")
        print("  > La configuración se aplicará la próxima vez que inicie Scapy.")
        
        return True
    except Exception as e:
        print(f"✗ Error al corregir la configuración de Scapy: {e}")
        return False

def main():
    """Función principal"""
    print("="*70)
    print("      Herramienta de diagnóstico para NetSniffer")
    print("="*70)
    
    print(f"Sistema operativo: {platform.system()} {platform.release()}")
    print(f"Versión de Python: {platform.python_version()}")
    
    # Comprobar si estamos en Windows
    if platform.system() != "Windows":
        print("Esta herramienta es solo para Windows. En sistemas Unix/Linux,")
        print("asegúrese de tener libpcap instalado y ejecutar como root.")
        return 1
    
    # Verificar si se ejecuta como administrador
    if not is_admin():
        print("ADVERTENCIA: Este script no se está ejecutando con privilegios de administrador.")
        print("Algunas comprobaciones y correcciones podrían fallar.")
        print("Se recomienda ejecutar como administrador para mejores resultados.\n")
    
    # Verificar Npcap
    npcap_ok = check_npcap()
    
    # Verificar Scapy
    scapy_ok = check_scapy_capture()
    
    # Sugerencias de solución
    print("\n=== Recomendaciones ===")
    
    if not npcap_ok:
        print("1. Npcap no está instalado o está dañado:")
        print("   - Descargue e instale Npcap desde: https://npcap.com")
        print("   - Asegúrese de marcar 'Install Npcap in WinPcap compatibility mode'")
        print("   - ¿Desea que intente instalar Npcap automáticamente? (s/n)")
        response = input("> ")
        if response.lower() in ['s', 'si', 'sí', 'y', 'yes']:
            install_npcap()
    
    if not scapy_ok:
        print("2. Problemas con Scapy:")
        print("   - Verifique que Scapy esté instalado: pip install scapy")
        print("   - Intente reinstalar Scapy: pip uninstall scapy && pip install scapy")
        print("   - ¿Desea que intente corregir la configuración de Scapy? (s/n)")
        response = input("> ")
        if response.lower() in ['s', 'si', 'sí', 'y', 'yes']:
            fix_scapy_config()
    
    if npcap_ok and scapy_ok:
        print("✓ Todo parece estar configurado correctamente.")
        print("  Si aún tiene problemas con NetSniffer:")
        print("  1. Asegúrese de ejecutar la aplicación como administrador")
        print("  2. Intente seleccionar otra interfaz de red")
        print("  3. Verifique que no haya otros programas bloqueando la captura")
    
    print("\n=== Información adicional para la solución de problemas ===")
    print("Cuando ejecute NetSniffer, asegúrese de:")
    print("1. Usar la interfaz de red correcta (la que está conectada a la red)")
    print("2. Ejecutar como administrador (clic derecho -> Ejecutar como administrador)")
    print("3. Desactivar temporalmente el firewall y antivirus si bloquean la captura")
    print("4. Si tiene múltiples adaptadores de red, pruebe cada uno")
    
    print("\n=== Comprobación completa ===")
    return 0

if __name__ == "__main__":
    sys.exit(main())
