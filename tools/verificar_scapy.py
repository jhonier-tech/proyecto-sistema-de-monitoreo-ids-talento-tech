#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Script para verificar si Scapy puede acceder a las interfaces de red,
lo que indica compatibilidad correcta con WinPcap
"""

import sys
import logging

# Configuración de logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

def main():
    """Función principal"""
    logging.info("=== Verificación de Acceso a Interfaces de Red con Scapy ===")
    
    # Paso 1: Verificar que Scapy está instalado
    try:
        logging.info("Verificando instalación de Scapy...")
        import scapy
        logging.info(f"✅ Scapy {scapy.__version__} está instalado")
    except ImportError:
        logging.error("❌ Scapy no está instalado. Instálelo con: pip install scapy>=2.5.0")
        return 1
    
    # Paso 2: Verificar que se puede importar el módulo conf de Scapy
    try:
        logging.info("Verificando acceso al módulo de configuración de Scapy...")
        from scapy.all import conf
        logging.info("✅ Módulo de configuración accesible")
    except ImportError as e:
        logging.error(f"❌ Error al importar módulo de configuración: {e}")
        return 1
    
    # Paso 3: Verificar que se pueden listar las interfaces de red
    try:
        logging.info("Verificando acceso a interfaces de red...")
        ifaces = conf.ifaces
        if not ifaces:
            logging.error("❌ No se encontraron interfaces de red")
            return 1
        
        logging.info(f"✅ Se encontraron {len(ifaces)} interfaces de red")
        
        # Listar todas las interfaces
        logging.info("Interfaces disponibles:")
        for idx, (iface_name, iface_obj) in enumerate(ifaces.items()):
            logging.info(f"{idx+1}. {iface_name} - {iface_obj}")
        
    except Exception as e:
        logging.error(f"❌ Error al acceder a interfaces de red: {e}")
        return 1
    
    # Paso 4: Verificar que se puede acceder al sniffer
    try:
        logging.info("Verificando acceso al sniffer...")
        from scapy.all import sniff
        logging.info("✅ Función de sniffing accesible")
    except ImportError as e:
        logging.error(f"❌ Error al importar función de sniffing: {e}")
        return 1
    
    # Paso 5: Verificar que se pueden cargar las capas de protocolos
    try:
        logging.info("Verificando capas de protocolos...")
        from scapy.all import IP, ICMP, TCP, UDP
        logging.info("✅ Capas de protocolos accesibles")
    except ImportError as e:
        logging.error(f"❌ Error al importar capas de protocolos: {e}")
        return 1
    
    # Resultado final
    logging.info("=== Resultados de la Verificación ===")
    logging.info("✅ Scapy puede acceder a las interfaces de red correctamente")
    logging.info("✅ La compatibilidad con WinPcap parece estar funcionando")
    logging.info("✅ NetSniffer debería poder capturar paquetes ICMP sin problemas")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
