#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Script para probar la captura de tráfico ICMP (ping)
"""

import sys
import time
import logging
from scapy.all import sniff, IP, ICMP, conf

# Configuración de logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

def packet_callback(packet):
    """Callback para cada paquete capturado"""
    if packet.haslayer(ICMP):
        logging.info("¡PAQUETE ICMP DETECTADO!")
        
        # Extraer información
        src = packet[IP].src if packet.haslayer(IP) else "Desconocido"
        dst = packet[IP].dst if packet.haslayer(IP) else "Desconocido"
        icmp_type = packet[ICMP].type
        
        # Determinar tipo de ICMP
        icmp_type_name = "Desconocido"
        if icmp_type == 0:
            icmp_type_name = "Echo Reply (respuesta ping)"
        elif icmp_type == 8:
            icmp_type_name = "Echo Request (solicitud ping)"
        
        logging.info(f"ICMP: {src} -> {dst} | Tipo: {icmp_type} ({icmp_type_name})")
        
        # Mostrar el paquete completo para depuración
        logging.info(f"Paquete completo:\n{packet.show(dump=True)}")
        
def main():
    """Función principal"""
    logging.info("=== Prueba de Captura de ICMP ===")
    
    # Mostrar interfaces disponibles
    logging.info("Interfaces disponibles:")
    for iface_name in conf.ifaces.keys():
        logging.info(f"- {iface_name}")
    
    # Solicitar nombre de interfaz
    if len(sys.argv) > 1:
        interface = sys.argv[1]
    else:
        interface = input("Ingrese el nombre de la interfaz a escuchar (deje en blanco para auto): ")
        if not interface.strip():
            interface = None
    
    logging.info(f"Iniciando captura en interfaz: {interface or 'Auto'}")
    logging.info("Ejecute 'ping 192.168.1.18' en otra terminal para generar tráfico ICMP")
    logging.info("Presione Ctrl+C para detener la captura")
    
    try:
        # Configurar captura para detectar ICMP específicamente
        sniff(
            iface=interface if interface else None,
            prn=packet_callback,
            filter="icmp",  # Filtro BPF para ICMP solamente
            store=False,
            count=0  # Sin límite
        )
    except KeyboardInterrupt:
        logging.info("Captura detenida por el usuario")
    except Exception as e:
        logging.error(f"Error durante la captura: {e}")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
