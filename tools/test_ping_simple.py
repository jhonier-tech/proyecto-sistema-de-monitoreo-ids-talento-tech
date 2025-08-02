#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Script simplificado para probar la captura de tráfico ICMP (ping)
"""

import sys
import time
import logging
import traceback

# Configuración de logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

def main():
    """Función principal simplificada"""
    logging.info("=== Prueba Simplificada de Captura de ICMP ===")
    
    try:
        # Importar Scapy con manejo de excepciones
        logging.info("Importando biblioteca Scapy...")
        try:
            from scapy.all import sniff, conf, IP, ICMP
            logging.info("✅ Scapy importado correctamente")
        except ImportError as e:
            logging.error(f"❌ Error al importar Scapy: {e}")
            logging.error("Por favor, verifique que Scapy está instalado: pip install scapy")
            return 1
        
        # Listar interfaces disponibles
        logging.info("Interfaces disponibles:")
        for idx, (iface_name, iface_obj) in enumerate(conf.ifaces.items()):
            logging.info(f"{idx+1}. {iface_name} - {iface_obj}")
        
        # Solicitar nombre de interfaz o usar automáticamente
        if len(sys.argv) > 1:
            selected_interface = sys.argv[1]
        else:
            try:
                choice = input("Seleccione el número de interfaz a escuchar (Enter para auto): ")
                if choice.strip():
                    idx = int(choice) - 1
                    ifaces = list(conf.ifaces.keys())
                    if 0 <= idx < len(ifaces):
                        selected_interface = ifaces[idx]
                    else:
                        logging.error("Número de interfaz inválido")
                        return 1
                else:
                    selected_interface = None
            except ValueError:
                logging.error("Entrada inválida")
                return 1
        
        # Instrucciones para el usuario
        logging.info("")
        logging.info("INSTRUCCIONES:")
        logging.info("1. Abra otra ventana CMD o PowerShell")
        logging.info("2. Ejecute: ping 8.8.8.8 -t (o cualquier otra dirección IP activa)")
        logging.info("3. Observe si se detectan paquetes ICMP en esta ventana")
        logging.info("4. Presione Ctrl+C para detener la prueba cuando termine")
        logging.info("")
        
        # Función para procesar paquetes
        def packet_callback(packet):
            if packet.haslayer(ICMP):
                icmp_type = packet[ICMP].type
                icmp_type_name = "Desconocido"
                if icmp_type == 0:
                    icmp_type_name = "Echo Reply (respuesta ping)"
                elif icmp_type == 8:
                    icmp_type_name = "Echo Request (solicitud ping)"
                
                src = packet[IP].src if packet.haslayer(IP) else "Desconocido"
                dst = packet[IP].dst if packet.haslayer(IP) else "Desconocido"
                
                logging.info("¡PAQUETE ICMP DETECTADO!")
                logging.info(f"ICMP: {src} -> {dst} | Tipo: {icmp_type} ({icmp_type_name})")
                
                # Mostrar ID y secuencia si están disponibles
                if hasattr(packet[ICMP], 'id') and hasattr(packet[ICMP], 'seq'):
                    logging.info(f"  ID: {packet[ICMP].id}, Seq: {packet[ICMP].seq}")
        
        # Iniciar captura
        logging.info(f"Iniciando captura en interfaz: {selected_interface or 'Auto'}")
        logging.info("Ejecute 'ping 8.8.8.8' en otra terminal para generar tráfico ICMP")
        logging.info("Presione Ctrl+C para detener la captura")
        
        # Configurar captura
        sniff(
            iface=selected_interface,
            prn=packet_callback,
            filter="icmp",  # Filtro BPF para ICMP solamente
            store=False,
            count=0  # Sin límite
        )
    
    except KeyboardInterrupt:
        logging.info("Captura detenida por el usuario")
    except Exception as e:
        logging.error(f"Error durante la captura: {e}")
        logging.error(traceback.format_exc())
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
