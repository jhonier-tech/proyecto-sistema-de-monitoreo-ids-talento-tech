#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Script mejorado para probar la captura de tráfico ICMP (ping)
Incluye soluciones para problemas comunes en la detección de paquetes ICMP
"""

import sys
import os
import time
import logging
import platform
from scapy.all import sniff, IP, ICMP, conf, get_if_list

# Configuración para diferentes sistemas operativos
if platform.system() == "Windows":
    try:
        # Intentar importar primero de la ubicación específica
        from scapy.arch.windows import get_windows_if_list
    except ImportError:
        # Definir una función alternativa si no está disponible
        def get_windows_if_list():
            """Versión simplificada de get_windows_if_list cuando no está disponible"""
            interfaces = []
            for iface_name in conf.ifaces.keys():
                interfaces.append({
                    'name': iface_name,
                    'description': str(conf.ifaces[iface_name])
                })
            return interfaces

# Configuración de logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

def verify_admin_privileges():
    """Verifica si se está ejecutando con privilegios de administrador"""
    if platform.system() == "Windows":
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except:
            return False
    else:
        return os.geteuid() == 0  # Para sistemas tipo Unix

def packet_callback(packet):
    """Callback mejorado para cada paquete capturado"""
    try:
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
            elif icmp_type == 3:
                icmp_type_name = "Destino Inalcanzable"
            elif icmp_type == 11:
                icmp_type_name = "Tiempo Excedido"
            
            logging.info(f"ICMP: {src} -> {dst} | Tipo: {icmp_type} ({icmp_type_name})")
            
            # Mostrar información detallada para depuración
            if hasattr(packet[ICMP], 'id'):
                logging.info(f"  ID: {packet[ICMP].id}, Seq: {packet[ICMP].seq}")
            
            return True
    except Exception as e:
        logging.error(f"Error procesando paquete: {e}")
    
    return False

def get_best_interfaces():
    """Obtiene las interfaces más probables para capturar tráfico ICMP"""
    if platform.system() == "Windows":
        try:
            # En Windows, obtener interfaces con descripción
            win_interfaces = get_windows_if_list()
            
            # Filtrar interfaces activas y no virtuales
            active_interfaces = []
            for iface in win_interfaces:
                if 'description' in iface and 'virtual' not in iface['description'].lower() and iface['name'] != 'lo':
                    active_interfaces.append({
                        'name': iface['name'],
                        'description': iface['description']
                    })
            
            # Si no encontramos interfaces, intentar método alternativo
            if not active_interfaces:
                logging.warning("No se encontraron interfaces usando el método principal, intentando alternativa...")
                for iface_name, iface_obj in conf.ifaces.items():
                    if 'lo' not in str(iface_name).lower() and 'loopback' not in str(iface_obj).lower():
                        active_interfaces.append({
                            'name': iface_name,
                            'description': str(iface_obj)
                        })
            
            return active_interfaces
        except Exception as e:
            logging.error(f"Error obteniendo interfaces: {e}")
            # Método de respaldo
            return [{'name': iface, 'description': str(conf.ifaces[iface]) if iface in conf.ifaces else iface} 
                    for iface in get_if_list() if 'lo' not in str(iface).lower()]
    else:
        # Para sistemas tipo Unix
        return [{'name': iface, 'description': iface} for iface in get_if_list() if iface != 'lo']

def test_interface(interface, timeout=10):
    """Prueba la captura en una interfaz específica"""
    logging.info(f"Probando interfaz: {interface}")
    logging.info(f"Ejecutando captura durante {timeout} segundos...")
    
    packets_captured = 0
    
    def count_callback(packet):
        nonlocal packets_captured
        if packet_callback(packet):
            packets_captured += 1
        return packets_captured >= 5  # Detener después de 5 paquetes ICMP
    
    try:
        # Configurar captura para detectar ICMP específicamente
        sniff(
            iface=interface,
            prn=count_callback,
            filter="icmp",  # Filtro BPF para ICMP solamente
            store=False,
            timeout=timeout,  # Tiempo límite para prueba
            stop_filter=lambda p: packets_captured >= 5
        )
        
        return packets_captured
    except Exception as e:
        logging.error(f"Error durante la captura en {interface}: {e}")
        return 0

def main():
    """Función principal mejorada"""
    logging.info("=== Prueba Mejorada de Captura de ICMP ===")
    
    # Verificar privilegios
    if not verify_admin_privileges():
        logging.warning("¡ADVERTENCIA! No se está ejecutando con privilegios de administrador")
        logging.warning("La captura de paquetes puede fallar sin privilegios elevados")
    
    # Obtener interfaces potenciales
    interfaces = get_best_interfaces()
    
    if not interfaces:
        logging.error("No se encontraron interfaces de red utilizables")
        return 1
    
    logging.info("Interfaces disponibles:")
    for i, iface in enumerate(interfaces):
        logging.info(f"{i+1}. {iface['name']} - {iface['description']}")
    
    # Solicitar nombre de interfaz o usar automáticamente
    if len(sys.argv) > 1:
        selected_interface = sys.argv[1]
    else:
        try:
            choice = input("Seleccione el número de interfaz a escuchar (Enter para probar todas): ")
            if choice.strip():
                idx = int(choice) - 1
                if 0 <= idx < len(interfaces):
                    selected_interface = interfaces[idx]['name']
                else:
                    logging.error("Número de interfaz inválido")
                    return 1
            else:
                selected_interface = None
        except ValueError:
            logging.error("Entrada inválida")
            return 1
    
    # Instrucciones para el usuario
    logging.info("INSTRUCCIONES:")
    logging.info("1. Abra otra ventana CMD o PowerShell")
    logging.info("2. Ejecute: ping 8.8.8.8 -t (o cualquier otra dirección IP activa)")
    logging.info("3. Observe si se detectan paquetes ICMP en esta ventana")
    logging.info("4. Presione Ctrl+C para detener la prueba cuando termine")
    
    # Si se seleccionó una interfaz específica
    if selected_interface:
        logging.info(f"Iniciando captura en interfaz: {selected_interface}")
        packets = test_interface(selected_interface, timeout=30)
        
        if packets > 0:
            logging.info(f"✅ ÉXITO: Se capturaron {packets} paquetes ICMP en {selected_interface}")
        else:
            logging.error(f"❌ FALLO: No se detectaron paquetes ICMP en {selected_interface}")
    else:
        # Probar todas las interfaces
        logging.info("Probando todas las interfaces disponibles...")
        success = False
        
        for iface in interfaces:
            logging.info(f"Probando interfaz: {iface['name']} - {iface['description']}")
            packets = test_interface(iface['name'], timeout=10)
            
            if packets > 0:
                logging.info(f"✅ ÉXITO: Se capturaron {packets} paquetes ICMP en {iface['name']}")
                success = True
                # Mostrar esta interfaz como la recomendada
                logging.info(f"RECOMENDACIÓN: Use esta interfaz para NetSniffer: {iface['name']}")
                break
            else:
                logging.warning(f"No se detectaron paquetes ICMP en {iface['name']}")
        
        if not success:
            logging.error("❌ No se detectaron paquetes ICMP en ninguna interfaz")
            logging.error("Posibles problemas:")
            logging.error("1. Npcap no está instalado correctamente")
            logging.error("2. No se están generando paquetes ICMP (pruebe 'ping 8.8.8.8')")
            logging.error("3. Firewall está bloqueando la captura")
            logging.error("4. Se necesitan privilegios de administrador")
    
    logging.info("Prueba finalizada")
    return 0

if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        logging.info("Prueba interrumpida por el usuario")
        sys.exit(0)
    except Exception as e:
        logging.error(f"Error en el script: {e}")
        sys.exit(1)
