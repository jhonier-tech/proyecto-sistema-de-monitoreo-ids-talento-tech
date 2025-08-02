#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Módulo para aplicar y gestionar filtros de paquetes
"""

import logging
import re
from PyQt5.QtCore import QObject

class FilterManager(QObject):
    """Clase para gestionar y aplicar filtros de paquetes de manera eficiente"""
    
    def __init__(self):
        """Inicializa el gestor de filtros"""
        super().__init__()
        self.max_recursion_depth = 50  # Limitar recursión para evitar problemas
        
    def parse_filter(self, filter_text):
        """Convierte un texto de filtro en una función de filtrado
        
        Args:
            filter_text (str): Texto del filtro (por ejemplo, 'tcp', 'ip.src==192.168.1.1')
            
        Returns:
            function: Función que recibe un paquete y devuelve True si pasa el filtro
        """
        if not filter_text:
            return lambda packet: True
            
        # Validar y limpiar el texto del filtro
        try:
            filter_text = filter_text.lower().strip()
        except:
            logging.error("Filtro inválido, mostrando todos los paquetes")
            return lambda packet: True
        
        # Filtros básicos predefinidos (optimizados)
        basic_filters = {
            'tcp': lambda p: 'TCP' in p,
            'udp': lambda p: 'UDP' in p,
            'icmp': lambda p: 'ICMP' in p,
            'arp': lambda p: 'ARP' in p,
            'dns': lambda p: 'DNS' in p,
            'http': lambda p: 'HTTP' in p or ('TCP' in p and (p['TCP'].dport == 80 or p['TCP'].sport == 80)),
            'https': lambda p: 'TCP' in p and (p['TCP'].dport == 443 or p['TCP'].sport == 443),
            'ip': lambda p: 'IP' in p,
            'ipv6': lambda p: 'IPv6' in p,
        }
        
        # Comprobar filtros básicos
        if filter_text in basic_filters:
            return basic_filters[filter_text]
            
        # Filtros de campos específicos
        try:
            # Dirección IP origen
            if filter_text.startswith('ip.src=='):
                ip = filter_text.split('==')[1].strip()
                return lambda p: p.haslayer('IP') and p['IP'].src == ip
                
            # Dirección IP destino
            elif filter_text.startswith('ip.dst=='):
                ip = filter_text.split('==')[1].strip()
                return lambda p: p.haslayer('IP') and p['IP'].dst == ip
                
            # Puerto origen
            elif filter_text.startswith('tcp.sport==') or filter_text.startswith('udp.sport=='):
                proto = filter_text.split('.')[0].upper()
                port = int(filter_text.split('==')[1].strip())
                return lambda p: p.haslayer(proto) and p[proto].sport == port
                
            # Puerto destino
            elif filter_text.startswith('tcp.dport==') or filter_text.startswith('udp.dport=='):
                proto = filter_text.split('.')[0].upper()
                port = int(filter_text.split('==')[1].strip())
                return lambda p: p.haslayer(proto) and p[proto].dport == port
                
            # Búsqueda de texto general
            else:
                return lambda p: self._search_packet_content(p, filter_text)
                
        except Exception as e:
            logging.error(f"Error al parsear filtro '{filter_text}': {e}")
            return lambda packet: True
            
    def _search_packet_content(self, packet, search_text, depth=0):
        """Busca texto en los campos del paquete de forma recursiva
        
        Args:
            packet: Paquete a analizar
            search_text (str): Texto a buscar
            depth (int): Profundidad actual de recursión
            
        Returns:
            bool: True si se encuentra el texto, False en caso contrario
        """
        # Protección contra recursión excesiva
        if depth >= self.max_recursion_depth:
            logging.warning(f"Límite de recursión alcanzado ({self.max_recursion_depth}) al buscar '{search_text}'")
            return False
            
        try:
            # Método seguro: usar representación en string para buscar
            # Evita la recursión profunda en los campos del paquete
            packet_str = str(packet).lower()
            if search_text in packet_str:
                return True
                
            # No buscar recursivamente en las capas para evitar problemas de recursión
            # Solo verificar campos de primer nivel
            return False
            
        except Exception as e:
            logging.error(f"Error en búsqueda de contenido: {e}")
            return False
            
    def validate_filter(self, filter_text):
        """Valida un filtro antes de aplicarlo
        
        Args:
            filter_text (str): Texto del filtro a validar
            
        Returns:
            tuple: (es_válido, mensaje_error)
        """
        if not filter_text or not filter_text.strip():
            return True, ""
            
        filter_text = filter_text.strip().lower()
        
        # Verificar filtros básicos conocidos
        basic_filters = ["tcp", "udp", "icmp", "arp", "dns", "http", "https", "ip", "ipv6"]
        if filter_text in basic_filters:
            return True, ""
            
        # Verificar filtros de campo
        if filter_text.startswith("ip.src==") or filter_text.startswith("ip.dst=="):
            ip = filter_text.split("==")[1].strip()
            # Validación básica de IP (simplificada)
            if not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip):
                return False, f"Formato de IP inválido: {ip}"
                
        elif filter_text.startswith("tcp.sport==") or filter_text.startswith("udp.sport==") or \
             filter_text.startswith("tcp.dport==") or filter_text.startswith("udp.dport=="):
            try:
                port = filter_text.split("==")[1].strip()
                port_num = int(port)
                if port_num < 0 or port_num > 65535:
                    return False, f"Número de puerto fuera de rango (0-65535): {port}"
            except:
                return False, f"Formato de puerto inválido: {filter_text.split('==')[1].strip()}"
                
        return True, ""
    
    def apply_filter(self, packet, filter_text):
        """Aplica un filtro a un paquete
        
        Args:
            packet: Paquete a filtrar
            filter_text (str): Texto del filtro
            
        Returns:
            bool: True si el paquete pasa el filtro, False en caso contrario
        """
        # Si no hay filtro, aceptar todos los paquetes
        if not filter_text or not filter_text.strip():
            return True
            
        # Validar el filtro primero
        is_valid, _ = self.validate_filter(filter_text)
        if not is_valid:
            return True
            
        try:
            # Implementación simplificada y segura para evitar recursión
            filter_text = filter_text.strip().lower()
            
            # Filtros básicos rápidos
            if filter_text == "tcp":
                return "TCP" in packet
            elif filter_text == "udp":
                return "UDP" in packet
            elif filter_text == "icmp":
                return "ICMP" in packet
            elif filter_text == "arp":
                return "ARP" in packet
            elif filter_text == "dns":
                return "DNS" in packet
            elif filter_text == "http":
                return "HTTP" in packet or ("TCP" in packet and (packet["TCP"].dport == 80 or packet["TCP"].sport == 80))
            elif filter_text == "https":
                return "TCP" in packet and (packet["TCP"].dport == 443 or packet["TCP"].sport == 443)
            elif filter_text == "ip":
                return "IP" in packet
            elif filter_text == "ipv6":
                return "IPv6" in packet
                
            # Filtros de campo específicos
            if filter_text.startswith("ip.src=="):
                ip = filter_text.split("==")[1].strip()
                return "IP" in packet and packet["IP"].src == ip
                
            elif filter_text.startswith("ip.dst=="):
                ip = filter_text.split("==")[1].strip()
                return "IP" in packet and packet["IP"].dst == ip
                
            elif filter_text.startswith("tcp.sport=="):
                port = int(filter_text.split("==")[1].strip())
                return "TCP" in packet and packet["TCP"].sport == port
                
            elif filter_text.startswith("tcp.dport=="):
                port = int(filter_text.split("==")[1].strip())
                return "TCP" in packet and packet["TCP"].dport == port
                
            elif filter_text.startswith("udp.sport=="):
                port = int(filter_text.split("==")[1].strip())
                return "UDP" in packet and packet["UDP"].sport == port
                
            elif filter_text.startswith("udp.dport=="):
                port = int(filter_text.split("==")[1].strip())
                return "UDP" in packet and packet["UDP"].dport == port
            
            # Búsqueda de texto simple en la representación del paquete
            else:
                packet_str = str(packet).lower()
                return filter_text in packet_str
                
        except Exception as e:
            logging.error(f"Error al aplicar filtro '{filter_text}': {e}")
            return True  # En caso de error, mostrar el paquete por defecto
