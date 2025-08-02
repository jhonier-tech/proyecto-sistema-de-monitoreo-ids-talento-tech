#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Módulo para análisis avanzado de paquetes de red
"""

import socket
import time
import datetime
import platform
import psutil
import logging
from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether, ARP
from protocols.protocol_analyzer import COMMON_PORTS

class PacketAnalyzer:
    """Analizador avanzado de paquetes para Sistema de monitoreo IDS"""
    
    # Niveles de riesgo para tipos de paquetes
    RISK_LEVELS = {
        'ICMP': {
            0: 'Bajo',    # Echo Reply
            3: 'Medio',   # Destination Unreachable
            8: 'Bajo',    # Echo Request
            13: 'Alto',   # Timestamp Request
            14: 'Alto',   # Timestamp Reply
            5: 'Alto',    # Redirect
            9: 'Alto',    # Router Advertisement
        },
        'TCP': {
            'default': 'Medio',
            22: 'Medio',  # SSH
            23: 'Alto',   # Telnet (no encriptado)
            80: 'Bajo',   # HTTP
            443: 'Bajo',  # HTTPS
        },
        'UDP': {
            'default': 'Medio',
            53: 'Bajo',   # DNS
            123: 'Bajo',  # NTP
            161: 'Medio', # SNMP
        },
        'ARP': 'Medio',
        'default': 'Bajo'
    }
    
    @staticmethod
    def get_hostname(ip):
        """Obtiene el nombre del host a partir de su IP
        
        Args:
            ip (str): Dirección IP para resolver
            
        Returns:
            str: Nombre del host o la IP si no se puede resolver
        """
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname
        except:
            return ip
            
    @staticmethod
    def get_packet_risk_level(packet):
        """Determina el nivel de riesgo de un paquete
        
        Args:
            packet: Paquete a analizar
            
        Returns:
            str: Nivel de riesgo (Alto, Medio, Bajo)
        """
        if packet.haslayer(ICMP):
            icmp_type = packet[ICMP].type
            return PacketAnalyzer.RISK_LEVELS['ICMP'].get(icmp_type, 'Medio')
            
        elif packet.haslayer(TCP):
            tcp = packet[TCP]
            dst_port = tcp.dport
            src_port = tcp.sport
            
            # Comprobar puertos específicos
            if dst_port in PacketAnalyzer.RISK_LEVELS['TCP']:
                return PacketAnalyzer.RISK_LEVELS['TCP'][dst_port]
            elif src_port in PacketAnalyzer.RISK_LEVELS['TCP']:
                return PacketAnalyzer.RISK_LEVELS['TCP'][src_port]
                
            # Puertos de sistema (1-1023) pueden representar un riesgo mayor
            if dst_port < 1024 or src_port < 1024:
                return 'Medio'
                
            return PacketAnalyzer.RISK_LEVELS['TCP']['default']
            
        elif packet.haslayer(UDP):
            udp = packet[UDP]
            dst_port = udp.dport
            src_port = udp.sport
            
            # Comprobar puertos específicos
            if dst_port in PacketAnalyzer.RISK_LEVELS['UDP']:
                return PacketAnalyzer.RISK_LEVELS['UDP'][dst_port]
            elif src_port in PacketAnalyzer.RISK_LEVELS['UDP']:
                return PacketAnalyzer.RISK_LEVELS['UDP'][src_port]
                
            return PacketAnalyzer.RISK_LEVELS['UDP']['default']
            
        elif packet.haslayer(ARP):
            return PacketAnalyzer.RISK_LEVELS['ARP']
            
        return PacketAnalyzer.RISK_LEVELS['default']
        
    @staticmethod
    def get_detailed_info(packet):
        """Extrae información detallada de un paquete
        
        Args:
            packet: Paquete a analizar
            
        Returns:
            dict: Diccionario con información detallada del paquete
        """
        try:
            logging.debug(f"Analizando paquete: {packet.summary()}")
            
            info = {
                'timestamp': datetime.fromtimestamp(packet.time).strftime('%Y-%m-%d %H:%M:%S.%f'),
                'length': len(packet),
                'protocol': 'Desconocido',
                'risk_level': PacketAnalyzer.get_packet_risk_level(packet),
                'source_mac': packet[Ether].src if packet.haslayer(Ether) else 'Desconocido',
                'dest_mac': packet[Ether].dst if packet.haslayer(Ether) else 'Desconocido',
                'source_ip': 'Desconocido',
                'dest_ip': 'Desconocido',
                'source_port': None,
                'dest_port': None,
                'source_hostname': 'Desconocido',
                'dest_hostname': 'Desconocido',
                'icmp_type': None,
                'icmp_code': None,
                'tcp_flags': None,
                'detailed_protocol': None
            }
            
            # Identificar capa de red (IP)
            if packet.haslayer(IP):
                ip = packet[IP]
                info['source_ip'] = ip.src
                info['dest_ip'] = ip.dst
                info['source_hostname'] = PacketAnalyzer.get_hostname(ip.src)
                info['dest_hostname'] = PacketAnalyzer.get_hostname(ip.dst)
                info['ttl'] = ip.ttl
            elif packet.haslayer(IPv6):
                ipv6 = packet[IPv6]
                info['source_ip'] = ipv6.src
                info['dest_ip'] = ipv6.dst
                info['source_hostname'] = PacketAnalyzer.get_hostname(ipv6.src)
                info['dest_hostname'] = PacketAnalyzer.get_hostname(ipv6.dst)
                info['ttl'] = ipv6.hlim
            
            # Identificar capa de transporte y aplicación
            if packet.haslayer(TCP):
                tcp = packet[TCP]
                info['protocol'] = 'TCP'
                info['source_port'] = tcp.sport
                info['dest_port'] = tcp.dport
                
                # Analizar flags TCP
                flags = []
                if tcp.flags.S: flags.append('SYN')
                if tcp.flags.A: flags.append('ACK')
                if tcp.flags.F: flags.append('FIN')
                if tcp.flags.R: flags.append('RST')
                if tcp.flags.P: flags.append('PSH')
                if tcp.flags.U: flags.append('URG')
                info['tcp_flags'] = ', '.join(flags)
                
                # Identificar protocolo de aplicación por puerto conocido
                if tcp.dport in COMMON_PORTS:
                    info['detailed_protocol'] = COMMON_PORTS[tcp.dport]
                elif tcp.sport in COMMON_PORTS:
                    info['detailed_protocol'] = COMMON_PORTS[tcp.sport]
                    
            elif packet.haslayer(UDP):
                udp = packet[UDP]
                info['protocol'] = 'UDP'
                info['source_port'] = udp.sport
                info['dest_port'] = udp.dport
                
                # Identificar protocolo de aplicación por puerto conocido
                if udp.dport in COMMON_PORTS:
                    info['detailed_protocol'] = COMMON_PORTS[udp.dport]
                elif udp.sport in COMMON_PORTS:
                    info['detailed_protocol'] = COMMON_PORTS[udp.sport]
                    
            elif packet.haslayer(ICMP):
                icmp = packet[ICMP]
                info['protocol'] = 'ICMP'
                info['icmp_type'] = icmp.type
                info['icmp_code'] = icmp.code
                
                # Identificar tipo de ICMP
                if icmp.type == 0:
                    info['detailed_protocol'] = 'ICMP-Reply'
                elif icmp.type == 8:
                    info['detailed_protocol'] = 'ICMP-Request'
                elif icmp.type == 3:
                    info['detailed_protocol'] = 'ICMP-Unreachable'
                elif icmp.type == 5:
                    info['detailed_protocol'] = 'ICMP-Redirect'
                else:
                    info['detailed_protocol'] = f'ICMP-Type{icmp.type}'
                    
            elif packet.haslayer(ARP):
                info['protocol'] = 'ARP'
                arp = packet[ARP]
                info['source_ip'] = arp.psrc
                info['dest_ip'] = arp.pdst
                info['detailed_protocol'] = 'ARP'
            
            logging.debug(f"Información detallada extraída: {info}")
            return info
            
        except Exception as e:
            import traceback
            logging.error(f"Error al extraer información detallada del paquete: {e}")
            logging.error(traceback.format_exc())
            
            # Devolver información básica para no bloquear la aplicación
            return {
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f'),
                'length': len(packet) if packet else 0,
                'protocol': 'Error',
                'risk_level': 'Desconocido',
                'source_mac': 'Error',
                'dest_mac': 'Error',
                'source_ip': 'Error',
                'dest_ip': 'Error',
                'source_hostname': 'Error',
                'dest_hostname': 'Error',
                'detailed_protocol': 'Error: ' + str(e)
            }
