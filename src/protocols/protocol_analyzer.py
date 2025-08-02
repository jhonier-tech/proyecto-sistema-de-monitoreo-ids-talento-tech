#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Módulo para la detección y análisis de protocolos de red
"""

import logging
import time
from functools import lru_cache
from scapy.all import *
from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether, ARP
from scapy.layers.dns import DNS

# Mapa de puertos comunes a servicios
COMMON_PORTS = {
    # Puertos TCP comunes
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    115: "SFTP",
    119: "NNTP",
    123: "NTP",
    143: "IMAP",
    161: "SNMP",
    194: "IRC",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    587: "SMTP",
    993: "IMAPS",
    995: "POP3S",
    1080: "SOCKS",
    1194: "OpenVPN",
    1433: "MSSQL",
    1521: "Oracle",
    3306: "MySQL",
    3389: "RDP",
    5060: "SIP",
    5061: "SIP-TLS",
    5222: "XMPP",
    5432: "PostgreSQL",
    5900: "VNC",
    6660: "IRC",
    6661: "IRC",
    6662: "IRC",
    6663: "IRC",
    6664: "IRC",
    6665: "IRC",
    6666: "IRC",
    6667: "IRC",
    6668: "IRC",
    6669: "IRC",
    8000: "HTTP-Alt",
    8080: "HTTP-Proxy",
    8443: "HTTPS-Alt",
    9000: "HTTP-Alt",
    9090: "HTTP-Alt",
    9100: "JetDirect",
    
    # Puertos UDP comunes
    53: "DNS",
    67: "DHCP-Server",
    68: "DHCP-Client",
    69: "TFTP",
    123: "NTP",
    137: "NetBIOS-NS",
    138: "NetBIOS-DGM",
    161: "SNMP",
    162: "SNMP-Trap",
    514: "Syslog",
    520: "RIP",
    1194: "OpenVPN",
    1701: "L2TP",
    1812: "RADIUS",
    1813: "RADIUS",
    4500: "IPsec",
    5060: "SIP",
    5353: "mDNS"
}

class ProtocolAnalyzer:
    """Clase para analizar y detectar protocolos en paquetes de red"""
    
    # Caché para mejorar rendimiento (máximo 1000 entradas)
    _protocol_cache = {}
    _cache_size_limit = 1000
    _last_cache_cleanup = time.time()
    _cleanup_interval = 60  # segundos
    
    @classmethod
    def _cleanup_cache(cls):
        """Limpia el caché si es necesario para evitar consumo excesivo de memoria"""
        current_time = time.time()
        if (current_time - cls._last_cache_cleanup) > cls._cleanup_interval:
            # Si el caché supera el límite, eliminar la mitad de las entradas más antiguas
            if len(cls._protocol_cache) > cls._cache_size_limit:
                # Ordenar por tiempo de último acceso
                sorted_cache = sorted(cls._protocol_cache.items(), key=lambda x: x[1]['last_access'])
                # Eliminar la mitad más antigua
                items_to_remove = len(sorted_cache) // 2
                for i in range(items_to_remove):
                    if sorted_cache[i][0] in cls._protocol_cache:
                        del cls._protocol_cache[sorted_cache[i][0]]
            cls._last_cache_cleanup = current_time
    
    @staticmethod
    def _get_packet_fingerprint(packet):
        """Genera una huella única para un paquete para usar como clave de caché
        
        Args:
            packet: El paquete a analizar
            
        Returns:
            str: Huella única del paquete
        """
        # Crear una representación única del paquete basada en atributos clave
        fingerprint = []
        
        # Capas básicas para la huella
        if packet.haslayer(IP):
            ip = packet[IP]
            fingerprint.extend([ip.src, ip.dst, str(ip.proto)])
            
            if packet.haslayer(TCP):
                tcp = packet[TCP]
                fingerprint.extend([str(tcp.sport), str(tcp.dport), str(tcp.flags)])
            elif packet.haslayer(UDP):
                udp = packet[UDP]
                fingerprint.extend([str(udp.sport), str(udp.dport)])
            elif packet.haslayer(ICMP):
                icmp = packet[ICMP]
                fingerprint.extend([str(icmp.type), str(icmp.code)])
        
        elif packet.haslayer(ARP):
            arp = packet[ARP]
            fingerprint.extend([arp.hwsrc, arp.hwdst, arp.psrc, arp.pdst, str(arp.op)])
            
        # Añadir longitud del paquete
        fingerprint.append(str(len(packet)))
        
        return ":".join(fingerprint)
    
    @classmethod
    def identify_protocol(cls, packet):
        """Identifica los protocolos presentes en un paquete
        
        Args:
            packet: El paquete a analizar
            
        Returns:
            tuple: (protocolo_principal, protocolos_adicionales)
        """
        # Comprobar si el paquete está en el caché
        fingerprint = cls._get_packet_fingerprint(packet)
        
        # Limpiar caché si es necesario
        cls._cleanup_cache()
        
        # Comprobar si el paquete está en caché
        if fingerprint in cls._protocol_cache:
            cache_entry = cls._protocol_cache[fingerprint]
            # Actualizar tiempo de acceso
            cache_entry['last_access'] = time.time()
            return cache_entry['main_protocol'], cache_entry['additional_protocols']
            
        main_protocol = "Unknown"
        additional_protocols = []
        
        try:
            # Analizar capa 2 (enlace)
            if packet.haslayer(Ether):
                additional_protocols.append("Ethernet")
                
                # Analizar ARP
                if packet.haslayer(ARP):
                    main_protocol = "ARP"
                
                # Analizar capa 3 (red)
                elif packet.haslayer(IP):
                    additional_protocols.append("IPv4")
                    ip_layer = packet.getlayer(IP)
                    
                    # Analizar ICMP
                    if packet.haslayer(ICMP):
                        main_protocol = "ICMP"
                        additional_protocols.append("ICMP")
                        icmp_layer = packet.getlayer(ICMP)
                        
                        # Guardar detalles adicionales del ICMP para análisis más preciso
                        if hasattr(icmp_layer, 'type'):
                            icmp_type = icmp_layer.type
                            if icmp_type == 0:
                                main_protocol = "ICMP-Reply"  # Echo Reply (respuesta ping)
                            elif icmp_type == 8:
                                main_protocol = "ICMP-Request"  # Echo Request (solicitud ping)
                        
                    # Analizar TCP
                    elif packet.haslayer(TCP):
                        tcp_layer = packet.getlayer(TCP)
                        
                        # Buscar puertos conocidos
                        src_service = COMMON_PORTS.get(tcp_layer.sport, None)
                        dst_service = COMMON_PORTS.get(tcp_layer.dport, None)
                        
                        # Analizar HTTP
                        if packet.haslayer(HTTP) or packet.haslayer(HTTPRequest) or packet.haslayer(HTTPResponse):
                            main_protocol = "HTTP"
                        # Detectar HTTPS por puerto
                        elif tcp_layer.dport == 443 or tcp_layer.sport == 443:
                            main_protocol = "HTTPS"
                        # Detectar por puertos conocidos
                        elif dst_service:
                            main_protocol = dst_service
                        elif src_service:
                            main_protocol = src_service
                        else:
                            main_protocol = "TCP"
                            
                        additional_protocols.append("TCP")
                        
                    # Analizar UDP
                    elif packet.haslayer(UDP):
                        udp_layer = packet.getlayer(UDP)
                        additional_protocols.append("UDP")
                        
                        # Analizar DNS
                        if packet.haslayer(DNS):
                            main_protocol = "DNS"
                        # Detectar por puertos conocidos
                        else:
                            src_service = COMMON_PORTS.get(udp_layer.sport, None)
                            dst_service = COMMON_PORTS.get(udp_layer.dport, None)
                            
                            if dst_service:
                                main_protocol = dst_service
                            elif src_service:
                                main_protocol = src_service
                            else:
                                main_protocol = "UDP"
                    else:
                        # Otros protocolos sobre IP
                        main_protocol = f"IP-{ip_layer.proto}"
                
                # Analizar IPv6
                elif packet.haslayer(IPv6):
                    main_protocol = "IPv6"
                    additional_protocols.append("IPv6")
                    
                    # Analizar capas superiores (similar a IPv4)
                    # ... código similar al de IPv4
                    
            # Otros tipos de paquetes
            else:
                if hasattr(packet, 'name'):
                    main_protocol = packet.name
                
        except Exception as e:
            logging.error(f"Error al identificar protocolo: {e}")
            
        # Guardar en caché para futuras consultas
        cls._protocol_cache[fingerprint] = {
            'main_protocol': main_protocol,
            'additional_protocols': additional_protocols,
            'last_access': time.time()
        }
            
        return main_protocol, additional_protocols
    
    @classmethod
    def get_packet_summary(cls, packet):
        """Obtiene un resumen del paquete
        
        Args:
            packet: El paquete a analizar
            
        Returns:
            dict: Diccionario con información del paquete
        """
        # Generar huella única para el paquete
        fingerprint = cls._get_packet_fingerprint(packet)
        
        # Verificar si existe en caché
        if fingerprint in cls._protocol_cache and 'summary' in cls._protocol_cache[fingerprint]:
            # Actualizar tiempo de acceso
            cls._protocol_cache[fingerprint]['last_access'] = time.time()
            return cls._protocol_cache[fingerprint]['summary']
        
        summary = {
            'src': None,
            'dst': None,
            'protocol': None,
            'length': len(packet),
            'info': None
        }
        
        try:
            # Protocolo principal
            main_protocol, _ = ProtocolAnalyzer.identify_protocol(packet)
            summary['protocol'] = main_protocol
            
            # Direcciones origen y destino
            if packet.haslayer(IP):
                summary['src'] = packet[IP].src
                summary['dst'] = packet[IP].dst
            elif packet.haslayer(IPv6):
                summary['src'] = packet[IPv6].src
                summary['dst'] = packet[IPv6].dst
            elif packet.haslayer(Ether):
                summary['src'] = packet[Ether].src
                summary['dst'] = packet[Ether].dst
            elif packet.haslayer(ARP):
                summary['src'] = packet[ARP].psrc
                summary['dst'] = packet[ARP].pdst
                
            # Información adicional
            if packet.haslayer(TCP):
                tcp = packet[TCP]
                summary['src'] = f"{summary['src']}:{tcp.sport}"
                summary['dst'] = f"{summary['dst']}:{tcp.dport}"
                
                # Banderas TCP
                flags = []
                if tcp.flags.S: flags.append("SYN")
                if tcp.flags.A: flags.append("ACK")
                if tcp.flags.F: flags.append("FIN")
                if tcp.flags.R: flags.append("RST")
                if tcp.flags.P: flags.append("PSH")
                if tcp.flags.U: flags.append("URG")
                
                flag_str = " ".join(flags)
                summary['info'] = f"Puerto {tcp.sport} → {tcp.dport} [{flag_str}] Seq={tcp.seq} Ack={tcp.ack}"
                
            elif packet.haslayer(UDP):
                udp = packet[UDP]
                summary['src'] = f"{summary['src']}:{udp.sport}"
                summary['dst'] = f"{summary['dst']}:{udp.dport}"
                summary['info'] = f"Puerto {udp.sport} → {udp.dport} Len={len(udp)}"
                
            elif packet.haslayer(ICMP):
                icmp = packet[ICMP]
                icmp_type = icmp.type
                icmp_code = icmp.code
                
                # Guardar información del ID y secuencia para mejorar la detección
                icmp_id = icmp.id if hasattr(icmp, 'id') else "N/A"
                icmp_seq = icmp.seq if hasattr(icmp, 'seq') else "N/A"
                
                if icmp_type == 0:
                    summary['info'] = f"Echo (ping) reply | ID:{icmp_id} Seq:{icmp_seq}"
                elif icmp_type == 3:
                    summary['info'] = f"Destino inalcanzable (código {icmp_code})"
                elif icmp_type == 5:
                    summary['info'] = "Redirección"
                elif icmp_type == 8:
                    summary['info'] = f"Echo (ping) request | ID:{icmp_id} Seq:{icmp_seq}"
                elif icmp_type == 11:
                    summary['info'] = "Tiempo excedido"
                else:
                    summary['info'] = f"Tipo: {icmp_type}, Código: {icmp_code}"
                    
            elif packet.haslayer(ARP):
                arp = packet[ARP]
                if arp.op == 1:  # who-has
                    summary['info'] = f"¿Quién tiene {arp.pdst}? Díselo a {arp.psrc}"
                elif arp.op == 2:  # is-at
                    summary['info'] = f"{arp.psrc} está en {arp.hwsrc}"
                else:
                    summary['info'] = f"ARP operación {arp.op}"
                    
            elif packet.haslayer(DNS):
                dns = packet[DNS]
                if dns.qr == 0:  # consulta
                    if dns.qd and dns.qd.qname:
                        qname = dns.qd.qname.decode('utf-8', errors='replace')
                        summary['info'] = f"Consulta DNS: {qname}"
                    else:
                        summary['info'] = "Consulta DNS"
                else:  # respuesta
                    summary['info'] = "Respuesta DNS"
                    
            # Si no se ha establecido información específica
            if not summary['info']:
                if hasattr(packet, 'summary'):
                    summary['info'] = packet.summary()
                else:
                    summary['info'] = f"Paquete {main_protocol} ({summary['length']} bytes)"
                    
        except Exception as e:
            logging.error(f"Error al obtener resumen del paquete: {e}")
            summary['info'] = f"Error al analizar paquete: {str(e)}"
            
        # Guardar resumen en caché
        if fingerprint in cls._protocol_cache:
            cls._protocol_cache[fingerprint]['summary'] = summary
        else:
            cls._protocol_cache[fingerprint] = {
                'main_protocol': summary['protocol'],
                'additional_protocols': [],
                'summary': summary,
                'last_access': time.time()
            }
            
        return summary
