#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Módulo para capturar paquetes de red utilizando Scapy
"""

import threading
import logging
import time
import os
from collections import deque
from scapy.all import sniff, conf
from PyQt5.QtCore import QObject, pyqtSignal

# Cache para optimizar operaciones
_packet_cache = {}
_interface_cache = {}
_cached_interfaces = {}

class PacketCapturer(QObject):
    """Clase para capturar paquetes de red usando Scapy"""
    
    # Señal emitida cuando se captura un paquete o lote de paquetes
    packetCaptured = pyqtSignal(object)
    batchCaptured = pyqtSignal(list)
    
    def __init__(self, interface=None):
        """Inicializa el capturador de paquetes
        
        Args:
            interface (str, optional): Nombre de la interfaz a usar para captura
        """
        super().__init__()
        
        self.interface = interface
        self.running = False
        self.capture_thread = None
        self.stop_sniff = threading.Event()
        
        # Configuración para procesamiento por lotes
        self.batch_mode = True
        self.batch_size = 100  # Tamaño del lote de paquetes
        self.packet_buffer = deque(maxlen=self.batch_size)
        self.last_emit_time = 0
        self.emit_interval = 0.5  # Segundos
        
    def start_capture(self, filter_str=None):
        """Inicia la captura de paquetes
        
        Args:
            filter_str (str, optional): Filtro BPF para aplicar a la captura
        """
        if self.running:
            logging.warning("La captura ya está en curso")
            return
            
        self.running = True
        self.stop_sniff.clear()
        
        # Iniciar el hilo de captura
        self.capture_thread = threading.Thread(
            target=self._capture_thread_func,
            args=(filter_str,),
            daemon=True
        )
        self.capture_thread.start()
        logging.info(f"Captura iniciada en interfaz: {self.interface}")
        
    def stop_capture(self):
        """Detiene la captura de paquetes en curso"""
        if not self.running:
            logging.warning("No hay captura en curso para detener")
            return
            
        self.running = False
        self.stop_sniff.set()
        
        if self.capture_thread and self.capture_thread.is_alive():
            self.capture_thread.join(timeout=2.0)
            
        logging.info("Captura detenida")
        
    def _capture_thread_func(self, filter_str=None):
        """Función que ejecuta el hilo de captura
        
        Args:
            filter_str (str, optional): Filtro BPF para aplicar a la captura
        """
        try:
            # Configurar opciones de sniff
            kwargs = {
                'prn': self._packet_callback,
                'stop_filter': lambda _: self.stop_sniff.is_set(),
                'store': 0,  # No almacenar paquetes en memoria
            }
            
            if self.interface:
                kwargs['iface'] = self.interface
                
            if filter_str:
                kwargs['filter'] = filter_str
                
            # Iniciar captura
            sniff(**kwargs)
            
        except Exception as e:
            logging.error(f"Error en captura de paquetes: {e}")
            self.running = False
    
    def _packet_callback(self, packet):
        """Callback llamado cuando se captura un paquete
        
        Args:
            packet: Paquete capturado por Scapy
        """
        try:
            if self.batch_mode:
                # Añadir paquete al buffer
                self.packet_buffer.append(packet)
                
                current_time = time.time()
                buffer_full = len(self.packet_buffer) >= self.batch_size
                time_elapsed = (current_time - self.last_emit_time) >= self.emit_interval
                
                # Emitir lote cuando el buffer esté lleno o haya pasado suficiente tiempo
                if buffer_full or (time_elapsed and self.packet_buffer):
                    packets_to_emit = list(self.packet_buffer)
                    self.packet_buffer.clear()
                    self.last_emit_time = current_time
                    
                    # Emitir señal con el lote de paquetes
                    self.batchCaptured.emit(packets_to_emit)
            else:
                # Modo tradicional: emitir cada paquete individualmente
                self.packetCaptured.emit(packet)
                
        except Exception as e:
            logging.error(f"Error en callback de paquete: {e}")
    
    @staticmethod
    def get_interfaces():
        """Obtiene la lista de interfaces de red disponibles
        
        Returns:
            list: Lista de diccionarios con información de las interfaces
        """
        interfaces = []
        
        def _cached_interfaces(timestamp):
            """Función para cachear resultados de interfaces"""
            if timestamp in _interface_cache:
                return _interface_cache[timestamp]
            return interfaces
        
        try:
            # Método 1: Usar Scapy para obtener interfaces
            for iface_name, iface_data in conf.ifaces.items():
                try:
                    interfaces.append({
                        'name': iface_name,
                        'description': str(iface_data.description),
                        'mac': iface_data.mac or '',
                        'ip': getattr(iface_data, 'ip', '')
                    })
                except Exception as e:
                    logging.debug(f"Error al obtener datos de interfaz {iface_name}: {e}")
                    
            if interfaces:
                # Usar el timestamp actual redondeado a 5 minutos para permitir una actualización cada 5 minutos como máximo
                current_5min = int(time.time() / 300)
                _interface_cache[current_5min] = interfaces
                return interfaces
                
            # Método 2: Usar netifaces como alternativa
            try:
                import netifaces
                logging.info("Intentando obtener interfaces con netifaces")
                
                for iface_name in netifaces.interfaces():
                    try:
                        addrs = netifaces.ifaddresses(iface_name)
                        
                        # Obtener dirección MAC
                        mac = ''
                        if netifaces.AF_LINK in addrs and addrs[netifaces.AF_LINK]:
                            mac = addrs[netifaces.AF_LINK][0].get('addr', '')
                        
                        # Obtener dirección IP
                        ip = ''
                        if netifaces.AF_INET in addrs and addrs[netifaces.AF_INET]:
                            ip = addrs[netifaces.AF_INET][0].get('addr', '')
                            
                        interfaces.append({
                            'name': iface_name,
                            'description': f'Interfaz {iface_name}',
                            'mac': mac,
                            'ip': ip
                        })
                    except Exception as e:
                        logging.debug(f"Error al procesar interfaz {iface_name} con netifaces: {e}")
                
                if interfaces:
                    # Usar el timestamp actual redondeado a 5 minutos
                    current_5min = int(time.time() / 300)
                    _interface_cache[current_5min] = interfaces
                    return interfaces
                    
            except ImportError:
                logging.info("netifaces no está disponible, intentando otro método")
            except Exception as e:
                logging.error(f"Error al obtener interfaces: {e}")
                import traceback
                logging.error(traceback.format_exc())
                
            # Método 3: Usar ipconfig como alternativa en Windows
            try:
                import subprocess
                import re
                import platform
                
                if platform.system() == "Windows":
                    # Ejecutar ipconfig y capturar su salida
                    proc = subprocess.Popen("ipconfig /all", shell=True, stdout=subprocess.PIPE)
                    output = proc.stdout.read().decode('latin-1', errors='ignore')
                    
                    # Buscar interfaces con patrón simple
                    iface_blocks = re.split(r'\r?\n\r?\n', output)
                    for block in iface_blocks:
                        if not block.strip():
                            continue
                            
                        name_match = re.search(r'Adaptador.*: (.*?):', block)
                        if name_match:
                            iface_name = name_match.group(1).strip()
                            
                            # Buscar MAC e IP
                            mac_match = re.search(r'Direcci.n f.sica.*?: (.*?)[\r\n]', block)
                            mac = mac_match.group(1).strip() if mac_match else ''
                            
                            ip_match = re.search(r'Direcci.n IPv4.*?: (.*?)[\r\n]', block)
                            ip = ip_match.group(1).strip() if ip_match else ''
                            
                            interfaces.append({
                                'name': iface_name,
                                'description': f'Adaptador {iface_name}',
                                'mac': mac,
                                'ip': ip
                            })
                
                if interfaces:
                    current_5min = int(time.time() / 300)
                    _interface_cache[current_5min] = interfaces
                    return interfaces
                    
            except Exception as e:
                logging.error(f"Error al obtener interfaces con ipconfig: {e}")
                
        except Exception as e:
            logging.error(f"Error general al obtener interfaces: {e}")
            
        # Devolver al menos una interfaz por defecto si no se encontró ninguna
        if not interfaces:
            interfaces.append({
                'name': 'lo0' if os.name != 'nt' else 'Ethernet',
                'description': 'Interfaz por defecto',
                'mac': '00:00:00:00:00:00',
                'ip': '127.0.0.1'
            })
            
        # Usar el timestamp actual redondeado a 5 minutos
        current_5min = int(time.time() / 300)
        _interface_cache[current_5min] = interfaces
        return interfaces
