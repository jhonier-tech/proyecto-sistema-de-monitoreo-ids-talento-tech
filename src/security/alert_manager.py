#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Módulo para la gestión de alertas y bloqueo de IPs sospechosas
"""

import os
import sys
import platform
import logging
import datetime
import threading
import subprocess
import ipaddress
import json
import traceback
from collections import defaultdict, deque

from security.security_config import ALERT_MESSAGES, BLOCK_ACTIONS, DEFAULT_OS

class AlertManager:
    """Gestor de alertas de seguridad para Sistema de monitoreo IDS"""
    
    # Constantes para detección de sistemas operativos por TTL
    OS_TTL_RANGES = {
        'Windows': range(64, 129),    # Windows: TTL 128
        'Linux': range(30, 65),       # Linux/Unix: TTL 64
        'MacOS': range(30, 65),       # MacOS: TTL 64
        'Cisco': range(240, 256),     # Cisco: TTL 255
        'Solaris': range(240, 256),   # Solaris: TTL 255
    }
    
    def __init__(self):
        """Inicializa el gestor de alertas"""
        self.alerts = deque(maxlen=100)  # Cola de alertas (máximo 100)
        self.blocked_ips = set()  # Conjunto de IPs bloqueadas
        self.ping_count = defaultdict(int)  # Contador de pings por IP
        self.last_alert_time = defaultdict(lambda: datetime.datetime.min)
        self.suspicious_patterns = {
            'ping_flood': {'threshold': 5, 'window': 10},  # 5 pings en 10 segundos
            'port_scan': {'threshold': 10, 'window': 30},  # 10 puertos distintos en 30 segundos
        }
        self.port_scan_tracker = defaultdict(set)  # Seguimiento de puertos por IP
        self.alert_callbacks = []  # Callbacks para notificaciones de alertas
        
        # Cargar configuración personalizada si existe
        self.custom_messages = {}
        self.load_custom_config()
        
        # Cargar IPs bloqueadas previamente
        self.load_blocked_ips()
        
    def load_blocked_ips(self):
        """Carga la lista de IPs bloqueadas desde un archivo"""
        try:
            blocked_file = os.path.join(os.path.dirname(os.path.dirname(__file__)), 
                                      "data", "blocked_ips.txt")
            if os.path.exists(blocked_file):
                with open(blocked_file, 'r') as f:
                    for line in f:
                        ip = line.strip()
                        if ip and not ip.startswith('#'):
                            self.blocked_ips.add(ip)
                logging.info(f"Cargadas {len(self.blocked_ips)} IPs bloqueadas")
        except Exception as e:
            logging.error(f"Error al cargar las IPs bloqueadas: {e}")
    
    def save_blocked_ips(self):
        """Guarda la lista de IPs bloqueadas en un archivo"""
        try:
            data_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data")
            os.makedirs(data_dir, exist_ok=True)
            
            blocked_file = os.path.join(data_dir, "blocked_ips.txt")
            with open(blocked_file, 'w') as f:
                f.write("# Lista de IPs bloqueadas por Sistema de monitoreo IDS\n")
                f.write("# Generado: " + datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S") + "\n\n")
                for ip in sorted(self.blocked_ips):
                    f.write(ip + "\n")
            logging.info(f"Guardadas {len(self.blocked_ips)} IPs bloqueadas")
        except Exception as e:
            logging.error(f"Error al guardar las IPs bloqueadas: {e}")
            
    def load_custom_config(self):
        """Carga la configuración personalizada de mensajes"""
        try:
            data_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data")
            config_file = os.path.join(data_dir, "security_messages.json")
            
            if os.path.exists(config_file):
                with open(config_file, 'r', encoding='utf-8') as f:
                    self.custom_messages = json.load(f)
                logging.info(f"Configuración de mensajes personalizada cargada")
        except Exception as e:
            logging.error(f"Error al cargar la configuración personalizada: {e}")
            self.custom_messages = {}
    
    def save_custom_config(self):
        """Guarda la configuración personalizada de mensajes"""
        try:
            data_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data")
            os.makedirs(data_dir, exist_ok=True)
            
            config_file = os.path.join(data_dir, "security_messages.json")
            with open(config_file, 'w', encoding='utf-8') as f:
                json.dump(self.custom_messages, f, indent=4, ensure_ascii=False)
            logging.info(f"Configuración de mensajes personalizada guardada")
        except Exception as e:
            logging.error(f"Error al guardar la configuración personalizada: {e}")
    
    def set_custom_message(self, alert_type, os_type, message):
        """Establece un mensaje personalizado para un tipo de alerta y SO específico"""
        if os_type not in self.custom_messages:
            self.custom_messages[os_type] = {}
        
        self.custom_messages[os_type][alert_type] = message
        self.save_custom_config()
        return True
    
    def get_alert_message(self, alert_type, os_type):
        """Obtiene el mensaje para un tipo de alerta y SO específico"""
        # Verificar si existe un mensaje personalizado
        if (os_type in self.custom_messages and 
            alert_type in self.custom_messages[os_type]):
            return self.custom_messages[os_type][alert_type]
        
        # Si no hay mensaje personalizado, usar el predeterminado
        if os_type in ALERT_MESSAGES and alert_type in ALERT_MESSAGES[os_type]:
            return ALERT_MESSAGES[os_type][alert_type]
        
        # Si no existe para el SO específico, usar el genérico
        if DEFAULT_OS in ALERT_MESSAGES and alert_type in ALERT_MESSAGES[DEFAULT_OS]:
            return ALERT_MESSAGES[DEFAULT_OS][alert_type]
        
        # Si todo falla, usar un mensaje genérico
        return f"Alerta de seguridad: {alert_type}"
    
    def block_ip(self, ip):
        """Bloquea una dirección IP usando reglas de firewall mejoradas que incluyen bloqueo de ICMP"""
        if ip in self.blocked_ips:
            logging.warning(f"La IP {ip} ya está bloqueada")
            return False
            
        try:
            # Validar que sea una IP válida
            ipaddress.ip_address(ip)
            
            # Agregar a la lista de bloqueados
            self.blocked_ips.add(ip)
            self.save_blocked_ips()
            
            # Obtener sistema operativo actual
            system = platform.system()
            
            # Aplicar reglas de firewall según el sistema operativo usando la configuración
            if system in BLOCK_ACTIONS:
                success = self._apply_block_rules(ip, system, "create")
                if not success:
                    logging.warning(f"No se pudieron aplicar todas las reglas de bloqueo para {ip}")
            else:
                logging.warning(f"Sistema operativo no soportado para bloqueo de IP: {system}")
                # Intento con reglas genéricas de Windows (más común)
                if "Windows" in BLOCK_ACTIONS:
                    success = self._apply_block_rules(ip, "Windows", "create")
            
            # Detectar el SO probable del origen (para mensajes de alerta)
            os_type = self._detect_os_from_ip(ip) or DEFAULT_OS
            
            # Registrar alerta de bloqueo
            msg = self.get_alert_message("MANUAL-BLOCK", os_type)
            self.add_alert("BLOQUEO", ip, msg, "Alto")
            
            logging.info(f"IP {ip} bloqueada con éxito (incluye bloqueo de pings)")
            return True
            
        except ValueError:
            logging.error(f"Dirección IP inválida: {ip}")
            return False
        except Exception as e:
            logging.error(f"Error al bloquear la IP {ip}: {e}")
            logging.error(traceback.format_exc())
            return False
            
    def _apply_block_rules(self, ip, system, action_type):
        """Aplica las reglas de bloqueo definidas en la configuración"""
        if system not in BLOCK_ACTIONS or action_type not in BLOCK_ACTIONS[system]:
            logging.error(f"No hay reglas de {action_type} definidas para {system}")
            return False
            
        try:
            rules = BLOCK_ACTIONS[system][action_type]
            for rule_template in rules:
                # Reemplazar {ip} en los comandos
                rule = []
                for part in rule_template:
                    rule.append(part.replace("{ip}", ip))
                
                # Ejecutar el comando
                logging.debug(f"Ejecutando comando de firewall: {' '.join(rule)}")
                result = subprocess.run(rule, capture_output=True, check=False)
                
                if result.returncode != 0:
                    logging.warning(f"Error al ejecutar regla de firewall: {' '.join(rule)}")
                    logging.warning(f"Salida de error: {result.stderr.decode('utf-8', errors='ignore')}")
                    # Continuamos con la siguiente regla aunque esta haya fallado
            
            return True
                
        except Exception as e:
            logging.error(f"Error al aplicar reglas de {action_type} para {ip}: {e}")
            logging.error(traceback.format_exc())
            return False
            
    def _detect_os_from_ip(self, ip):
        """Intenta detectar el sistema operativo asociado a una IP basándose en registros previos"""
        # Buscar en alertas previas si tenemos información del SO para esta IP
        for alert in reversed(list(self.alerts)):
            if alert.get('ip') == ip and alert.get('os_type'):
                return alert.get('os_type')
        
        return None
    
    def unblock_ip(self, ip):
        """Desbloquea una dirección IP eliminando todas las reglas de firewall"""
        if ip not in self.blocked_ips:
            logging.warning(f"La IP {ip} no está bloqueada")
            return False
            
        try:
            # Quitar de la lista de bloqueados
            self.blocked_ips.remove(ip)
            self.save_blocked_ips()
            
            # Obtener sistema operativo actual
            system = platform.system()
            
            # Aplicar reglas de desbloqueo según el sistema operativo
            if system in BLOCK_ACTIONS:
                success = self._apply_block_rules(ip, system, "delete")
                if not success:
                    logging.warning(f"No se pudieron eliminar todas las reglas de bloqueo para {ip}")
            else:
                logging.warning(f"Sistema operativo no soportado para desbloqueo de IP: {system}")
                # Intento con reglas genéricas de Windows (más común)
                if "Windows" in BLOCK_ACTIONS:
                    success = self._apply_block_rules(ip, "Windows", "delete")
            
            logging.info(f"IP {ip} desbloqueada con éxito")
            return True
            
        except Exception as e:
            logging.error(f"Error al desbloquear la IP {ip}: {e}")
            logging.error(traceback.format_exc())
            return False
    
    def is_ip_blocked(self, ip):
        """Verifica si una IP está bloqueada"""
        return ip in self.blocked_ips
    
    def register_alert_callback(self, callback):
        """Registra una función callback para ser notificada de alertas"""
        if callback not in self.alert_callbacks:
            self.alert_callbacks.append(callback)
    
    def add_alert(self, tipo, ip, mensaje, nivel_riesgo="Medio", os_type=None):
        """
        Agrega una nueva alerta al sistema
        
        Args:
            tipo (str): Tipo de alerta (PING, PING-FLOOD, etc)
            ip (str): Dirección IP relacionada con la alerta
            mensaje (str): Mensaje descriptivo
            nivel_riesgo (str): Nivel de riesgo (Alto, Medio, Bajo)
            os_type (str, opcional): Sistema operativo detectado
        """
        timestamp = datetime.datetime.now()
        
        # Detectar sistema operativo si no se proporciona
        if not os_type:
            os_type = self._detect_os_from_ip(ip) or DEFAULT_OS
        
        # Crear objeto de alerta
        alerta = {
            'timestamp': timestamp,
            'tipo': tipo,
            'ip': ip,
            'mensaje': mensaje,
            'nivel_riesgo': nivel_riesgo,
            'os_type': os_type
        }
        
        # Agregar a la cola de alertas
        self.alerts.append(alerta)
        
        # Notificar a los callbacks registrados
        for callback in self.alert_callbacks:
            try:
                callback(alerta)
            except Exception as e:
                logging.error(f"Error en callback de alerta: {e}")
        
        # Registrar en el log
        log_msg = f"ALERTA {nivel_riesgo}: {tipo} - IP: {ip} - SO: {os_type} - {mensaje}"
        if nivel_riesgo == "Alto":
            logging.warning(log_msg)
        else:
            logging.info(log_msg)
            
        return alerta
    
    def detect_os_by_ttl(self, ttl):
        """Detecta el sistema operativo probable basado en el valor TTL"""
        for os_name, ttl_range in self.OS_TTL_RANGES.items():
            if ttl in ttl_range:
                return os_name
        
        return "Desconocido"
    
    def analyze_packet(self, packet, packet_info):
        """Analiza un paquete para detectar posibles amenazas"""
        try:
            # Obtener información básica
            src_ip = packet_info.get('source_ip', None)
            dst_ip = packet_info.get('dest_ip', None)
            protocol = packet_info.get('protocol', 'Desconocido')
            ttl = packet_info.get('ttl', 0)
            
            # Ignorar paquetes sin IPs
            if not src_ip or src_ip == 'Desconocido' or not dst_ip or dst_ip == 'Desconocido':
                return
                
            # Verificar si la IP está bloqueada
            if src_ip in self.blocked_ips:
                # Detectar sistema operativo por TTL
                os_type = self.detect_os_by_ttl(ttl)
                msg = self.get_alert_message("BLOCKED-IP", os_type)
                msg = f"{msg} ({protocol})"
                
                self.add_alert("BLOCKED-IP", src_ip, msg, "Alto", os_type)
                return
            
            # Detectar sistema operativo por TTL
            os_type = self.detect_os_by_ttl(ttl)
            
            # Analizar pings (ICMP)
            if protocol == 'ICMP' and packet_info.get('icmp_type') == 8:  # ICMP Echo Request
                self.ping_count[src_ip] += 1
                now = datetime.datetime.now()
                
                # Evitar spam de alertas de la misma IP (máximo 1 cada 30 segundos)
                if (now - self.last_alert_time[src_ip]).total_seconds() > 30:
                    self.last_alert_time[src_ip] = now
                    
                    # Usar mensaje personalizado
                    msg = self.get_alert_message("PING", os_type)
                    msg = f"{msg} (TTL: {ttl})"
                    
                    self.add_alert("PING", src_ip, msg, "Medio", os_type)
                
                # Verificar umbral de ping flood
                window = self.suspicious_patterns['ping_flood']['window']
                threshold = self.suspicious_patterns['ping_flood']['threshold']
                
                if self.ping_count[src_ip] >= threshold:
                    # Ping flood detectado
                    msg = self.get_alert_message("PING-FLOOD", os_type)
                    msg = f"{msg} ({self.ping_count[src_ip]} pings)"
                    
                    self.add_alert("PING-FLOOD", src_ip, msg, "Alto", os_type)
                    
                    # Bloquear automáticamente
                    self.block_ip(src_ip)
            
            # Analizar escaneo de puertos (TCP)
            if protocol == 'TCP':
                dst_port = packet_info.get('dest_port', 0)
                if dst_port > 0:
                    self.port_scan_tracker[src_ip].add(dst_port)
                    
                    # Verificar umbral de escaneo de puertos
                    window = self.suspicious_patterns['port_scan']['window']
                    threshold = self.suspicious_patterns['port_scan']['threshold']
                    
                    if len(self.port_scan_tracker[src_ip]) >= threshold:
                        # Escaneo de puertos detectado
                        msg = self.get_alert_message("PORT-SCAN", os_type)
                        msg = f"{msg} ({len(self.port_scan_tracker[src_ip])} puertos)"
                        
                        self.add_alert("PORT-SCAN", src_ip, msg, "Alto", os_type)
                        
                        # Reset del contador
                        self.port_scan_tracker[src_ip] = set()
            
            # Limpiar contadores periódicamente (cada 1 minuto)
            now = datetime.datetime.now()
            if now.second == 0 and now.microsecond < 100000:
                self.ping_count.clear()
                self.port_scan_tracker.clear()
                
        except Exception as e:
            logging.error(f"Error al analizar paquete para alertas: {e}")
    
    def get_alerts(self, count=10):
        """Obtiene las últimas alertas generadas"""
        return list(self.alerts)[-count:]
    
    def get_blocked_ips(self):
        """Obtiene la lista de IPs bloqueadas"""
        return sorted(list(self.blocked_ips))

# Instancia global del gestor de alertas
alert_manager = AlertManager()
