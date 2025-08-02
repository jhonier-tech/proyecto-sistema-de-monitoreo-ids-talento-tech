#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Configuración de mensajes y acciones para el sistema de seguridad
"""

# Mensajes para diferentes tipos de alertas según el sistema operativo
ALERT_MESSAGES = {
    "Windows": {
        "PING": "Ping detectado desde sistema Windows (posible reconocimiento)",
        "PING-FLOOD": "Ataque de ping flood detectado desde Windows",
        "PORT-SCAN": "Escaneo de puertos detectado desde Windows",
        "BLOCKED-IP": "Intento de conexión bloqueada desde Windows",
        "ARP-SPOOF": "Posible ataque ARP spoofing desde Windows",
        "MANUAL-BLOCK": "IP bloqueada manualmente (Windows)"
    },
    "Linux": {
        "PING": "Ping detectado desde sistema Linux/Unix (posible reconocimiento)",
        "PING-FLOOD": "Ataque de ping flood detectado desde Linux/Unix",
        "PORT-SCAN": "Escaneo de puertos detectado desde Linux/Unix",
        "BLOCKED-IP": "Intento de conexión bloqueada desde Linux/Unix",
        "ARP-SPOOF": "Posible ataque ARP spoofing desde Linux/Unix",
        "MANUAL-BLOCK": "IP bloqueada manualmente (Linux/Unix)"
    },
    "Android": {
        "PING": "Ping detectado desde dispositivo Android (posible reconocimiento)",
        "PING-FLOOD": "Ataque de ping flood detectado desde Android",
        "PORT-SCAN": "Escaneo de puertos detectado desde Android",
        "BLOCKED-IP": "Intento de conexión bloqueada desde Android",
        "ARP-SPOOF": "Posible ataque ARP spoofing desde Android",
        "MANUAL-BLOCK": "IP bloqueada manualmente (Android)"
    },
    "MacOS": {
        "PING": "Ping detectado desde sistema MacOS (posible reconocimiento)",
        "PING-FLOOD": "Ataque de ping flood detectado desde MacOS",
        "PORT-SCAN": "Escaneo de puertos detectado desde MacOS",
        "BLOCKED-IP": "Intento de conexión bloqueada desde MacOS",
        "ARP-SPOOF": "Posible ataque ARP spoofing desde MacOS",
        "MANUAL-BLOCK": "IP bloqueada manualmente (MacOS)"
    },
    "Desconocido": {
        "PING": "Ping detectado desde sistema desconocido (posible reconocimiento)",
        "PING-FLOOD": "Ataque de ping flood detectado desde sistema desconocido",
        "PORT-SCAN": "Escaneo de puertos detectado desde sistema desconocido",
        "BLOCKED-IP": "Intento de conexión bloqueada desde sistema desconocido",
        "ARP-SPOOF": "Posible ataque ARP spoofing desde sistema desconocido",
        "MANUAL-BLOCK": "IP bloqueada manualmente"
    }
}

# Configuración de acciones de bloqueo por sistema operativo
BLOCK_ACTIONS = {
    "Windows": {
        # Reglas avanzadas para el firewall de Windows que incluyen bloqueo de ICMP
        "create": [
            # Bloquear todo el tráfico entrante
            ["netsh", "advfirewall", "firewall", "add", "rule", 
             "name=\"SistemaMonitoreoIDS_Block_{ip}_In\"", 
             "dir=in", "action=block", "remoteip={ip}"],
             
            # Bloquear todo el tráfico saliente
            ["netsh", "advfirewall", "firewall", "add", "rule", 
             "name=\"SistemaMonitoreoIDS_Block_{ip}_Out\"", 
             "dir=out", "action=block", "remoteip={ip}"],
             
            # Bloquear específicamente ICMP (ping)
            ["netsh", "advfirewall", "firewall", "add", "rule", 
             "name=\"SistemaMonitoreoIDS_Block_{ip}_ICMP\"", 
             "dir=in", "action=block", "protocol=icmpv4", "remoteip={ip}"]
        ],
        "delete": [
            # Eliminar reglas de bloqueo entrante
            ["netsh", "advfirewall", "firewall", "delete", "rule", 
             "name=\"SistemaMonitoreoIDS_Block_{ip}_In\""],
             
            # Eliminar reglas de bloqueo saliente
            ["netsh", "advfirewall", "firewall", "delete", "rule", 
             "name=\"SistemaMonitoreoIDS_Block_{ip}_Out\""],
             
            # Eliminar reglas específicas de ICMP
            ["netsh", "advfirewall", "firewall", "delete", "rule", 
             "name=\"SistemaMonitoreoIDS_Block_{ip}_ICMP\""]
        ]
    },
    "Linux": {
        "create": [
            # Bloquear tráfico entrante
            ["iptables", "-A", "INPUT", "-s", "{ip}", "-j", "DROP"],
            
            # Bloquear tráfico saliente
            ["iptables", "-A", "OUTPUT", "-d", "{ip}", "-j", "DROP"],
            
            # Bloquear específicamente ICMP (ping)
            ["iptables", "-A", "INPUT", "-s", "{ip}", "-p", "icmp", "-j", "DROP"],
            ["iptables", "-A", "OUTPUT", "-d", "{ip}", "-p", "icmp", "-j", "DROP"]
        ],
        "delete": [
            # Eliminar reglas de tráfico entrante
            ["iptables", "-D", "INPUT", "-s", "{ip}", "-j", "DROP"],
            
            # Eliminar reglas de tráfico saliente
            ["iptables", "-D", "OUTPUT", "-d", "{ip}", "-j", "DROP"],
            
            # Eliminar reglas específicas de ICMP
            ["iptables", "-D", "INPUT", "-s", "{ip}", "-p", "icmp", "-j", "DROP"],
            ["iptables", "-D", "OUTPUT", "-d", "{ip}", "-p", "icmp", "-j", "DROP"]
        ]
    },
    "MacOS": {
        "create": [
            # Bloquear tráfico con pf (packet filter)
            ["echo", "block in from {ip} to any", ">", "/etc/pf.conf.sistemamonitoreoIDS"],
            ["echo", "block out from any to {ip}", ">>", "/etc/pf.conf.sistemamonitoreoIDS"],
            ["pfctl", "-f", "/etc/pf.conf.sistemamonitoreoIDS", "-e"]
        ],
        "delete": [
            # Eliminar reglas de bloqueo
            ["sed", "-i", "", "/block.*{ip}/d", "/etc/pf.conf.sistemamonitoreoIDS"],
            ["pfctl", "-f", "/etc/pf.conf.sistemamonitoreoIDS", "-e"]
        ]
    }
}

# Configuración por defecto
DEFAULT_OS = "Desconocido"
