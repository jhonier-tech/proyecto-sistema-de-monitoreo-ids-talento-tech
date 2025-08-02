#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Script de prueba para la visualización mejorada de paquetes
Este script crea un entorno simplificado para probar la funcionalidad de visualización
"""

import os
import sys
import logging
from PyQt5.QtWidgets import QApplication, QMainWindow, QVBoxLayout, QWidget, QPushButton
from scapy.all import IP, ICMP, Ether, TCP, UDP, DNS, Raw

# Configurar logging
logging.basicConfig(level=logging.INFO)

try:
    # Intentar importar los módulos necesarios
    sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from src.gui.enhanced_packet_detail_view import EnhancedPacketDetailView
    from src.analyzer.packet_analyzer import PacketAnalyzer
except ImportError as e:
    print(f"Error de importación: {e}")
    print("Por favor, ejecuta primero 'solucionar_visualizacion_paquetes.py'")
    sys.exit(1)

class TestWindow(QMainWindow):
    """Ventana de prueba para la visualización de paquetes"""
    
    def __init__(self):
        super().__init__()
        
        self.setWindowTitle("Prueba de Visualización de Paquetes")
        self.setMinimumSize(1000, 800)
        
        # Widget central
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)
        
        # Crear vista detallada mejorada
        self.detail_view = EnhancedPacketDetailView()
        layout.addWidget(self.detail_view)
        
        # Botones de prueba
        self.create_test_buttons(layout)
        
        # Crear paquetes de ejemplo
        self.create_test_packets()
        
    def create_test_buttons(self, layout):
        """Crea botones para probar diferentes tipos de paquetes"""
        
        # ICMP Request
        icmp_req_btn = QPushButton("Probar paquete ICMP Request")
        icmp_req_btn.clicked.connect(lambda: self.test_packet("icmp_request"))
        layout.addWidget(icmp_req_btn)
        
        # TCP
        tcp_btn = QPushButton("Probar paquete TCP")
        tcp_btn.clicked.connect(lambda: self.test_packet("tcp"))
        layout.addWidget(tcp_btn)
        
        # UDP
        udp_btn = QPushButton("Probar paquete UDP")
        udp_btn.clicked.connect(lambda: self.test_packet("udp"))
        layout.addWidget(udp_btn)
        
        # DNS
        dns_btn = QPushButton("Probar paquete DNS")
        dns_btn.clicked.connect(lambda: self.test_packet("dns"))
        layout.addWidget(dns_btn)
    
    def create_test_packets(self):
        """Crea paquetes de ejemplo para probar"""
        # Paquete ICMP Request
        self.icmp_request = Ether(src="00:11:22:33:44:55", dst="66:77:88:99:AA:BB")/IP(src="192.168.1.100", dst="8.8.8.8")/ICMP(type=8, code=0)
        
        # Paquete TCP
        self.tcp = Ether(src="00:11:22:33:44:55", dst="66:77:88:99:AA:BB")/IP(src="192.168.1.100", dst="93.184.216.34")/TCP(sport=52000, dport=443, flags="S")
        
        # Paquete UDP
        self.udp = Ether(src="00:11:22:33:44:55", dst="66:77:88:99:AA:BB")/IP(src="192.168.1.100", dst="8.8.8.8")/UDP(sport=53124, dport=53)
        
        # Paquete DNS
        dns_query = DNS(rd=1, qd=DNSQR(qname="www.example.com"))
        self.dns = Ether(src="00:11:22:33:44:55", dst="66:77:88:99:AA:BB")/IP(src="192.168.1.100", dst="8.8.8.8")/UDP(sport=53124, dport=53)/dns_query
    
    def test_packet(self, packet_type):
        """Prueba la visualización con un tipo de paquete específico"""
        try:
            if packet_type == "icmp_request":
                self.detail_view.display_packet(self.icmp_request)
                self.setWindowTitle("Prueba - Paquete ICMP Request")
            elif packet_type == "tcp":
                self.detail_view.display_packet(self.tcp)
                self.setWindowTitle("Prueba - Paquete TCP")
            elif packet_type == "udp":
                self.detail_view.display_packet(self.udp)
                self.setWindowTitle("Prueba - Paquete UDP")
            elif packet_type == "dns":
                self.detail_view.display_packet(self.dns)
                self.setWindowTitle("Prueba - Paquete DNS")
        except Exception as e:
            logging.error(f"Error al mostrar paquete {packet_type}: {e}")
            import traceback
            logging.error(traceback.format_exc())

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = TestWindow()
    window.show()
    sys.exit(app.exec_())
