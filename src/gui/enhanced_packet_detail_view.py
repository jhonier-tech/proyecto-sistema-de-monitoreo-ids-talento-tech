#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Módulo para la vista detallada mejorada de paquetes
"""

import logging
from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, QGridLayout,
                           QFrame, QScrollArea, QSplitter, QTabWidget, QTreeWidget,
                           QTreeWidgetItem, QHeaderView, QTableWidget, QTableWidgetItem)
from PyQt5.QtGui import QFont, QColor, QBrush, QPalette
from PyQt5.QtCore import Qt, pyqtSignal

from gui.packet_graph_view import PacketGraphView
from gui.packet_detail_view import PacketDetailView
from gui.packet_hex_view import PacketHexView
from analyzer.packet_analyzer import PacketAnalyzer

class PacketInfoPanel(QFrame):
    """Panel para mostrar información resumida del paquete"""
    
    def __init__(self, parent=None):
        """Inicializa el panel de información del paquete
        
        Args:
            parent: Widget padre
        """
        super().__init__(parent)
        
        # Establecer estilo
        self.setFrameShape(QFrame.StyledPanel)
        self.setFrameShadow(QFrame.Raised)
        
        # Configurar el layout
        self.setup_ui()
        
    def setup_ui(self):
        """Configura la interfaz de usuario"""
        # Layout principal
        layout = QGridLayout(self)
        layout.setVerticalSpacing(10)
        layout.setHorizontalSpacing(15)
        
        # Fuentes
        label_font = QFont("Segoe UI", 9, QFont.Bold)
        value_font = QFont("Segoe UI", 9)
        
        # Primera columna: Información básica
        row = 0
        
        # Fila 1: Sistema y MAC
        self.add_info_field(layout, row, 0, "Sistema origen:", "sistema_origen", label_font, value_font)
        self.add_info_field(layout, row, 2, "Sistema destino:", "sistema_destino", label_font, value_font)
        row += 1
        
        # Fila 2: MAC
        self.add_info_field(layout, row, 0, "MAC origen:", "mac_origen", label_font, value_font)
        self.add_info_field(layout, row, 2, "MAC destino:", "mac_destino", label_font, value_font)
        row += 1
        
        # Fila 3: IP
        self.add_info_field(layout, row, 0, "IP origen:", "ip_origen", label_font, value_font)
        self.add_info_field(layout, row, 2, "IP destino:", "ip_destino", label_font, value_font)
        row += 1
        
        # Fila 4: Puerto
        self.add_info_field(layout, row, 0, "Puerto origen:", "puerto_origen", label_font, value_font)
        self.add_info_field(layout, row, 2, "Puerto destino:", "puerto_destino", label_font, value_font)
        row += 1
        
        # Fila 5: Protocolo y tipo
        self.add_info_field(layout, row, 0, "Protocolo:", "protocolo", label_font, value_font)
        self.add_info_field(layout, row, 2, "Tipo:", "tipo", label_font, value_font)
        row += 1
        
        # Fila 6: Tamaño y tiempo
        self.add_info_field(layout, row, 0, "Tamaño:", "tamano", label_font, value_font)
        self.add_info_field(layout, row, 2, "Timestamp:", "timestamp", label_font, value_font)
        row += 1
        
        # Fila 7: Nivel de riesgo
        label = QLabel("Nivel de riesgo:")
        label.setFont(label_font)
        layout.addWidget(label, row, 0, 1, 1)
        
        self.riesgo_valor = QLabel("Desconocido")
        self.riesgo_valor.setFont(value_font)
        layout.addWidget(self.riesgo_valor, row, 1, 1, 3)
        
        # Expandir último espacio
        layout.setColumnStretch(3, 1)
        
    def add_info_field(self, layout, row, col, label_text, object_name, label_font, value_font):
        """Añade un campo de información al layout
        
        Args:
            layout: Layout donde añadir el campo
            row: Fila en el grid
            col: Columna en el grid
            label_text: Texto de la etiqueta
            object_name: Nombre del objeto para el valor
            label_font: Fuente para la etiqueta
            value_font: Fuente para el valor
        """
        label = QLabel(label_text)
        label.setFont(label_font)
        layout.addWidget(label, row, col, 1, 1)
        
        value = QLabel("---")
        value.setFont(value_font)
        value.setObjectName(object_name)
        layout.addWidget(value, row, col + 1, 1, 1)
        
    def update_info(self, packet_info):
        """Actualiza la información mostrada con los datos del paquete
        
        Args:
            packet_info: Diccionario con información detallada del paquete
        """
        try:
            # Verificar que tenemos un diccionario válido
            if not isinstance(packet_info, dict):
                logging.error(f"packet_info no es un diccionario: {type(packet_info)}")
                return
                
            # Actualizar valores
            self.findChild(QLabel, "sistema_origen").setText(packet_info.get('source_hostname', '---'))
            self.findChild(QLabel, "sistema_destino").setText(packet_info.get('dest_hostname', '---'))
            self.findChild(QLabel, "mac_origen").setText(packet_info.get('source_mac', '---'))
            self.findChild(QLabel, "mac_destino").setText(packet_info.get('dest_mac', '---'))
            self.findChild(QLabel, "ip_origen").setText(packet_info.get('source_ip', '---'))
            self.findChild(QLabel, "ip_destino").setText(packet_info.get('dest_ip', '---'))
            
            # Puertos (pueden ser None)
            puerto_origen = packet_info.get('source_port')
            if puerto_origen is not None:
                self.findChild(QLabel, "puerto_origen").setText(str(puerto_origen))
            else:
                self.findChild(QLabel, "puerto_origen").setText('---')
                
            puerto_destino = packet_info.get('dest_port')
            if puerto_destino is not None:
                self.findChild(QLabel, "puerto_destino").setText(str(puerto_destino))
            else:
                self.findChild(QLabel, "puerto_destino").setText('---')
            
            # Protocolo y tipo
            self.findChild(QLabel, "protocolo").setText(packet_info.get('protocol', 'Desconocido'))
            self.findChild(QLabel, "tipo").setText(packet_info.get('detailed_protocol', '---'))
            
            # Tamaño y timestamp
            self.findChild(QLabel, "tamano").setText(f"{packet_info.get('length', 0)} bytes")
            self.findChild(QLabel, "timestamp").setText(packet_info.get('timestamp', '---'))
            
            # Nivel de riesgo con color
            nivel_riesgo = packet_info.get('risk_level', 'Desconocido')
            self.riesgo_valor.setText(nivel_riesgo)
            
            # Colorear según nivel de riesgo
            if nivel_riesgo == 'Alto':
                self.riesgo_valor.setStyleSheet("color: red; font-weight: bold;")
            elif nivel_riesgo == 'Medio':
                self.riesgo_valor.setStyleSheet("color: orange; font-weight: bold;")
            elif nivel_riesgo == 'Bajo':
                self.riesgo_valor.setStyleSheet("color: green; font-weight: bold;")
            else:
                self.riesgo_valor.setStyleSheet("")
                
        except Exception as e:
            import traceback
            logging.error(f"Error al actualizar panel de información: {e}")
            logging.error(traceback.format_exc())

class EnhancedPacketDetailView(QWidget):
    """Vista detallada mejorada para paquetes de red"""
    
    def __init__(self, parent=None):
        """Inicializa la vista detallada mejorada
        
        Args:
            parent: Widget padre
        """
        super().__init__(parent)
        
        # Configurar el widget
        self.setup_ui()
        
    def setup_ui(self):
        """Configura la interfaz de usuario"""
        # Layout principal
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)
        
        # Panel de información
        self.info_panel = PacketInfoPanel()
        main_layout.addWidget(self.info_panel)
        
        # Crear splitter para las vistas de detalles y gráfico
        self.splitter = QSplitter(Qt.Horizontal)
        
        # Pestañas para la vista de detalles
        self.tabs = QTabWidget()
        
        # Vista clásica de detalles (árbol)
        self.detail_view = PacketDetailView()
        self.tabs.addTab(self.detail_view, "Estructura")
        
        # Vista hexadecimal
        self.hex_view = PacketHexView()
        self.tabs.addTab(self.hex_view, "Hexadecimal")
        
        # Añadir pestañas al splitter
        self.splitter.addWidget(self.tabs)
        
        # Vista de gráfico
        self.graph_view = PacketGraphView()
        self.splitter.addWidget(self.graph_view)
        
        # Configurar proporciones iniciales
        self.splitter.setSizes([int(self.width() * 0.6), int(self.width() * 0.4)])
        
        # Añadir splitter al layout principal
        main_layout.addWidget(self.splitter)
        
    def display_packet(self, packet):
        """Muestra los detalles de un paquete
        
        Args:
            packet: Objeto de paquete de Scapy a mostrar
        """
        if not packet:
            # Limpiar la vista cuando no hay paquete
            self.info_panel.update_info({
                'source_hostname': '---',
                'dest_hostname': '---',
                'source_mac': '---',
                'dest_mac': '---',
                'source_ip': '---',
                'dest_ip': '---',
                'source_port': None,
                'dest_port': None,
                'protocol': 'Desconocido',
                'detailed_protocol': '---',
                'length': 0,
                'timestamp': '---',
                'risk_level': 'Desconocido'
            })
            self.detail_view.clear()
            self.hex_view.clear()
            return
            
        try:
            # Importar aquí para evitar problemas de importación circular
            from analyzer.packet_analyzer import PacketAnalyzer
            
            # Obtener información detallada del paquete
            packet_info = PacketAnalyzer.get_detailed_info(packet)
            
            # Registro de depuración para verificar si se obtiene la información correctamente
            logging.debug(f"Información detallada obtenida: {packet_info}")
            
            # Actualizar panel de información
            self.info_panel.update_info(packet_info)
            
            # Actualizar vista de detalles tradicional
            self.detail_view.display_packet(packet)
            
            # Actualizar vista hexadecimal
            self.hex_view.display_packet(packet)
            
            # Actualizar vista de gráfico
            self.graph_view.set_packet(packet, packet_info)
            
        except Exception as e:
            import traceback
            logging.error(f"Error al mostrar detalles del paquete: {e}")
            logging.error(traceback.format_exc())
