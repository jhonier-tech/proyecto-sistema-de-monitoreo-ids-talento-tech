#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Módulo para el diálogo de selección de interfaz de red
"""

import logging
from PyQt5.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout, QTableWidget, 
                           QTableWidgetItem, QPushButton, QLabel, QHeaderView,
                           QAbstractItemView, QMessageBox, QTextBrowser, 
                           QSplitter, QWidget)
from PyQt5.QtGui import QFont, QIcon, QColor
from PyQt5.QtCore import Qt

from capture.packet_capturer import PacketCapturer
from utils.icons import get_icon_path

class InterfaceDialog(QDialog):
    """Diálogo para seleccionar una interfaz de red"""
    
    def __init__(self, parent=None):
        """Inicializa el diálogo de selección de interfaz
        
        Args:
            parent: Widget padre
        """
        super().__init__(parent)
        
        # Configurar ventana
        self.setWindowTitle("Seleccionar Interfaz")
        self.setWindowIcon(QIcon(get_icon_path("interface")))
        self.setMinimumSize(700, 450)
        self.resize(900, 550)
        
        # Variables
        self.interfaces = []
        self.selected_interface = None
        self.selected_interface_desc = ""
        self.selected_interface_full = ""
        
        # Configurar interfaz
        self.setup_ui()
        
        # Cargar interfaces
        self.load_interfaces()
        
    def setup_ui(self):
        """Configura la interfaz de usuario"""
        # Layout principal
        layout = QVBoxLayout(self)
        
        # Etiqueta de instrucciones
        title_label = QLabel("Seleccione la interfaz de red para capturar paquetes:")
        title_label.setFont(QFont("Arial", 11, QFont.Bold))
        layout.addWidget(title_label)
        
        # Divisor principal
        splitter = QSplitter(Qt.Vertical)
        layout.addWidget(splitter, 1)
        
        # Panel superior: Tabla de interfaces
        table_widget = QWidget()
        table_layout = QVBoxLayout(table_widget)
        table_layout.setContentsMargins(0, 0, 0, 0)
        
        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(["Nombre", "Descripción", "Dirección MAC", "Dirección IP"])
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.verticalHeader().setVisible(False)
        self.table.setAlternatingRowColors(True)
        self.table.itemSelectionChanged.connect(self.on_selection_changed)
        table_layout.addWidget(self.table)
        
        splitter.addWidget(table_widget)
        
        # Panel inferior: Detalles de la interfaz seleccionada
        details_widget = QWidget()
        details_layout = QVBoxLayout(details_widget)
        details_layout.setContentsMargins(0, 0, 0, 0)
        
        details_label = QLabel("Detalles de la interfaz seleccionada:")
        details_label.setFont(QFont("Arial", 10, QFont.Bold))
        details_layout.addWidget(details_label)
        
        # Etiqueta para mostrar el nombre completo de la interfaz
        self.interface_name_label = QLabel()
        self.interface_name_label.setFont(QFont("Arial", 9))
        self.interface_name_label.setStyleSheet("background-color: #f0f0f0; padding: 5px; border-radius: 3px;")
        self.interface_name_label.setWordWrap(True)
        self.interface_name_label.setText("Seleccione una interfaz para ver sus detalles")
        details_layout.addWidget(self.interface_name_label)
        
        self.details_text = QTextBrowser()
        self.details_text.setReadOnly(True)
        self.details_text.setMinimumHeight(120)
        self.details_text.setStyleSheet("QTextBrowser { background-color: #f5f5f5; border: 1px solid #ddd; }")
        details_layout.addWidget(self.details_text)
        
        splitter.addWidget(details_widget)
        
        # Establecer proporción inicial
        splitter.setSizes([300, 150])
        
        # Botones
        button_layout = QHBoxLayout()
        
        self.refresh_button = QPushButton("Actualizar")
        self.refresh_button.setIcon(QIcon(get_icon_path("refresh")))
        self.refresh_button.clicked.connect(self.load_interfaces)
        button_layout.addWidget(self.refresh_button)
        
        button_layout.addStretch()
        
        self.cancel_button = QPushButton("Cancelar")
        self.cancel_button.clicked.connect(self.reject)
        button_layout.addWidget(self.cancel_button)
        
        self.accept_button = QPushButton("Aceptar")
        self.accept_button.setIcon(QIcon(get_icon_path("check")))
        self.accept_button.setDefault(True)
        self.accept_button.clicked.connect(self.accept)
        button_layout.addWidget(self.accept_button)
        
        layout.addLayout(button_layout)
        
    def load_interfaces(self):
        """Carga la lista de interfaces de red disponibles"""
        try:
            # Obtener interfaces
            self.interfaces = PacketCapturer.get_interfaces()
            
            # Actualizar tabla
            self.table.setRowCount(len(self.interfaces))
            
            for i, iface in enumerate(self.interfaces):
                # Nombre
                name_item = QTableWidgetItem(iface['name'])
                self.table.setItem(i, 0, name_item)
                
                # Descripción
                desc_item = QTableWidgetItem(iface['description'])
                self.table.setItem(i, 1, desc_item)
                
                # MAC
                mac_item = QTableWidgetItem(iface['mac'])
                self.table.setItem(i, 2, mac_item)
                
                # IP
                ip_item = QTableWidgetItem(iface['ip'])
                
                # Destacar las interfaces con IP local o real
                if iface['ip'] and iface['ip'] != '127.0.0.1':
                    # Interfaces con IP real (no loopback) en amarillo claro
                    if iface['ip'].startswith('192.168.') or iface['ip'].startswith('10.') or iface['ip'].startswith('172.'):
                        ip_item.setBackground(QColor(255, 255, 200))  # Amarillo claro
                        # Añadir tooltip destacando que es una interfaz de red local
                        ip_item.setToolTip("Interfaz de red local (LAN)")
                        # Colorear toda la fila
                        for col in range(4):
                            item = self.table.item(i, col)
                            if item:
                                item.setBackground(QColor(255, 255, 200))
                
                self.table.setItem(i, 3, ip_item)
                
            # Seleccionar primera fila
            if self.table.rowCount() > 0:
                self.table.selectRow(0)
                self.on_selection_changed()
                
        except Exception as e:
            logging.error(f"Error al cargar interfaces: {e}")
            QMessageBox.warning(self, "Error", f"No se pudieron cargar las interfaces: {str(e)}")
            
    def on_selection_changed(self):
        """Actualiza los detalles cuando cambia la selección"""
        selected_rows = self.table.selectionModel().selectedRows()
        if not selected_rows:
            self.details_text.clear()
            self.interface_name_label.setText("Seleccione una interfaz para ver sus detalles")
            return
            
        row = selected_rows[0].row()
        iface = self.interfaces[row]
        
        # Actualizar la etiqueta con el nombre completo de la interfaz
        full_name = f"{iface['name']} - {iface['description']}"
        self.interface_name_label.setText(f"Interfaz seleccionada: {full_name}")
        self.interface_name_label.setStyleSheet("background-color: #e8f5e9; padding: 8px; border-radius: 4px; border: 1px solid #81c784; font-weight: bold;")
        self.selected_interface_full = full_name
        
        # Actualizar área de detalles con información enriquecida
        details_html = f"""
        <style>
            .title {{ color: #2c3e50; font-weight: bold; }}
            .value {{ color: #3498db; }}
            .warning {{ color: #e74c3c; }}
            .highlight {{ background-color: #f1c40f; padding: 2px; }}
        </style>
        
        <h3>Interfaz de red seleccionada:</h3>
        
        <p><span class="title">Nombre técnico:</span> <span class="value">{iface['name']}</span></p>
        <p><span class="title">Descripción:</span> <span class="value">{iface['description']}</span></p>
        <p><span class="title">Dirección MAC:</span> <span class="value">{iface['mac'] or 'No disponible'}</span></p>
        <p><span class="title">Dirección IP:</span> <span class="value">{iface['ip'] or 'No disponible'}</span></p>
        
        <h4>Información adicional:</h4>
        <ul>
        """
        
        # Añadir información según el tipo de interfaz
        if iface['ip'] == '127.0.0.1':
            details_html += '<li><span class="warning">Esta es una interfaz de loopback (localhost)</span></li>'
        elif not iface['ip']:
            details_html += '<li><span class="warning">Esta interfaz no tiene dirección IP asignada</span></li>'
        elif iface['ip'].startswith('192.168.') or iface['ip'].startswith('10.') or iface['ip'].startswith('172.'):
            details_html += f'<li><span class="highlight">Esta es una interfaz de red local (LAN) con IP {iface["ip"]}</span></li>'
            details_html += '<li>Ideal para capturar tráfico de la red local</li>'
        
        if iface['name'].lower().find('wifi') >= 0 or iface['description'].lower().find('wifi') >= 0 or iface['description'].lower().find('wireless') >= 0:
            details_html += '<li>Interfaz de red inalámbrica (WiFi)</li>'
        
        if iface['name'].lower().find('ethernet') >= 0 or iface['description'].lower().find('ethernet') >= 0:
            details_html += '<li>Interfaz de red cableada (Ethernet)</li>'
            
        if iface['name'].lower().find('virtual') >= 0 or iface['description'].lower().find('virtual') >= 0:
            details_html += '<li><span class="warning">Esta parece ser una interfaz virtual</span></li>'
            
        details_html += "</ul>"
        
        self.details_text.setHtml(details_html)
            
    def accept(self):
        """Maneja la aceptación del diálogo"""
        # Obtener interfaz seleccionada
        selected_rows = self.table.selectionModel().selectedRows()
        if not selected_rows:
            QMessageBox.warning(self, "Error", "Por favor, seleccione una interfaz")
            return
            
        row = selected_rows[0].row()
        self.selected_interface = self.interfaces[row]['name']
        self.selected_interface_desc = self.interfaces[row]['description']
        self.selected_interface_full = f"{self.interfaces[row]['name']} - {self.interfaces[row]['description']}"
        
        logging.info(f"Interfaz seleccionada: {self.selected_interface_full}")
        super().accept()
        
    def get_selected_interface(self):
        """Obtiene la interfaz seleccionada
        
        Returns:
            str: Nombre de la interfaz seleccionada
        """
        return self.selected_interface
        
    def get_selected_interface_description(self):
        """Obtiene la descripción de la interfaz seleccionada
        
        Returns:
            str: Descripción de la interfaz seleccionada
        """
        return self.selected_interface_desc
        
    def get_selected_interface_full(self):
        """Obtiene el nombre completo de la interfaz seleccionada
        
        Returns:
            str: Nombre completo de la interfaz (nombre + descripción)
        """
        return self.selected_interface_full
