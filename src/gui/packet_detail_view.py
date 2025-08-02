#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Módulo para la vista de detalles de paquetes
"""

import logging
from PyQt5.QtWidgets import QTreeWidget, QTreeWidgetItem, QHeaderView
from PyQt5.QtGui import QFont, QBrush, QColor
from PyQt5.QtCore import Qt

class PacketDetailView(QTreeWidget):
    """Widget para mostrar los detalles de un paquete"""
    
    def __init__(self, parent=None):
        """Inicializa la vista de detalles de paquetes
        
        Args:
            parent: Widget padre
        """
        super().__init__(parent)
        
        # Configuración de la vista
        self.setup_ui()
        
    def setup_ui(self):
        """Configura la interfaz de usuario"""
        # Configurar la vista de árbol
        self.setAlternatingRowColors(True)
        self.setAnimated(True)
        self.setExpandsOnDoubleClick(True)
        
        # Configurar encabezados
        self.setColumnCount(2)
        self.setHeaderLabels(["Campo", "Valor"])
        
        # Ajustar anchos de columna
        header = self.header()
        header.setStretchLastSection(True)
        header.setSectionResizeMode(0, QHeaderView.Interactive)
        self.setColumnWidth(0, 250)
        
        # Fuente monoespaciada para los valores
        self.value_font = QFont("Consolas", 9)
        
    def display_packet(self, packet):
        """Muestra los detalles de un paquete
        
        Args:
            packet: Objeto de paquete de Scapy a mostrar
        """
        # Limpiar vista
        self.clear()
        
        if not packet:
            return
            
        try:
            # Añadir estructura del paquete
            self.add_packet_structure(packet)
            
            # Expandir primer nivel
            self.expandToDepth(0)
            
        except Exception as e:
            logging.error(f"Error al mostrar detalles del paquete: {e}")
            
    def add_packet_structure(self, packet):
        """Añade la estructura del paquete a la vista de árbol
        
        Args:
            packet: Objeto de paquete de Scapy
        """
        # Obtener todas las capas del paquete
        counter = 0
        layer = packet
        
        while layer:
            layer_name = layer.name
            
            # Crear elemento para esta capa
            layer_item = QTreeWidgetItem(self)
            layer_item.setText(0, f"Capa {counter}: {layer_name}")
            layer_item.setFont(1, self.value_font)
            
            # Colorear según el tipo de capa
            self.set_layer_color(layer_item, layer_name)
            
            # Añadir campos de esta capa
            self.add_layer_fields(layer_item, layer)
            
            # Ir a la siguiente capa
            counter += 1
            
            # Obtener la siguiente capa
            if layer.payload and layer.payload.name != 'Raw':
                layer = layer.payload
            else:
                # Si hay datos Raw, añadirlos
                if layer.payload and layer.payload.name == 'Raw':
                    raw_item = QTreeWidgetItem(self)
                    raw_item.setText(0, f"Capa {counter}: Datos (Raw)")
                    raw_item.setFont(1, self.value_font)
                    
                    # Colorear los datos
                    raw_item.setBackground(0, QBrush(QColor(240, 240, 240)))
                    
                    # Añadir datos
                    raw_data = layer.payload.load
                    
                    # Intentar mostrar como texto si es posible
                    try:
                        text_data = raw_data.decode('utf-8', 'ignore')
                        if all(32 <= ord(c) <= 126 or c in '\r\n\t' for c in text_data):
                            # Es texto legible
                            data_item = QTreeWidgetItem(raw_item)
                            data_item.setText(0, "Datos (texto)")
                            data_item.setText(1, text_data if len(text_data) < 1000 else f"{text_data[:1000]}... (truncado)")
                            data_item.setFont(1, self.value_font)
                    except:
                        pass
                        
                    # Mostrar siempre los datos en hexadecimal
                    hex_item = QTreeWidgetItem(raw_item)
                    hex_item.setText(0, "Datos (hex)")
                    
                    # Formatear los bytes en grupos de 16
                    hex_data = raw_data.hex()
                    formatted_hex = ""
                    for i in range(0, len(hex_data), 32):
                        chunk = hex_data[i:i+32]
                        formatted_chunk = ' '.join(chunk[j:j+2] for j in range(0, len(chunk), 2))
                        formatted_hex += formatted_chunk + '\n'
                    
                    hex_item.setText(1, formatted_hex if len(formatted_hex) < 1000 else f"{formatted_hex[:1000]}... (truncado)")
                    hex_item.setFont(1, self.value_font)
                
                break
                
    def add_layer_fields(self, parent_item, layer):
        """Añade los campos de una capa a un elemento padre
        
        Args:
            parent_item: Elemento padre donde añadir los campos
            layer: Capa de paquete de Scapy
        """
        # Recorrer campos de la capa
        for field_name in layer.fields_desc:
            field_value = layer.getfieldval(field_name.name)
            
            # Crear elemento para este campo
            field_item = QTreeWidgetItem(parent_item)
            field_item.setText(0, field_name.name)
            field_item.setFont(1, self.value_font)
            
            # Formatear el valor según el tipo
            if isinstance(field_value, int):
                if field_name.name in ['type', 'proto']:
                    # Mostrar como hexadecimal
                    field_item.setText(1, f"0x{field_value:04x} ({field_value})")
                elif field_name.name in ['dport', 'sport']:
                    # Añadir nombre del servicio conocido si es posible
                    service_name = self.get_service_name(field_value)
                    if service_name:
                        field_item.setText(1, f"{field_value} ({service_name})")
                    else:
                        field_item.setText(1, str(field_value))
                else:
                    field_item.setText(1, str(field_value))
            elif isinstance(field_value, bytes):
                # Formatear bytes como hexadecimal
                hex_value = field_value.hex()
                formatted_value = ':'.join(hex_value[i:i+2] for i in range(0, len(hex_value), 2))
                field_item.setText(1, formatted_value)
            elif isinstance(field_value, list):
                # Formatear listas
                field_item.setText(1, str(field_value))
                
                # Añadir elementos de la lista como subelementos
                for i, item_value in enumerate(field_value):
                    list_item = QTreeWidgetItem(field_item)
                    list_item.setText(0, f"[{i}]")
                    list_item.setText(1, str(item_value))
                    list_item.setFont(1, self.value_font)
            else:
                # Valores normales
                field_item.setText(1, str(field_value))
                
    def set_layer_color(self, item, layer_name):
        """Aplica un color al elemento según el tipo de capa
        
        Args:
            item: QTreeWidgetItem a colorear
            layer_name: Nombre de la capa
        """
        color = QColor(255, 255, 255)  # Blanco por defecto
        
        # Asignar colores según capa
        if layer_name == 'Ethernet':
            color = QColor(240, 240, 255)  # Azul muy claro
        elif layer_name == 'IP':
            color = QColor(240, 240, 255)  # Azul muy claro
        elif layer_name == 'TCP':
            color = QColor(231, 230, 255)  # Azul claro
        elif layer_name == 'UDP':
            color = QColor(231, 255, 230)  # Verde claro
        elif layer_name == 'ICMP':
            color = QColor(255, 230, 230)  # Rojo claro
        elif layer_name == 'DNS':
            color = QColor(255, 255, 200)  # Amarillo claro
        elif layer_name == 'Raw':
            color = QColor(240, 240, 240)  # Gris claro
        
        # Aplicar el color
        item.setBackground(0, QBrush(color))
        item.setBackground(1, QBrush(color))
        
    def get_service_name(self, port):
        """Obtiene el nombre del servicio asociado a un puerto
        
        Args:
            port: Número de puerto
            
        Returns:
            str: Nombre del servicio o None si no es conocido
        """
        # Algunos puertos comunes
        common_ports = {
            20: "FTP-data",
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            67: "DHCP-Server",
            68: "DHCP-Client",
            69: "TFTP",
            80: "HTTP",
            110: "POP3",
            123: "NTP",
            143: "IMAP",
            161: "SNMP",
            162: "SNMP-trap",
            443: "HTTPS",
            445: "SMB",
            993: "IMAPS",
            995: "POP3S",
            3306: "MySQL",
            3389: "RDP",
            5900: "VNC",
            8080: "HTTP-Alt"
        }
        
        return common_ports.get(port)
        
    def clear(self):
        """Limpia la vista de detalles"""
        super().clear()
