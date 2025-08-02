#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Módulo para la vista hexadecimal de paquetes
"""

import logging
from PyQt5.QtWidgets import QTextEdit, QApplication
from PyQt5.QtGui import QFont, QTextCharFormat, QColor, QTextCursor
from PyQt5.QtCore import Qt

class PacketHexView(QTextEdit):
    """Widget para mostrar la vista hexadecimal de un paquete"""
    
    def __init__(self, parent=None):
        """Inicializa la vista hexadecimal de paquetes
        
        Args:
            parent: Widget padre
        """
        super().__init__(parent)
        
        # Configuración de la vista
        self.setup_ui()
        
        # Paquete actual
        self.current_packet = None
        
    def setup_ui(self):
        """Configura la interfaz de usuario"""
        # Configurar vista de texto
        self.setReadOnly(True)
        self.setLineWrapMode(QTextEdit.NoWrap)
        
        # Usar fuente monoespaciada
        font = QFont("Consolas", 10)
        self.setFont(font)
        
        # Establecer colores de fondo y texto
        self.setStyleSheet("""
            QTextEdit {
                background-color: white;
                color: black;
            }
        """)
        
    def display_packet(self, packet):
        """Muestra la representación hexadecimal de un paquete
        
        Args:
            packet: Objeto de paquete de Scapy a mostrar
        """
        # Guardar paquete actual
        self.current_packet = packet
        
        if not packet:
            self.clear()
            return
            
        try:
            # Convertir paquete a bytes
            packet_bytes = bytes(packet)
            
            # Generar vista hexadecimal
            self.generate_hex_dump(packet_bytes)
            
        except Exception as e:
            logging.error(f"Error al mostrar vista hexadecimal: {e}")
            self.setPlainText(f"Error al procesar paquete: {str(e)}")
            
    def generate_hex_dump(self, data):
        """Genera y muestra un volcado hexadecimal de los datos
        
        Args:
            data: Datos binarios a mostrar
        """
        # Limpiar contenido actual
        self.clear()
        
        # Crear formatos para las diferentes secciones
        offset_format = QTextCharFormat()
        offset_format.setForeground(QColor(100, 100, 100))
        
        hex_format = QTextCharFormat()
        hex_format.setForeground(QColor(0, 0, 150))
        
        ascii_format = QTextCharFormat()
        ascii_format.setForeground(QColor(0, 100, 0))
        
        # Obtener cursor para inserción de texto
        cursor = self.textCursor()
        
        # Procesar datos en bloques de 16 bytes
        for offset in range(0, len(data), 16):
            # Bloque actual
            block = data[offset:offset+16]
            
            # Formatear offset
            cursor.insertText(f"{offset:08x}  ", offset_format)
            
            # Formatear parte hexadecimal
            hex_values = []
            for i, byte in enumerate(block):
                # Añadir espacio adicional cada 8 bytes
                if i == 8:
                    hex_values.append(" ")
                    
                hex_values.append(f"{byte:02x}")
                
            # Rellenar espacios si el bloque no está completo
            if len(block) < 16:
                # Añadir espacios para alinear la parte ASCII
                padding = "   " * (16 - len(block))
                # Ajustar si estamos a la mitad
                if len(block) < 8:
                    padding = padding[1:]  # Quitar un espacio por el espacio extra
                    
                hex_text = " ".join(hex_values) + padding
            else:
                hex_text = " ".join(hex_values)
                
            cursor.insertText(hex_text + "  ", hex_format)
            
            # Formatear parte ASCII
            ascii_values = []
            for byte in block:
                # Mostrar solo caracteres imprimibles
                if 32 <= byte <= 126:
                    ascii_values.append(chr(byte))
                else:
                    ascii_values.append(".")
                    
            cursor.insertText("".join(ascii_values), ascii_format)
            
            # Nueva línea
            cursor.insertText("\n")
            
        # Mover cursor al inicio
        cursor.movePosition(QTextCursor.Start)
        self.setTextCursor(cursor)
        
    def clear(self):
        """Limpia la vista hexadecimal"""
        super().clear()
        self.current_packet = None
