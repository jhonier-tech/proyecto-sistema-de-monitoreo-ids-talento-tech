#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Módulo para visualización gráfica de paquetes
"""

import logging
import numpy as np
import matplotlib
import matplotlib.pyplot as plt
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure
from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, QComboBox, 
                           QPushButton, QFrame, QSizePolicy)
from PyQt5.QtCore import Qt

class PacketGraphView(QWidget):
    """Widget para visualizar gráficamente los paquetes seleccionados"""
    
    def __init__(self, parent=None):
        """Inicializa el widget de visualización gráfica
        
        Args:
            parent: Widget padre
        """
        super().__init__(parent)
        
        # Configurar el widget
        self.setup_ui()
        
        # Paquete actual
        self.current_packet = None
        self.packet_info = None
        
    def setup_ui(self):
        """Configura la interfaz de usuario"""
        # Layout principal
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)
        
        # Panel de control
        control_frame = QFrame()
        control_frame.setFrameShape(QFrame.StyledPanel)
        control_layout = QHBoxLayout(control_frame)
        
        # Tipo de gráfico
        self.graph_type_label = QLabel("Tipo de gráfico:")
        self.graph_type_combo = QComboBox()
        self.graph_type_combo.addItems([
            "Estructura por capas",
            "Estructura por bytes",
            "Distribución del tamaño",
            "Hexadecimal"
        ])
        self.graph_type_combo.currentIndexChanged.connect(self.update_graph)
        
        # Botón de actualizar
        self.update_btn = QPushButton("Actualizar")
        self.update_btn.clicked.connect(self.update_graph)
        
        # Añadir widgets al layout de control
        control_layout.addWidget(self.graph_type_label)
        control_layout.addWidget(self.graph_type_combo)
        control_layout.addStretch()
        control_layout.addWidget(self.update_btn)
        
        # Área del gráfico
        self.figure = Figure(figsize=(5, 4), dpi=100)
        self.canvas = FigureCanvas(self.figure)
        self.canvas.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        
        # Añadir widgets al layout principal
        main_layout.addWidget(control_frame)
        main_layout.addWidget(self.canvas)
        
    def set_packet(self, packet, packet_info):
        """Establece el paquete actual para visualización
        
        Args:
            packet: Objeto de paquete de Scapy
            packet_info: Información detallada del paquete
        """
        try:
            logging.debug(f"Estableciendo paquete para visualización gráfica: {packet.summary() if packet else None}")
            self.current_packet = packet
            self.packet_info = packet_info
            self.update_graph()
        except Exception as e:
            import traceback
            logging.error(f"Error al establecer paquete para visualización gráfica: {e}")
            logging.error(traceback.format_exc())
        
    def update_graph(self):
        """Actualiza el gráfico según el tipo seleccionado"""
        if not self.current_packet:
            return
            
        # Limpiar figura actual
        self.figure.clear()
        
        # Obtener tipo de gráfico seleccionado
        graph_type = self.graph_type_combo.currentText()
        
        if graph_type == "Estructura por capas":
            self.plot_layer_structure()
        elif graph_type == "Estructura por bytes":
            self.plot_byte_structure()
        elif graph_type == "Distribución del tamaño":
            self.plot_size_distribution()
        elif graph_type == "Hexadecimal":
            self.plot_hex_view()
            
        # Actualizar canvas
        self.canvas.draw()
        
    def plot_layer_structure(self):
        """Genera un gráfico de la estructura por capas del paquete"""
        try:
            # Crear axes
            ax = self.figure.add_subplot(111)
            
            # Obtener capas del paquete
            layers = []
            sizes = []
            colors = []
            
            # Extraer capas y tamaños
            layer = self.current_packet
            while layer:
                layer_name = layer.name
                layer_size = len(layer)
                
                layers.append(layer_name)
                sizes.append(layer_size)
                
                # Asignar color según capa
                if layer_name == 'Ethernet':
                    colors.append('#4CAF50')  # Verde
                elif layer_name == 'IP' or layer_name == 'IPv6':
                    colors.append('#2196F3')  # Azul
                elif layer_name == 'TCP':
                    colors.append('#FFC107')  # Amarillo
                elif layer_name == 'UDP':
                    colors.append('#9C27B0')  # Púrpura
                elif layer_name == 'ICMP':
                    colors.append('#F44336')  # Rojo
                elif layer_name == 'Raw':
                    colors.append('#607D8B')  # Gris
                else:
                    colors.append('#FF9800')  # Naranja
                
                # Obtener siguiente capa
                if hasattr(layer, 'payload') and layer.payload:
                    layer = layer.payload
                else:
                    break
                    
            # Crear gráfico de pastel
            wedges, texts, autotexts = ax.pie(
                sizes, 
                labels=layers,
                colors=colors,
                autopct='%1.1f%%',
                startangle=90,
                wedgeprops={'edgecolor': 'w'}
            )
            
            # Personalizar textos
            for text in texts:
                text.set_fontsize(9)
            for autotext in autotexts:
                autotext.set_fontsize(8)
                autotext.set_color('white')
                
            ax.set_title('Estructura por capas del paquete')
            ax.axis('equal')  # Asegurar que el gráfico sea circular
            
        except Exception as e:
            logging.error(f"Error al generar gráfico de capas: {e}")
            ax = self.figure.add_subplot(111)
            ax.text(0.5, 0.5, f"Error al generar gráfico: {e}", 
                   ha='center', va='center', color='red')
            
    def plot_byte_structure(self):
        """Genera un gráfico de la estructura por bytes del paquete"""
        try:
            # Crear axes
            ax = self.figure.add_subplot(111)
            
            # Convertir paquete a bytes
            packet_bytes = bytes(self.current_packet)
            packet_len = len(packet_bytes)
            
            # Crear histograma de bytes
            bins = min(256, packet_len)  # Hasta 256 bins, uno por cada valor posible de byte
            n, bins, patches = ax.hist(
                np.frombuffer(packet_bytes, dtype=np.uint8), 
                bins=bins, 
                range=(0, 255),
                color='#2196F3',
                alpha=0.7
            )
            
            # Añadir líneas para bytes comunes en red
            common_bytes = {
                0x00: 'NULL',
                0x0A: 'LF',
                0x0D: 'CR',
                0x20: 'SPACE',
                0x45: 'IP',
                0xFF: 'FF'
            }
            
            for byte, name in common_bytes.items():
                if byte in packet_bytes:
                    ax.axvline(x=byte, color='red', linestyle='--', alpha=0.5)
                    ax.text(byte, max(n)*0.9, name, rotation=90, alpha=0.7)
            
            ax.set_title(f'Distribución de bytes en el paquete ({packet_len} bytes)')
            ax.set_xlabel('Valor del byte (0-255)')
            ax.set_ylabel('Frecuencia')
            
        except Exception as e:
            logging.error(f"Error al generar gráfico de bytes: {e}")
            ax = self.figure.add_subplot(111)
            ax.text(0.5, 0.5, f"Error al generar gráfico: {e}", 
                   ha='center', va='center', color='red')
            
    def plot_size_distribution(self):
        """Genera un gráfico de la distribución del tamaño del paquete"""
        try:
            # Crear axes
            ax = self.figure.add_subplot(111)
            
            # Información sobre tamaños
            packet_len = len(self.current_packet)
            
            # Obtener capas y tamaños
            layers = []
            sizes = []
            
            # Extraer capas y tamaños
            layer = self.current_packet
            while layer:
                layer_name = layer.name
                layer_size = len(layer)
                
                layers.append(layer_name)
                sizes.append(layer_size)
                
                # Obtener siguiente capa
                if hasattr(layer, 'payload') and layer.payload:
                    layer = layer.payload
                else:
                    break
            
            # Crear gráfico de barras horizontal
            y_pos = np.arange(len(layers))
            ax.barh(y_pos, sizes, align='center', color='#2196F3', alpha=0.7)
            ax.set_yticks(y_pos)
            ax.set_yticklabels(layers)
            
            # Añadir valores
            for i, v in enumerate(sizes):
                ax.text(v + 0.1, i, str(v), color='black', va='center')
            
            ax.set_title(f'Tamaño de las capas del paquete (Total: {packet_len} bytes)')
            ax.set_xlabel('Tamaño (bytes)')
            
            # Invertir para que la capa superior esté arriba
            ax.invert_yaxis()
            
        except Exception as e:
            logging.error(f"Error al generar gráfico de tamaño: {e}")
            ax = self.figure.add_subplot(111)
            ax.text(0.5, 0.5, f"Error al generar gráfico: {e}", 
                   ha='center', va='center', color='red')
            
    def plot_hex_view(self):
        """Genera una visualización hexadecimal del paquete"""
        try:
            # Crear axes sin ejes
            ax = self.figure.add_subplot(111)
            ax.axis('off')
            
            # Convertir paquete a bytes
            packet_bytes = bytes(self.current_packet)
            packet_len = len(packet_bytes)
            
            # Crear representación hexadecimal formateada
            hex_text = ""
            ascii_text = ""
            offset = 0
            
            # Procesar 16 bytes por línea
            for i in range(0, packet_len, 16):
                # Obtener fragmento de bytes actual
                chunk = packet_bytes[i:i+16]
                chunk_len = len(chunk)
                
                # Añadir offset
                hex_line = f"{i:04x}:  "
                
                # Convertir a hex
                for j in range(16):
                    if j < chunk_len:
                        hex_line += f"{chunk[j]:02x} "
                        # Convertir a ASCII (solo caracteres imprimibles)
                        if 32 <= chunk[j] <= 126:
                            ascii_text += chr(chunk[j])
                        else:
                            ascii_text += "."
                    else:
                        hex_line += "   "
                        ascii_text += " "
                    
                    # Espacio adicional cada 8 bytes
                    if j == 7:
                        hex_line += " "
                
                # Añadir ASCII al final de la línea
                hex_line += f"  |{ascii_text}|"
                hex_text += hex_line + "\n"
                ascii_text = ""
                
            # Mostrar texto hexadecimal
            ax.text(0.01, 0.99, hex_text, family='monospace', fontsize=9,
                   verticalalignment='top', horizontalalignment='left')
            
            ax.set_title('Vista hexadecimal del paquete')
            
        except Exception as e:
            logging.error(f"Error al generar vista hexadecimal: {e}")
            ax = self.figure.add_subplot(111)
            ax.text(0.5, 0.5, f"Error al generar gráfico: {e}", 
                   ha='center', va='center', color='red')
