#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Módulo para la ventana de estadísticas
"""

import logging
import numpy as np
from collections import Counter, defaultdict
from PyQt5.QtWidgets import (QMainWindow, QVBoxLayout, QHBoxLayout, QWidget, 
                           QTabWidget, QTableWidget, QTableWidgetItem,
                           QHeaderView, QPushButton, QSplitter, QLabel,
                           QComboBox)
from PyQt5.QtGui import QIcon, QFont, QColor, QBrush
from PyQt5.QtCore import Qt, QSize

from utils.icons import get_icon_path
import pyqtgraph as pg

class StatisticsWindow(QMainWindow):
    """Ventana para mostrar estadísticas de los paquetes capturados"""
    
    def __init__(self, packets=None):
        """Inicializa la ventana de estadísticas
        
        Args:
            packets: Lista de paquetes para analizar
        """
        super().__init__()
        
        # Configuración de la ventana
        self.setWindowTitle("Estadísticas de red")
        self.setWindowIcon(QIcon(get_icon_path("statistics")))
        self.resize(800, 600)
        
        # Paquetes
        self.packets = packets or []
        
        # Configurar interfaz
        self.setup_ui()
        
        # Analizar paquetes
        self.update_statistics(self.packets)
        
    def setup_ui(self):
        """Configura la interfaz de usuario"""
        # Widget central
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # Layout principal
        main_layout = QVBoxLayout(central_widget)
        
        # Control de tiempo
        time_layout = QHBoxLayout()
        
        time_label = QLabel("Período de tiempo:")
        time_layout.addWidget(time_label)
        
        self.time_combo = QComboBox()
        self.time_combo.addItems(["Todo", "Últimos 10 segundos", "Últimos 30 segundos", 
                                "Último minuto", "Últimos 5 minutos"])
        self.time_combo.currentIndexChanged.connect(self.on_time_changed)
        time_layout.addWidget(self.time_combo)
        
        time_layout.addStretch()
        
        self.refresh_button = QPushButton("Actualizar")
        self.refresh_button.clicked.connect(lambda: self.update_statistics(self.packets))
        time_layout.addWidget(self.refresh_button)
        
        main_layout.addLayout(time_layout)
        
        # Pestañas
        self.tab_widget = QTabWidget()
        main_layout.addWidget(self.tab_widget)
        
        # Pestaña de protocolos
        protocol_tab = QWidget()
        protocol_layout = QVBoxLayout(protocol_tab)
        
        # Tabla de protocolos
        self.protocol_table = QTableWidget()
        self.protocol_table.setColumnCount(3)
        self.protocol_table.setHorizontalHeaderLabels(["Protocolo", "Paquetes", "Porcentaje"])
        self.protocol_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.protocol_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.protocol_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.protocol_table.setAlternatingRowColors(True)
        protocol_layout.addWidget(self.protocol_table)
        
        # Gráfico de protocolos
        self.protocol_plot = pg.PlotWidget()
        self.protocol_plot.setBackground('w')
        self.protocol_plot.setTitle("Distribución de protocolos")
        self.protocol_plot.setLabel('left', "Paquetes")
        self.protocol_plot.setLabel('bottom', "Protocolo")
        protocol_layout.addWidget(self.protocol_plot)
        
        self.tab_widget.addTab(protocol_tab, "Protocolos")
        
        # Pestaña de direcciones
        address_tab = QWidget()
        address_layout = QHBoxLayout(address_tab)
        
        # Splitter para tablas de origen y destino
        address_splitter = QSplitter(Qt.Horizontal)
        
        # Tabla de direcciones de origen
        src_widget = QWidget()
        src_layout = QVBoxLayout(src_widget)
        src_layout.setContentsMargins(0, 0, 0, 0)
        
        src_label = QLabel("Direcciones de origen")
        src_label.setAlignment(Qt.AlignCenter)
        src_layout.addWidget(src_label)
        
        self.src_table = QTableWidget()
        self.src_table.setColumnCount(3)
        self.src_table.setHorizontalHeaderLabels(["Dirección IP", "Paquetes", "Porcentaje"])
        self.src_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.src_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.src_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.src_table.setAlternatingRowColors(True)
        src_layout.addWidget(self.src_table)
        
        address_splitter.addWidget(src_widget)
        
        # Tabla de direcciones de destino
        dst_widget = QWidget()
        dst_layout = QVBoxLayout(dst_widget)
        dst_layout.setContentsMargins(0, 0, 0, 0)
        
        dst_label = QLabel("Direcciones de destino")
        dst_label.setAlignment(Qt.AlignCenter)
        dst_layout.addWidget(dst_label)
        
        self.dst_table = QTableWidget()
        self.dst_table.setColumnCount(3)
        self.dst_table.setHorizontalHeaderLabels(["Dirección IP", "Paquetes", "Porcentaje"])
        self.dst_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.dst_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.dst_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.dst_table.setAlternatingRowColors(True)
        dst_layout.addWidget(self.dst_table)
        
        address_splitter.addWidget(dst_widget)
        
        address_layout.addWidget(address_splitter)
        
        self.tab_widget.addTab(address_tab, "Direcciones")
        
        # Pestaña de puertos
        port_tab = QWidget()
        port_layout = QHBoxLayout(port_tab)
        
        # Splitter para tablas de puertos TCP y UDP
        port_splitter = QSplitter(Qt.Horizontal)
        
        # Tabla de puertos TCP
        tcp_widget = QWidget()
        tcp_layout = QVBoxLayout(tcp_widget)
        tcp_layout.setContentsMargins(0, 0, 0, 0)
        
        tcp_label = QLabel("Puertos TCP")
        tcp_label.setAlignment(Qt.AlignCenter)
        tcp_layout.addWidget(tcp_label)
        
        self.tcp_table = QTableWidget()
        self.tcp_table.setColumnCount(3)
        self.tcp_table.setHorizontalHeaderLabels(["Puerto", "Paquetes", "Porcentaje"])
        self.tcp_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.tcp_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.tcp_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.tcp_table.setAlternatingRowColors(True)
        tcp_layout.addWidget(self.tcp_table)
        
        port_splitter.addWidget(tcp_widget)
        
        # Tabla de puertos UDP
        udp_widget = QWidget()
        udp_layout = QVBoxLayout(udp_widget)
        udp_layout.setContentsMargins(0, 0, 0, 0)
        
        udp_label = QLabel("Puertos UDP")
        udp_label.setAlignment(Qt.AlignCenter)
        udp_layout.addWidget(udp_label)
        
        self.udp_table = QTableWidget()
        self.udp_table.setColumnCount(3)
        self.udp_table.setHorizontalHeaderLabels(["Puerto", "Paquetes", "Porcentaje"])
        self.udp_table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.udp_table.setSelectionBehavior(QTableWidget.SelectRows)
        self.udp_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.udp_table.setAlternatingRowColors(True)
        udp_layout.addWidget(self.udp_table)
        
        port_splitter.addWidget(udp_widget)
        
        port_layout.addWidget(port_splitter)
        
        self.tab_widget.addTab(port_tab, "Puertos")
        
        # Pestaña de tamaño de paquetes
        size_tab = QWidget()
        size_layout = QVBoxLayout(size_tab)
        
        # Gráfico de distribución de tamaños
        self.size_plot = pg.PlotWidget()
        self.size_plot.setBackground('w')
        self.size_plot.setTitle("Distribución de tamaños de paquete")
        self.size_plot.setLabel('left', "Paquetes")
        self.size_plot.setLabel('bottom', "Tamaño (bytes)")
        size_layout.addWidget(self.size_plot)
        
        # Estadísticas de tamaño
        size_stats_layout = QHBoxLayout()
        
        self.min_size_label = QLabel("Mínimo: 0 bytes")
        size_stats_layout.addWidget(self.min_size_label)
        
        self.avg_size_label = QLabel("Promedio: 0 bytes")
        size_stats_layout.addWidget(self.avg_size_label)
        
        self.max_size_label = QLabel("Máximo: 0 bytes")
        size_stats_layout.addWidget(self.max_size_label)
        
        size_layout.addLayout(size_stats_layout)
        
        self.tab_widget.addTab(size_tab, "Tamaños")
        
        # Pestaña de actividad temporal
        time_tab = QWidget()
        time_layout = QVBoxLayout(time_tab)
        
        # Gráfico de actividad temporal
        self.time_plot = pg.PlotWidget()
        self.time_plot.setBackground('w')
        self.time_plot.setTitle("Actividad temporal")
        self.time_plot.setLabel('left', "Paquetes/s")
        self.time_plot.setLabel('bottom', "Tiempo (s)")
        time_layout.addWidget(self.time_plot)
        
        self.tab_widget.addTab(time_tab, "Actividad temporal")
        
    def update_statistics(self, packets):
        """Actualiza las estadísticas con los paquetes dados
        
        Args:
            packets: Lista de paquetes para analizar
        """
        if not packets:
            logging.warning("No hay paquetes para analizar")
            return
            
        self.packets = packets
        logging.info(f"Actualizando estadísticas con {len(packets)} paquetes")
        
        try:
            # Aplicar filtro de tiempo si es necesario
            filtered_packets = self.filter_packets_by_time()
            
            # Analizar protocolos
            self.analyze_protocols(filtered_packets)
            
            # Analizar direcciones
            self.analyze_addresses(filtered_packets)
            
            # Analizar puertos
            self.analyze_ports(filtered_packets)
            
            # Analizar tamaños
            self.analyze_sizes(filtered_packets)
            
            # Analizar actividad temporal
            self.analyze_time_activity(filtered_packets)
            
        except Exception as e:
            logging.error(f"Error al actualizar estadísticas: {e}")
            
    def filter_packets_by_time(self):
        """Filtra los paquetes según el período de tiempo seleccionado
        
        Returns:
            list: Paquetes filtrados
        """
        import time
        
        current_time = time.time()
        time_filter = self.time_combo.currentText()
        
        if time_filter == "Todo":
            return self.packets
        
        # Determinar el límite de tiempo
        if time_filter == "Últimos 10 segundos":
            time_limit = current_time - 10
        elif time_filter == "Últimos 30 segundos":
            time_limit = current_time - 30
        elif time_filter == "Último minuto":
            time_limit = current_time - 60
        elif time_filter == "Últimos 5 minutos":
            time_limit = current_time - 300
        else:
            return self.packets
            
        # Filtrar paquetes
        return [p for p in self.packets if hasattr(p, 'time') and p.time >= time_limit]
        
    def on_time_changed(self):
        """Maneja el cambio en el período de tiempo"""
        self.update_statistics(self.packets)
        
    def analyze_protocols(self, packets):
        """Analiza la distribución de protocolos
        
        Args:
            packets: Lista de paquetes para analizar
        """
        # Contador de protocolos
        protocol_counter = Counter()
        
        for packet in packets:
            # Detectar el protocolo más específico
            protocol = "Desconocido"
            
            try:
                if packet.haslayer('TCP'):
                    # Detectar protocolos de aplicación
                    tcp_layer = packet.getlayer('TCP')
                    if tcp_layer.dport == 80 or tcp_layer.sport == 80:
                        # Verificar si es HTTP
                        if packet.haslayer('Raw') and b'HTTP/' in packet.getlayer('Raw').load:
                            protocol = "HTTP"
                        else:
                            protocol = "TCP"
                    elif tcp_layer.dport == 443 or tcp_layer.sport == 443:
                        protocol = "HTTPS"
                    else:
                        protocol = "TCP"
                elif packet.haslayer('UDP'):
                    udp_layer = packet.getlayer('UDP')
                    if packet.haslayer('DNS'):
                        protocol = "DNS"
                    else:
                        protocol = "UDP"
                elif packet.haslayer('ICMP'):
                    protocol = "ICMP"
                elif packet.haslayer('ARP'):
                    protocol = "ARP"
                elif packet.haslayer('IP'):
                    protocol = "IP"
                elif packet.haslayer('Ether'):
                    protocol = "Ethernet"
            except:
                pass
                
            protocol_counter[protocol] += 1
            
        # Actualizar tabla
        self.protocol_table.setRowCount(len(protocol_counter))
        
        total_packets = len(packets)
        for i, (protocol, count) in enumerate(protocol_counter.most_common()):
            # Protocolo
            protocol_item = QTableWidgetItem(protocol)
            self.protocol_table.setItem(i, 0, protocol_item)
            
            # Cantidad
            count_item = QTableWidgetItem(str(count))
            count_item.setTextAlignment(Qt.AlignRight | Qt.AlignVCenter)
            self.protocol_table.setItem(i, 1, count_item)
            
            # Porcentaje
            percentage = (count / total_packets) * 100 if total_packets > 0 else 0
            percentage_item = QTableWidgetItem(f"{percentage:.2f}%")
            percentage_item.setTextAlignment(Qt.AlignRight | Qt.AlignVCenter)
            self.protocol_table.setItem(i, 2, percentage_item)
            
        # Actualizar gráfico
        self.protocol_plot.clear()
        
        # Preparar datos para el gráfico
        protocols = []
        counts = []
        colors = []
        
        # Paleta de colores
        color_map = {
            "HTTP": (0, 0, 255, 150),
            "HTTPS": (0, 128, 255, 150),
            "TCP": (0, 0, 200, 150),
            "DNS": (255, 255, 0, 150),
            "UDP": (0, 200, 0, 150),
            "ICMP": (255, 0, 0, 150),
            "ARP": (200, 200, 200, 150),
            "IP": (150, 150, 150, 150),
            "Ethernet": (100, 100, 100, 150)
        }
        
        for protocol, count in protocol_counter.most_common(10):
            protocols.append(protocol)
            counts.append(count)
            colors.append(color_map.get(protocol, (150, 150, 150, 150)))
            
        # Crear gráfico de barras
        x = range(len(protocols))
        bar_graph = pg.BarGraphItem(x=x, height=counts, width=0.6, brushes=[pg.mkBrush(c) for c in colors])
        self.protocol_plot.addItem(bar_graph)
        
        # Configurar eje X
        ax = self.protocol_plot.getAxis('bottom')
        ax.setTicks([[(i, p) for i, p in enumerate(protocols)]])
        
    def analyze_addresses(self, packets):
        """Analiza la distribución de direcciones IP
        
        Args:
            packets: Lista de paquetes para analizar
        """
        # Contadores de direcciones
        src_counter = Counter()
        dst_counter = Counter()
        
        for packet in packets:
            try:
                if packet.haslayer('IP'):
                    ip_layer = packet.getlayer('IP')
                    src_counter[ip_layer.src] += 1
                    dst_counter[ip_layer.dst] += 1
            except:
                pass
                
        # Actualizar tabla de origen
        self.src_table.setRowCount(len(src_counter))
        
        total_packets = len(packets)
        for i, (addr, count) in enumerate(src_counter.most_common()):
            # Dirección
            addr_item = QTableWidgetItem(addr)
            self.src_table.setItem(i, 0, addr_item)
            
            # Cantidad
            count_item = QTableWidgetItem(str(count))
            count_item.setTextAlignment(Qt.AlignRight | Qt.AlignVCenter)
            self.src_table.setItem(i, 1, count_item)
            
            # Porcentaje
            percentage = (count / total_packets) * 100 if total_packets > 0 else 0
            percentage_item = QTableWidgetItem(f"{percentage:.2f}%")
            percentage_item.setTextAlignment(Qt.AlignRight | Qt.AlignVCenter)
            self.src_table.setItem(i, 2, percentage_item)
            
        # Actualizar tabla de destino
        self.dst_table.setRowCount(len(dst_counter))
        
        for i, (addr, count) in enumerate(dst_counter.most_common()):
            # Dirección
            addr_item = QTableWidgetItem(addr)
            self.dst_table.setItem(i, 0, addr_item)
            
            # Cantidad
            count_item = QTableWidgetItem(str(count))
            count_item.setTextAlignment(Qt.AlignRight | Qt.AlignVCenter)
            self.dst_table.setItem(i, 1, count_item)
            
            # Porcentaje
            percentage = (count / total_packets) * 100 if total_packets > 0 else 0
            percentage_item = QTableWidgetItem(f"{percentage:.2f}%")
            percentage_item.setTextAlignment(Qt.AlignRight | Qt.AlignVCenter)
            self.dst_table.setItem(i, 2, percentage_item)
            
    def analyze_ports(self, packets):
        """Analiza la distribución de puertos
        
        Args:
            packets: Lista de paquetes para analizar
        """
        # Contadores de puertos
        tcp_ports = Counter()
        udp_ports = Counter()
        
        for packet in packets:
            try:
                if packet.haslayer('TCP'):
                    tcp_layer = packet.getlayer('TCP')
                    tcp_ports[tcp_layer.sport] += 1
                    tcp_ports[tcp_layer.dport] += 1
                elif packet.haslayer('UDP'):
                    udp_layer = packet.getlayer('UDP')
                    udp_ports[udp_layer.sport] += 1
                    udp_ports[udp_layer.dport] += 1
            except:
                pass
                
        # Actualizar tabla de puertos TCP
        self.tcp_table.setRowCount(len(tcp_ports))
        
        total_tcp = sum(tcp_ports.values())
        for i, (port, count) in enumerate(tcp_ports.most_common()):
            # Puerto
            port_item = QTableWidgetItem(str(port))
            self.tcp_table.setItem(i, 0, port_item)
            
            # Cantidad
            count_item = QTableWidgetItem(str(count))
            count_item.setTextAlignment(Qt.AlignRight | Qt.AlignVCenter)
            self.tcp_table.setItem(i, 1, count_item)
            
            # Porcentaje
            percentage = (count / total_tcp) * 100 if total_tcp > 0 else 0
            percentage_item = QTableWidgetItem(f"{percentage:.2f}%")
            percentage_item.setTextAlignment(Qt.AlignRight | Qt.AlignVCenter)
            self.tcp_table.setItem(i, 2, percentage_item)
            
        # Actualizar tabla de puertos UDP
        self.udp_table.setRowCount(len(udp_ports))
        
        total_udp = sum(udp_ports.values())
        for i, (port, count) in enumerate(udp_ports.most_common()):
            # Puerto
            port_item = QTableWidgetItem(str(port))
            self.udp_table.setItem(i, 0, port_item)
            
            # Cantidad
            count_item = QTableWidgetItem(str(count))
            count_item.setTextAlignment(Qt.AlignRight | Qt.AlignVCenter)
            self.udp_table.setItem(i, 1, count_item)
            
            # Porcentaje
            percentage = (count / total_udp) * 100 if total_udp > 0 else 0
            percentage_item = QTableWidgetItem(f"{percentage:.2f}%")
            percentage_item.setTextAlignment(Qt.AlignRight | Qt.AlignVCenter)
            self.udp_table.setItem(i, 2, percentage_item)
            
    def analyze_sizes(self, packets):
        """Analiza la distribución de tamaños de paquetes
        
        Args:
            packets: Lista de paquetes para analizar
        """
        # Recopilar tamaños
        sizes = [len(packet) for packet in packets]
        
        if not sizes:
            return
            
        # Calcular estadísticas
        min_size = min(sizes)
        max_size = max(sizes)
        avg_size = sum(sizes) / len(sizes)
        
        # Actualizar etiquetas
        self.min_size_label.setText(f"Mínimo: {min_size} bytes")
        self.avg_size_label.setText(f"Promedio: {avg_size:.2f} bytes")
        self.max_size_label.setText(f"Máximo: {max_size} bytes")
        
        # Actualizar gráfico
        self.size_plot.clear()
        
        # Crear histograma
        y, x = np.histogram(sizes, bins=20)
        
        # Crear gráfico de barras
        bar_graph = pg.BarGraphItem(x=x[:-1], height=y, width=(x[1]-x[0])*0.8, brush=(0, 0, 255, 150))
        self.size_plot.addItem(bar_graph)
        
    def analyze_time_activity(self, packets):
        """Analiza la actividad temporal
        
        Args:
            packets: Lista de paquetes para analizar
        """
        if not packets:
            return
            
        # Recopilar tiempos
        timestamps = [packet.time for packet in packets if hasattr(packet, 'time')]
        
        if not timestamps:
            return
            
        # Ordenar por tiempo
        timestamps.sort()
        
        # Calcular tiempo inicial y final
        start_time = min(timestamps)
        end_time = max(timestamps)
        
        # Duración total en segundos
        duration = end_time - start_time
        
        if duration <= 0:
            return
            
        # Dividir en intervalos
        num_intervals = min(int(duration), 100)  # Máximo 100 intervalos
        interval_size = duration / num_intervals if num_intervals > 0 else 1
        
        # Contar paquetes por intervalo
        intervals = defaultdict(int)
        
        for ts in timestamps:
            interval_idx = int((ts - start_time) / interval_size)
            intervals[interval_idx] += 1
            
        # Preparar datos para el gráfico
        x = []
        y = []
        
        for i in range(num_intervals):
            x.append(start_time + i * interval_size)
            y.append(intervals[i] / interval_size)  # Paquetes por segundo
            
        # Actualizar gráfico
        self.time_plot.clear()
        
        # Crear gráfico de línea
        self.time_plot.plot(x=[t - start_time for t in x], y=y, pen=(0, 0, 255))
        
# Importar numpy al principio para asegurar que esté disponible
import numpy as np
