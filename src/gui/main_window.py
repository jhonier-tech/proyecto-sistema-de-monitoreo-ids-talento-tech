#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Módulo para la ventana principal de la aplicación Sistema de monitoreo IDS
"""

import os
import sys
import logging
import datetime
from PyQt5.QtWidgets import (QMainWindow, QTabWidget, QAction, QMenu, 
                            QToolBar, QStatusBar, QMessageBox, QFileDialog,
                            QVBoxLayout, QWidget, QSplitter, QApplication, QDialog)
from PyQt5.QtGui import QIcon, QKeySequence, QColor
from PyQt5.QtCore import Qt, QSize, pyqtSlot, QSettings, QTimer

from gui.packet_list_view import PacketListView
from gui.packet_detail_view import PacketDetailView
from gui.packet_hex_view import PacketHexView
from gui.enhanced_packet_detail_view import EnhancedPacketDetailView
from gui.interface_dialog import InterfaceDialog
from gui.filter_bar import FilterBar
from gui.statistics_window import StatisticsWindow
from gui.preferences_dialog import PreferencesDialog
from gui.about_dialog import AboutDialog
from gui.alerts_manager_view import AlertsManagerView
from capture.packet_capturer import PacketCapturer
from utils.theme_manager import ThemeManager
from utils.icons import get_icon_path
from security.alert_manager import alert_manager

class MainWindow(QMainWindow):
    """Ventana principal de la aplicación Sistema de monitoreo IDS"""
    
    def __init__(self):
        super().__init__()
        
        # Configuración inicial
        self.settings = QSettings("Sistema de monitoreo IDS", "Sistema de monitoreo IDS")
        self.theme_manager = ThemeManager()
        self.packet_capturer = None
        self.is_capturing = False
        self.capture_count = 0
        self.current_interface = None
        
        # Configurar la interfaz
        self.setup_ui()
        
        # Cargar configuración guardada
        self.load_settings()
        
        # Configurar temporizador para actualizar estadísticas
        self.stats_timer = QTimer()
        self.stats_timer.setInterval(1000)  # Actualizar cada segundo
        self.stats_timer.timeout.connect(self.update_statistics)
        
        # Mostrar mensaje de bienvenida
        self.statusBar().showMessage("Bienvenido al Sistema de monitoreo IDS. Seleccione una interfaz para comenzar la captura.", 5000)
        
    def setup_ui(self):
        """Configura la interfaz de usuario principal"""
        # Configurar ventana
        self.setWindowTitle("Sistema de monitoreo IDS - Analizador de Red")
        self.setWindowIcon(QIcon(get_icon_path("app_icon")))
        self.resize(1200, 800)
        self.setMinimumSize(800, 600)
        
        # Crear widget central
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)
        
        # Barra de filtros
        self.filter_bar = FilterBar()
        self.filter_bar.filterApplied.connect(self.apply_filter)
        main_layout.addWidget(self.filter_bar)
        
        # Crear pestañas principales
        self.tab_widget = QTabWidget()
        main_layout.addWidget(self.tab_widget)
        
        # Pestaña de captura (principal)
        capture_tab = QWidget()
        capture_layout = QVBoxLayout(capture_tab)
        capture_layout.setContentsMargins(0, 0, 0, 0)
        
        # Crear splitter principal para la pestaña de captura
        main_splitter = QSplitter(Qt.Vertical)
        capture_layout.addWidget(main_splitter)
        
        # Vista de lista de paquetes
        self.packet_list_view = PacketListView()
        self.packet_list_view.packetSelected.connect(self.on_packet_selected)
        main_splitter.addWidget(self.packet_list_view)
        
        # Vista detallada mejorada (reemplaza el splitter inferior)
        self.enhanced_detail_view = EnhancedPacketDetailView()
        main_splitter.addWidget(self.enhanced_detail_view)
        
        # Mantener vistas tradicionales para compatibilidad
        self.packet_detail_view = self.enhanced_detail_view.detail_view
        self.packet_hex_view = self.enhanced_detail_view.hex_view
        
        # Configurar tamaños relativos
        main_splitter.setSizes([500, 500])
        
        # Pestaña de seguridad
        self.security_tab = AlertsManagerView()
        
        # Agregar pestañas
        self.tab_widget.addTab(capture_tab, "Captura")
        self.tab_widget.addTab(self.security_tab, "Seguridad")
        
        # Crear barra de estado
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        
        # Crear barra de herramientas
        self.create_toolbar()
        
        # Crear menús
        self.create_menus()
        
        # Aplicar tema
        self.apply_theme()
        
    def create_toolbar(self):
        """Crea la barra de herramientas principal"""
        # Barra de herramientas principal
        self.toolbar = QToolBar("Barra de Herramientas Principal")
        self.toolbar.setMovable(False)
        self.toolbar.setIconSize(QSize(24, 24))
        self.toolbar.setToolButtonStyle(Qt.ToolButtonTextUnderIcon)
        self.addToolBar(self.toolbar)
        
        # Acción: Iniciar/Detener captura
        self.action_start_capture = QAction(QIcon(get_icon_path("start")), "Iniciar", self)
        self.action_start_capture.setShortcut(QKeySequence("Ctrl+I"))
        self.action_start_capture.triggered.connect(self.toggle_capture)
        self.toolbar.addAction(self.action_start_capture)
        
        # Acción: Seleccionar interfaz
        self.action_select_interface = QAction(QIcon(get_icon_path("interface")), "Interfaces", self)
        self.action_select_interface.triggered.connect(self.show_interface_dialog)
        self.toolbar.addAction(self.action_select_interface)
        
        self.toolbar.addSeparator()
        
        # Acción: Limpiar captura
        self.action_clear = QAction(QIcon(get_icon_path("clear")), "Limpiar", self)
        self.action_clear.triggered.connect(self.clear_capture)
        self.toolbar.addAction(self.action_clear)
        
        # Acción: Guardar captura
        self.action_save = QAction(QIcon(get_icon_path("save")), "Guardar", self)
        self.action_save.setShortcut(QKeySequence.Save)
        self.action_save.triggered.connect(self.save_capture)
        self.toolbar.addAction(self.action_save)
        
        self.toolbar.addSeparator()
        
        # Acción: Estadísticas
        self.action_statistics = QAction(QIcon(get_icon_path("statistics")), "Estadísticas", self)
        self.action_statistics.triggered.connect(self.show_statistics)
        self.toolbar.addAction(self.action_statistics)
        
        # Acción: Seguridad
        self.action_security = QAction(QIcon(get_icon_path("shield")), "Seguridad", self)
        self.action_security.triggered.connect(lambda: self.tab_widget.setCurrentWidget(self.security_tab))
        self.toolbar.addAction(self.action_security)
        
    def create_menus(self):
        """Crea los menús de la aplicación"""
        # Menú Archivo
        file_menu = self.menuBar().addMenu("&Archivo")
        
        action_open = QAction("&Abrir captura...", self)
        action_open.setShortcut(QKeySequence.Open)
        action_open.triggered.connect(self.open_capture_file)
        file_menu.addAction(action_open)
        
        file_menu.addAction(self.action_save)
        
        action_save_as = QAction("Guardar &como...", self)
        action_save_as.setShortcut(QKeySequence("Ctrl+Shift+S"))
        action_save_as.triggered.connect(self.save_capture_as)
        file_menu.addAction(action_save_as)
        
        file_menu.addSeparator()
        
        action_export = QAction("&Exportar paquetes...", self)
        action_export.triggered.connect(self.export_packets)
        file_menu.addAction(action_export)
        
        file_menu.addSeparator()
        
        action_exit = QAction("&Salir", self)
        action_exit.setShortcut(QKeySequence.Quit)
        action_exit.triggered.connect(self.close)
        file_menu.addAction(action_exit)
        
        # Menú Captura
        capture_menu = self.menuBar().addMenu("&Captura")
        
        capture_menu.addAction(self.action_start_capture)
        capture_menu.addAction(self.action_select_interface)
        
        capture_menu.addSeparator()
        
        action_options = QAction("&Opciones de captura...", self)
        action_options.triggered.connect(self.show_capture_options)
        capture_menu.addAction(action_options)
        
        capture_menu.addAction(self.action_clear)
        
        # Menú Ver
        view_menu = self.menuBar().addMenu("&Ver")
        
        action_zoom_in = QAction("&Aumentar zoom", self)
        action_zoom_in.setShortcut(QKeySequence.ZoomIn)
        action_zoom_in.triggered.connect(self.zoom_in)
        view_menu.addAction(action_zoom_in)
        
        action_zoom_out = QAction("&Disminuir zoom", self)
        action_zoom_out.setShortcut(QKeySequence.ZoomOut)
        action_zoom_out.triggered.connect(self.zoom_out)
        view_menu.addAction(action_zoom_out)
        
        action_reset_zoom = QAction("&Restablecer zoom", self)
        action_reset_zoom.setShortcut(QKeySequence("Ctrl+0"))
        action_reset_zoom.triggered.connect(self.reset_zoom)
        view_menu.addAction(action_reset_zoom)
        
        view_menu.addSeparator()
        
        # Submenú de temas
        theme_menu = QMenu("&Temas", self)
        
        action_light_theme = QAction("Tema &claro", self)
        action_light_theme.triggered.connect(lambda: self.set_theme("light"))
        theme_menu.addAction(action_light_theme)
        
        action_dark_theme = QAction("Tema &oscuro", self)
        action_dark_theme.triggered.connect(lambda: self.set_theme("dark"))
        theme_menu.addAction(action_dark_theme)
        
        action_system_theme = QAction("Tema del &sistema", self)
        action_system_theme.triggered.connect(lambda: self.set_theme("system"))
        theme_menu.addAction(action_system_theme)
        
        view_menu.addMenu(theme_menu)
        
        view_menu.addSeparator()
        
        action_preferences = QAction("&Preferencias...", self)
        action_preferences.setShortcut(QKeySequence("Ctrl+P"))
        action_preferences.triggered.connect(self.show_preferences)
        view_menu.addAction(action_preferences)
        
        # Menú Análisis
        analysis_menu = self.menuBar().addMenu("&Análisis")
        
        action_filter = QAction("&Filtros avanzados...", self)
        action_filter.setShortcut(QKeySequence("Ctrl+F"))
        action_filter.triggered.connect(self.show_filter_dialog)
        analysis_menu.addAction(action_filter)
        
        analysis_menu.addAction(self.action_statistics)
        
        action_protocols = QAction("&Jerarquía de protocolos", self)
        action_protocols.triggered.connect(self.show_protocol_hierarchy)
        analysis_menu.addAction(action_protocols)
        
        action_flow_graph = QAction("Gráfico de &flujo", self)
        action_flow_graph.triggered.connect(self.show_flow_graph)
        analysis_menu.addAction(action_flow_graph)
        
        # Menú Seguridad
        security_menu = self.menuBar().addMenu("Se&guridad")
        
        action_show_alerts = QAction("&Mostrar alertas", self)
        action_show_alerts.setIcon(QIcon(get_icon_path("shield")))
        action_show_alerts.triggered.connect(lambda: self.tab_widget.setCurrentWidget(self.security_tab))
        security_menu.addAction(action_show_alerts)
        
        action_block_ip = QAction("&Bloquear IP...", self)
        action_block_ip.triggered.connect(self.show_block_ip_dialog)
        security_menu.addAction(action_block_ip)
        
        # Menú Ayuda
        help_menu = self.menuBar().addMenu("A&yuda")
        
        action_help = QAction("&Ayuda del Sistema de monitoreo IDS", self)
        action_help.setShortcut(QKeySequence.HelpContents)
        action_help.triggered.connect(self.show_help)
        help_menu.addAction(action_help)
        
        action_about = QAction("&Acerca del Sistema de monitoreo IDS", self)
        action_about.triggered.connect(self.show_about)
        help_menu.addAction(action_about)
        
    def apply_theme(self):
        """Aplica el tema actual a la interfaz"""
        theme = self.settings.value("theme", "system")
        self.theme_manager.apply_theme(theme)
        
    def set_theme(self, theme):
        """Cambia el tema de la aplicación"""
        self.settings.setValue("theme", theme)
        self.theme_manager.apply_theme(theme)
        
    def toggle_capture(self):
        """Inicia o detiene la captura de paquetes"""
        if self.is_capturing:
            self.stop_capture()
        else:
            self.start_capture()
            
    def start_capture(self):
        """Inicia la captura de paquetes"""
        if not self.current_interface:
            logging.info("No hay interfaz seleccionada, mostrando diálogo")
            self.show_interface_dialog()
            return
            
        try:
            # Reiniciar el capturer para cada nueva captura
            if self.packet_capturer:
                self.packet_capturer.stop_capture()
                
            logging.info(f"Creando capturer para interfaz: {self.current_interface}")
            self.packet_capturer = PacketCapturer(self.current_interface)
            
            # Intentar conectar en modo batch (optimizado) primero
            try:
                self.packet_capturer.batchCaptured.connect(self.on_batch_captured)
                logging.info("Usando modo de captura por lotes (optimizado)")
            except Exception as e:
                logging.warning(f"No se pudo usar modo batch, usando modo tradicional: {e}")
                self.packet_capturer.packetCaptured.connect(self.on_packet_captured)
            
            # Obtener filtro actual
            current_filter = self.filter_bar.filter_edit.text().strip() if hasattr(self.filter_bar, 'filter_edit') else ""
            logging.info(f"Filtro actual: '{current_filter}'")
            
            # Iniciar captura con el filtro actual
            self.packet_capturer.start_capture(filter_str=current_filter)
            self.is_capturing = True
            self.action_start_capture.setIcon(QIcon(get_icon_path("stop")))
            self.action_start_capture.setText("Detener")
            # Mostrar información detallada de la interfaz en la barra de estado
            interface_desc = self.current_interface_desc if hasattr(self, 'current_interface_desc') else self.current_interface
            self.statusBar().showMessage(f"Capturando en interfaz: {interface_desc}")
            
            # Actualizar información cada segundo
            self.stats_timer.start()
            
            # Mostrar mensaje de información
            logging.info("Captura iniciada correctamente")
            QMessageBox.information(self, "Captura iniciada", 
                                  f"Captura iniciada en la interfaz: {self.current_interface_desc if hasattr(self, 'current_interface_desc') else self.current_interface}.\n\n"
                                  f"Si no ve paquetes, asegúrese de que:\n"
                                  f"1. La aplicación tenga privilegios de administrador\n"
                                  f"2. La interfaz seleccionada esté activa\n"
                                  f"3. Haya tráfico en la red")
                                  
        except Exception as e:
            QMessageBox.critical(self, "Error de captura", 
                                f"No se pudo iniciar la captura: {str(e)}")
            logging.error(f"Error al iniciar la captura: {e}")
            import traceback
            logging.error(traceback.format_exc())
            
    def stop_capture(self):
        """Detiene la captura de paquetes"""
        if self.packet_capturer:
            self.packet_capturer.stop_capture()
            
        self.is_capturing = False
        self.action_start_capture.setIcon(QIcon(get_icon_path("start")))
        self.action_start_capture.setText("Iniciar")
        interface_name = self.current_interface_desc if hasattr(self, 'current_interface_desc') else self.current_interface
        self.statusBar().showMessage(f"Captura detenida - Último adaptador: {interface_name} - {self.capture_count} paquetes capturados")
        self.stats_timer.stop()
        logging.info(f"Captura detenida - {self.capture_count} paquetes capturados")
        
    def show_interface_dialog(self):
        """Muestra el diálogo de selección de interfaz"""
        dialog = InterfaceDialog(self)
        if dialog.exec_():
            self.current_interface = dialog.get_selected_interface()
            self.current_interface_desc = dialog.get_selected_interface_description()
            self.current_interface_full = dialog.get_selected_interface_full()
            
            if self.current_interface:
                # Actualizar la barra de estado con información detallada
                self.statusBar().showMessage(f"Interfaz seleccionada: {self.current_interface_full}", 5000)
                logging.info(f"Interfaz seleccionada para captura: {self.current_interface_full}")
                
                # Cambiar el título de la ventana para mostrar la interfaz seleccionada
                original_title = "Sistema de monitoreo IDS - Analizador de Red"
                self.setWindowTitle(f"{original_title} - Interfaz: {self.current_interface_desc}")
                
    def on_batch_captured(self, packets):
        """Maneja un lote de paquetes capturados
        
        Args:
            packets (list): Lista de paquetes capturados
        """
        try:
            # Procesar cada paquete del lote
            for packet in packets:
                self.on_packet_captured(packet)
                
            # Actualizar la interfaz cada cierto número de paquetes
            if self.capture_count % 100 == 0:
                # Actualizar la barra de estado con el número de paquetes capturados
                interface_desc = self.current_interface_desc if hasattr(self, 'current_interface_desc') else self.current_interface
                self.statusBar().showMessage(f"Capturando en interfaz: {interface_desc} | {self.capture_count} paquetes")
                QApplication.processEvents()  # Permitir que la interfaz se actualice
                
        except Exception as e:
            logging.error(f"Error en procesamiento por lotes: {e}")
                
    def on_packet_captured(self, packet):
        """Maneja un paquete capturado"""
        try:
            # Incrementar contador
            self.capture_count += 1
            
            # Optimización: Limitar registro y análisis detallado a cada 10 paquetes
            # para mejorar rendimiento durante captura intensiva
            do_detailed_analysis = (self.capture_count % 10 == 0 or self.capture_count < 100)
            
            if do_detailed_analysis:
                # Registrar información básica del paquete
                protocols = []
                if packet.haslayer('Ether'): protocols.append('Ethernet')
                if packet.haslayer('IP'): protocols.append('IP')
                if packet.haslayer('TCP'): protocols.append('TCP')
                if packet.haslayer('UDP'): protocols.append('UDP')
                if packet.haslayer('ICMP'): protocols.append('ICMP')
                if packet.haslayer('DNS'): protocols.append('DNS')
                if packet.haslayer('HTTP'): protocols.append('HTTP')
                if packet.haslayer('ARP'): protocols.append('ARP')
                
                proto_str = ', '.join(protocols) or 'Desconocido'
                logging.info(f"Paquete #{self.capture_count} capturado: {proto_str} - {len(packet)} bytes")
                
                # Actualizar barra de estado con información detallada (limitada)
                self.statusBar().showMessage(
                    f"Paquetes capturados: {self.capture_count} | Último: {proto_str} - {len(packet)} bytes"
                )
            else:
                # Versión simplificada para mejorar rendimiento
                if self.capture_count % 50 == 0:  # Actualizar cada 50 paquetes
                    self.statusBar().showMessage(f"Paquetes capturados: {self.capture_count}")
                protocols = []
            
            # Añadir a la vista de lista
            self.packet_list_view.add_packet(packet)
            
            # Analizar seguridad del paquete (siempre, por seguridad)
            self.analyze_packet_security(packet, protocols)
            
        except Exception as e:
            logging.error(f"Error al procesar paquete capturado: {e}")
            import traceback
            logging.error(traceback.format_exc())
        
    def on_packet_selected(self, packet):
        """Maneja la selección de un paquete"""
        try:
            # Registro de depuración para verificar el paquete recibido
            logging.debug(f"Paquete seleccionado recibido en MainWindow: {packet}")
            if packet is None:
                logging.warning("El paquete seleccionado es None")
                return
                
            # Actualizar vista detallada mejorada
            self.enhanced_detail_view.display_packet(packet)
        except Exception as e:
            import traceback
            logging.error(f"Error en on_packet_selected: {e}")
            logging.error(traceback.format_exc())
    
    def analyze_packet_security(self, packet, protocols):
        """Analiza un paquete para detectar amenazas de seguridad"""
        # Preparar información básica del paquete para el análisis de seguridad
        packet_info = {}
        
        # Extraer información de origen y destino
        if packet.haslayer('IP'):
            packet_info['source_ip'] = packet['IP'].src
            packet_info['dest_ip'] = packet['IP'].dst
            packet_info['ttl'] = packet['IP'].ttl
        else:
            # Si no es un paquete IP, intentar obtener direcciones MAC
            if packet.haslayer('Ether'):
                packet_info['source_mac'] = packet['Ether'].src
                packet_info['dest_mac'] = packet['Ether'].dst
            else:
                packet_info['source_ip'] = 'Desconocido'
                packet_info['dest_ip'] = 'Desconocido'
        
        # Extraer información de puertos para TCP/UDP
        if packet.haslayer('TCP'):
            packet_info['protocol'] = 'TCP'
            packet_info['source_port'] = packet['TCP'].sport
            packet_info['dest_port'] = packet['TCP'].dport
            packet_info['flags'] = packet['TCP'].flags
        elif packet.haslayer('UDP'):
            packet_info['protocol'] = 'UDP'
            packet_info['source_port'] = packet['UDP'].sport
            packet_info['dest_port'] = packet['UDP'].dport
        elif packet.haslayer('ICMP'):
            packet_info['protocol'] = 'ICMP'
            packet_info['icmp_type'] = packet['ICMP'].type
            packet_info['icmp_code'] = packet['ICMP'].code
        elif packet.haslayer('ARP'):
            packet_info['protocol'] = 'ARP'
            packet_info['arp_op'] = packet['ARP'].op
        else:
            # Protocolo no específicamente analizado
            packet_info['protocol'] = protocols[0] if protocols else 'Desconocido'
            
        # Analizar con el gestor de alertas
        alert_manager.analyze_packet(packet, packet_info)
        
    def apply_filter(self, filter_text):
        """Aplica un filtro a los paquetes mostrados"""
        try:
            self.packet_list_view.apply_filter(filter_text)
        except Exception as e:
            QMessageBox.warning(self, "Error de filtro", f"Error al aplicar el filtro: {str(e)}")
            
    def clear_capture(self):
        """Limpia todos los paquetes capturados"""
        if self.capture_count > 0:
            reply = QMessageBox.question(self, "Limpiar captura", 
                                        "¿Está seguro de que desea borrar todos los paquetes capturados?",
                                        QMessageBox.Yes | QMessageBox.No)
            if reply == QMessageBox.Yes:
                self.packet_list_view.clear()
                self.enhanced_detail_view.display_packet(None)
                self.capture_count = 0
                self.statusBar().showMessage("Captura limpiada")
                
    def save_capture(self):
        """Guarda la captura actual"""
        if self.capture_count == 0:
            QMessageBox.information(self, "Guardar captura", "No hay paquetes para guardar.")
            return
            
        filename = self.settings.value("last_save_path", "")
        if not filename:
            self.save_capture_as()
        else:
            try:
                self.packet_list_view.save_packets(filename)
                self.statusBar().showMessage(f"Captura guardada en {filename}", 3000)
            except Exception as e:
                QMessageBox.critical(self, "Error al guardar", f"No se pudo guardar la captura: {str(e)}")
                
    def save_capture_as(self):
        """Guarda la captura actual con un nuevo nombre"""
        if self.capture_count == 0:
            QMessageBox.information(self, "Guardar captura", "No hay paquetes para guardar.")
            return
            
        default_dir = self.settings.value("last_save_path", "")
        filename, _ = QFileDialog.getSaveFileName(self, "Guardar captura", default_dir,
                                                "Capturas de NetSniffer (*.pcap);;Todos los archivos (*)")
        
        if filename:
            try:
                self.packet_list_view.save_packets(filename)
                self.settings.setValue("last_save_path", filename)
                self.statusBar().showMessage(f"Captura guardada en {filename}", 3000)
            except Exception as e:
                QMessageBox.critical(self, "Error al guardar", f"No se pudo guardar la captura: {str(e)}")
                
    def open_capture_file(self):
        """Abre un archivo de captura existente"""
        default_dir = self.settings.value("last_open_path", "")
        filename, _ = QFileDialog.getOpenFileName(self, "Abrir captura", default_dir,
                                                "Capturas (*.pcap *.pcapng);;Todos los archivos (*)")
        
        if filename:
            try:
                self.stop_capture()
                self.clear_capture()
                self.packet_list_view.load_packets(filename)
                self.capture_count = self.packet_list_view.get_packet_count()
                self.settings.setValue("last_open_path", filename)
                self.statusBar().showMessage(f"Captura cargada desde {filename}: {self.capture_count} paquetes", 3000)
            except Exception as e:
                QMessageBox.critical(self, "Error al abrir", f"No se pudo abrir la captura: {str(e)}")
                
    def export_packets(self):
        """Exporta los paquetes a diferentes formatos"""
        if self.capture_count == 0:
            QMessageBox.information(self, "Exportar paquetes", "No hay paquetes para exportar.")
            return
            
        # Aquí iría la lógica para exportar a diferentes formatos (CSV, XML, etc.)
        QMessageBox.information(self, "Exportar paquetes", "Función no implementada aún.")
        
    def show_statistics(self):
        """Muestra la ventana de estadísticas"""
        if not hasattr(self, 'statistics_window') or not self.statistics_window.isVisible():
            self.statistics_window = StatisticsWindow(self.packet_list_view.get_packets())
            self.statistics_window.show()
        else:
            self.statistics_window.activateWindow()
            
    def update_statistics(self):
        """Actualiza las estadísticas en tiempo real"""
        if hasattr(self, 'statistics_window') and self.statistics_window.isVisible():
            self.statistics_window.update_statistics(self.packet_list_view.get_packets())
            
    def show_capture_options(self):
        """Muestra el diálogo de opciones de captura"""
        # Aquí iría la lógica para mostrar y configurar opciones de captura
        QMessageBox.information(self, "Opciones de captura", "Función no implementada aún.")
        
    def show_filter_dialog(self):
        """Muestra el diálogo de filtros avanzados"""
        # Aquí iría la lógica para mostrar el diálogo de filtros avanzados
        QMessageBox.information(self, "Filtros avanzados", "Función no implementada aún.")
        
    def show_protocol_hierarchy(self):
        """Muestra la jerarquía de protocolos"""
        # Aquí iría la lógica para mostrar la jerarquía de protocolos
        QMessageBox.information(self, "Jerarquía de protocolos", "Función no implementada aún.")
        
    def show_flow_graph(self):
        """Muestra el gráfico de flujo"""
        # Aquí iría la lógica para mostrar el gráfico de flujo
        QMessageBox.information(self, "Gráfico de flujo", "Función no implementada aún.")
        
    def show_preferences(self):
        """Muestra el diálogo de preferencias"""
        dialog = PreferencesDialog(self)
        dialog.exec_()
        
    def show_help(self):
        """Muestra la ayuda de la aplicación"""
        # Aquí iría la lógica para mostrar la ayuda
        QMessageBox.information(self, "Ayuda del Sistema de monitoreo IDS", "Función no implementada aún.")
        
    def show_about(self):
        """Muestra el diálogo de acerca de"""
        dialog = AboutDialog(self)
        dialog.exec_()
        
    def zoom_in(self):
        """Aumenta el zoom de la vista"""
        # Aquí iría la lógica para aumentar el zoom
        pass
        
    def zoom_out(self):
        """Disminuye el zoom de la vista"""
        # Aquí iría la lógica para disminuir el zoom
        pass
        
    def reset_zoom(self):
        """Restablece el zoom a su valor predeterminado"""
        # Aquí iría la lógica para restablecer el zoom
        pass
        
    def load_settings(self):
        """Carga la configuración guardada"""
        # Cargar tema
        theme = self.settings.value("theme", "system")
        self.theme_manager.apply_theme(theme)
        
        # Cargar geometría de la ventana
        if self.settings.contains("geometry"):
            self.restoreGeometry(self.settings.value("geometry"))
            
        if self.settings.contains("windowState"):
            self.restoreState(self.settings.value("windowState"))
            
    def save_settings(self):
        """Guarda la configuración actual"""
        self.settings.setValue("geometry", self.saveGeometry())
        self.settings.setValue("windowState", self.saveState())
        
    def closeEvent(self, event):
        """Maneja el evento de cierre de la ventana"""
        if self.is_capturing:
            reply = QMessageBox.question(self, "Cerrar Sistema de monitoreo IDS", 
                                        "Hay una captura en curso. ¿Está seguro de que desea salir?",
                                        QMessageBox.Yes | QMessageBox.No)
            if reply == QMessageBox.No:
                event.ignore()
                return
                
        self.save_settings()
        event.accept()
        
    def show_block_ip_dialog(self):
        """Muestra el diálogo para bloquear una IP"""
        from gui.alerts_manager_view import BlockIPDialog
        
        dialog = BlockIPDialog(self)
        if dialog.exec_() == QDialog.Accepted:
            data = dialog.get_data()
            ip = data['ip']
            motivo = data['motivo'] or "Bloqueo manual"
            
            if not ip:
                QMessageBox.warning(self, "Error", "Debe ingresar una dirección IP")
                return
                
            if alert_manager.block_ip(ip):
                # Registrar una alerta de bloqueo manual
                alert_manager.add_alert("MANUAL-BLOCK", ip, motivo, "Alto")
                self.security_tab.refresh_blocked_ips()
                self.security_tab.refresh_alerts()
                QMessageBox.information(self, "IP Bloqueada", 
                                      f"La dirección IP {ip} ha sido bloqueada exitosamente.")
            else:
                QMessageBox.warning(self, "Error", 
                                 f"No se pudo bloquear la dirección IP {ip}.")
