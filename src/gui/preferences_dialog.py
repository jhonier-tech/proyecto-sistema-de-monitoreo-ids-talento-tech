#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Módulo para el diálogo de preferencias
"""

from PyQt5.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout, QTabWidget,
                           QWidget, QFormLayout, QLabel, QLineEdit,
                           QCheckBox, QComboBox, QSpinBox, QPushButton,
                           QGroupBox, QRadioButton, QDialogButtonBox,
                           QFileDialog, QColorDialog, QMessageBox)
from PyQt5.QtGui import QIcon, QColor
from PyQt5.QtCore import Qt, QSettings

from utils.icons import get_icon_path

class PreferencesDialog(QDialog):
    """Diálogo para configurar las preferencias de la aplicación"""
    
    def __init__(self, parent=None):
        """Inicializa el diálogo de preferencias
        
        Args:
            parent: Widget padre
        """
        super().__init__(parent)
        
        # Configurar ventana
        self.setWindowTitle("Preferencias")
        self.setWindowIcon(QIcon(get_icon_path("preferences")))
        self.resize(500, 400)
        
        # Cargar configuración
        self.settings = QSettings("Sistema de monitoreo IDS", "Sistema de monitoreo IDS")
        
        # Configurar interfaz
        self.setup_ui()
        
        # Cargar valores actuales
        self.load_settings()
        
    def setup_ui(self):
        """Configura la interfaz de usuario"""
        # Layout principal
        layout = QVBoxLayout(self)
        
        # Pestañas
        self.tab_widget = QTabWidget()
        layout.addWidget(self.tab_widget)
        
        # Pestaña General
        self.setup_general_tab()
        
        # Pestaña Captura
        self.setup_capture_tab()
        
        # Pestaña Visualización
        self.setup_display_tab()
        
        # Pestaña Avanzado
        self.setup_advanced_tab()
        
        # Botones
        button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        button_box.accepted.connect(self.accept)
        button_box.rejected.connect(self.reject)
        layout.addWidget(button_box)
        
    def setup_general_tab(self):
        """Configura la pestaña de opciones generales"""
        general_tab = QWidget()
        layout = QVBoxLayout(general_tab)
        
        # Opciones de inicio
        startup_group = QGroupBox("Inicio")
        startup_layout = QVBoxLayout(startup_group)
        
        self.check_auto_capture = QCheckBox("Iniciar captura automáticamente al abrir")
        startup_layout.addWidget(self.check_auto_capture)
        
        self.check_load_last = QCheckBox("Cargar última sesión al iniciar")
        startup_layout.addWidget(self.check_load_last)
        
        self.check_check_updates = QCheckBox("Comprobar actualizaciones al iniciar")
        startup_layout.addWidget(self.check_check_updates)
        
        layout.addWidget(startup_group)
        
        # Opciones de archivo
        file_group = QGroupBox("Archivos")
        file_layout = QFormLayout(file_group)
        
        self.combo_default_format = QComboBox()
        self.combo_default_format.addItems(["PCAP", "PCAPNG"])
        file_layout.addRow("Formato de captura predeterminado:", self.combo_default_format)
        
        self.edit_save_dir = QLineEdit()
        browse_button = QPushButton("Examinar...")
        browse_button.clicked.connect(self.browse_save_dir)
        
        save_dir_layout = QHBoxLayout()
        save_dir_layout.addWidget(self.edit_save_dir)
        save_dir_layout.addWidget(browse_button)
        
        file_layout.addRow("Directorio de guardado:", save_dir_layout)
        
        layout.addWidget(file_group)
        
        # Ajuste de tiempo
        time_group = QGroupBox("Ajustes de tiempo")
        time_layout = QFormLayout(time_group)
        
        self.combo_time_format = QComboBox()
        self.combo_time_format.addItems(["Tiempo local", "UTC", "Tiempo desde inicio", "Tiempo desde paquete anterior"])
        time_layout.addRow("Formato de tiempo:", self.combo_time_format)
        
        layout.addWidget(time_group)
        
        layout.addStretch()
        
        self.tab_widget.addTab(general_tab, "General")
        
    def setup_capture_tab(self):
        """Configura la pestaña de opciones de captura"""
        capture_tab = QWidget()
        layout = QVBoxLayout(capture_tab)
        
        # Opciones de captura
        capture_group = QGroupBox("Opciones de captura")
        capture_layout = QFormLayout(capture_group)
        
        self.check_promiscuous = QCheckBox("Activar modo promiscuo")
        capture_layout.addRow("", self.check_promiscuous)
        
        self.spin_buffer_size = QSpinBox()
        self.spin_buffer_size.setMinimum(1)
        self.spin_buffer_size.setMaximum(1000)
        self.spin_buffer_size.setSuffix(" MB")
        capture_layout.addRow("Tamaño del buffer:", self.spin_buffer_size)
        
        self.spin_max_packets = QSpinBox()
        self.spin_max_packets.setMinimum(0)
        self.spin_max_packets.setMaximum(1000000)
        self.spin_max_packets.setSpecialValueText("Sin límite")
        capture_layout.addRow("Número máximo de paquetes:", self.spin_max_packets)
        
        layout.addWidget(capture_group)
        
        # Opciones de filtrado
        filter_group = QGroupBox("Filtrado")
        filter_layout = QFormLayout(filter_group)
        
        self.edit_default_filter = QLineEdit()
        filter_layout.addRow("Filtro predeterminado:", self.edit_default_filter)
        
        layout.addWidget(filter_group)
        
        layout.addStretch()
        
        self.tab_widget.addTab(capture_tab, "Captura")
        
    def setup_display_tab(self):
        """Configura la pestaña de opciones de visualización"""
        display_tab = QWidget()
        layout = QVBoxLayout(display_tab)
        
        # Opciones de tema
        theme_group = QGroupBox("Tema")
        theme_layout = QVBoxLayout(theme_group)
        
        self.radio_light = QRadioButton("Tema claro")
        theme_layout.addWidget(self.radio_light)
        
        self.radio_dark = QRadioButton("Tema oscuro")
        theme_layout.addWidget(self.radio_dark)
        
        self.radio_system = QRadioButton("Usar tema del sistema")
        theme_layout.addWidget(self.radio_system)
        
        layout.addWidget(theme_group)
        
        # Opciones de fuente
        font_group = QGroupBox("Fuente")
        font_layout = QFormLayout(font_group)
        
        self.combo_font_family = QComboBox()
        self.combo_font_family.addItems(["Consolas", "Courier New", "Monospace", "DejaVu Sans Mono"])
        font_layout.addRow("Familia:", self.combo_font_family)
        
        self.spin_font_size = QSpinBox()
        self.spin_font_size.setMinimum(8)
        self.spin_font_size.setMaximum(18)
        font_layout.addRow("Tamaño:", self.spin_font_size)
        
        layout.addWidget(font_group)
        
        # Opciones de coloración
        color_group = QGroupBox("Coloración de paquetes")
        color_layout = QVBoxLayout(color_group)
        
        self.check_color_packets = QCheckBox("Colorear paquetes según protocolo")
        color_layout.addWidget(self.check_color_packets)
        
        self.check_alternate_colors = QCheckBox("Alternar colores de fila")
        color_layout.addWidget(self.check_alternate_colors)
        
        layout.addWidget(color_group)
        
        layout.addStretch()
        
        self.tab_widget.addTab(display_tab, "Visualización")
        
    def setup_advanced_tab(self):
        """Configura la pestaña de opciones avanzadas"""
        advanced_tab = QWidget()
        layout = QVBoxLayout(advanced_tab)
        
        # Opciones avanzadas de captura
        advanced_group = QGroupBox("Opciones avanzadas")
        advanced_layout = QFormLayout(advanced_group)
        
        self.spin_capture_timeout = QSpinBox()
        self.spin_capture_timeout.setMinimum(0)
        self.spin_capture_timeout.setMaximum(10000)
        self.spin_capture_timeout.setSuffix(" ms")
        self.spin_capture_timeout.setSpecialValueText("Sin timeout")
        advanced_layout.addRow("Timeout de captura:", self.spin_capture_timeout)
        
        self.check_resolve_names = QCheckBox("Resolver nombres de host")
        advanced_layout.addRow("", self.check_resolve_names)
        
        self.check_check_checksums = QCheckBox("Verificar checksums")
        advanced_layout.addRow("", self.check_check_checksums)
        
        layout.addWidget(advanced_group)
        
        # Opciones de rendimiento
        performance_group = QGroupBox("Rendimiento")
        performance_layout = QFormLayout(performance_group)
        
        self.spin_refresh_interval = QSpinBox()
        self.spin_refresh_interval.setMinimum(100)
        self.spin_refresh_interval.setMaximum(5000)
        self.spin_refresh_interval.setSuffix(" ms")
        performance_layout.addRow("Intervalo de actualización:", self.spin_refresh_interval)
        
        layout.addWidget(performance_group)
        
        # Opciones de registro
        log_group = QGroupBox("Registro")
        log_layout = QFormLayout(log_group)
        
        self.combo_log_level = QComboBox()
        self.combo_log_level.addItems(["ERROR", "WARNING", "INFO", "DEBUG"])
        log_layout.addRow("Nivel de registro:", self.combo_log_level)
        
        layout.addWidget(log_group)
        
        # Botón para restaurar valores predeterminados
        reset_button = QPushButton("Restaurar valores predeterminados")
        reset_button.clicked.connect(self.reset_defaults)
        layout.addWidget(reset_button)
        
        layout.addStretch()
        
        self.tab_widget.addTab(advanced_tab, "Avanzado")
        
    def browse_save_dir(self):
        """Abre un diálogo para seleccionar el directorio de guardado"""
        directory = QFileDialog.getExistingDirectory(self, "Seleccionar directorio de guardado", 
                                                   self.edit_save_dir.text())
        if directory:
            self.edit_save_dir.setText(directory)
            
    def load_settings(self):
        """Carga la configuración actual"""
        # General
        self.check_auto_capture.setChecked(self.settings.value("auto_capture", False, type=bool))
        self.check_load_last.setChecked(self.settings.value("load_last_session", True, type=bool))
        self.check_check_updates.setChecked(self.settings.value("check_updates", True, type=bool))
        
        self.combo_default_format.setCurrentText(self.settings.value("default_format", "PCAP"))
        self.edit_save_dir.setText(self.settings.value("save_directory", ""))
        self.combo_time_format.setCurrentText(self.settings.value("time_format", "Tiempo local"))
        
        # Captura
        self.check_promiscuous.setChecked(self.settings.value("promiscuous_mode", True, type=bool))
        self.spin_buffer_size.setValue(self.settings.value("buffer_size", 10, type=int))
        self.spin_max_packets.setValue(self.settings.value("max_packets", 0, type=int))
        self.edit_default_filter.setText(self.settings.value("default_filter", ""))
        
        # Visualización
        theme = self.settings.value("theme", "system")
        if theme == "light":
            self.radio_light.setChecked(True)
        elif theme == "dark":
            self.radio_dark.setChecked(True)
        else:
            self.radio_system.setChecked(True)
            
        self.combo_font_family.setCurrentText(self.settings.value("font_family", "Consolas"))
        self.spin_font_size.setValue(self.settings.value("font_size", 10, type=int))
        self.check_color_packets.setChecked(self.settings.value("color_packets", True, type=bool))
        self.check_alternate_colors.setChecked(self.settings.value("alternate_colors", True, type=bool))
        
        # Avanzado
        self.spin_capture_timeout.setValue(self.settings.value("capture_timeout", 0, type=int))
        self.check_resolve_names.setChecked(self.settings.value("resolve_names", False, type=bool))
        self.check_check_checksums.setChecked(self.settings.value("check_checksums", True, type=bool))
        self.spin_refresh_interval.setValue(self.settings.value("refresh_interval", 1000, type=int))
        self.combo_log_level.setCurrentText(self.settings.value("log_level", "INFO"))
        
    def save_settings(self):
        """Guarda la configuración actual"""
        # General
        self.settings.setValue("auto_capture", self.check_auto_capture.isChecked())
        self.settings.setValue("load_last_session", self.check_load_last.isChecked())
        self.settings.setValue("check_updates", self.check_check_updates.isChecked())
        
        self.settings.setValue("default_format", self.combo_default_format.currentText())
        self.settings.setValue("save_directory", self.edit_save_dir.text())
        self.settings.setValue("time_format", self.combo_time_format.currentText())
        
        # Captura
        self.settings.setValue("promiscuous_mode", self.check_promiscuous.isChecked())
        self.settings.setValue("buffer_size", self.spin_buffer_size.value())
        self.settings.setValue("max_packets", self.spin_max_packets.value())
        self.settings.setValue("default_filter", self.edit_default_filter.text())
        
        # Visualización
        if self.radio_light.isChecked():
            theme = "light"
        elif self.radio_dark.isChecked():
            theme = "dark"
        else:
            theme = "system"
            
        self.settings.setValue("theme", theme)
        
        self.settings.setValue("font_family", self.combo_font_family.currentText())
        self.settings.setValue("font_size", self.spin_font_size.value())
        self.settings.setValue("color_packets", self.check_color_packets.isChecked())
        self.settings.setValue("alternate_colors", self.check_alternate_colors.isChecked())
        
        # Avanzado
        self.settings.setValue("capture_timeout", self.spin_capture_timeout.value())
        self.settings.setValue("resolve_names", self.check_resolve_names.isChecked())
        self.settings.setValue("check_checksums", self.check_check_checksums.isChecked())
        self.settings.setValue("refresh_interval", self.spin_refresh_interval.value())
        self.settings.setValue("log_level", self.combo_log_level.currentText())
        
    def reset_defaults(self):
        """Restaura los valores predeterminados"""
        reply = QMessageBox.question(self, "Restaurar valores predeterminados",
                                    "¿Está seguro de que desea restaurar todos los valores a su configuración predeterminada?",
                                    QMessageBox.Yes | QMessageBox.No)
                                    
        if reply == QMessageBox.Yes:
            # Eliminar todas las configuraciones
            self.settings.clear()
            
            # Recargar valores predeterminados
            self.load_settings()
            
    def accept(self):
        """Maneja la aceptación del diálogo"""
        # Guardar configuración
        self.save_settings()
        
        super().accept()
