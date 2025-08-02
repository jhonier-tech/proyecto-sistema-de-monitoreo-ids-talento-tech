#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Módulo para la barra de filtros
"""

from PyQt5.QtWidgets import (QWidget, QHBoxLayout, QLineEdit, QToolButton, 
                           QCompleter, QMenu, QAction, QLabel)
from PyQt5.QtGui import QIcon
from PyQt5.QtCore import Qt, pyqtSignal

from utils.icons import get_icon_path

class FilterBar(QWidget):
    """Barra de filtros para filtrar paquetes"""
    
    # Señal emitida cuando se aplica un filtro
    filterApplied = pyqtSignal(str)
    
    def __init__(self, parent=None):
        """Inicializa la barra de filtros
        
        Args:
            parent: Widget padre
        """
        super().__init__(parent)
        
        # Configuración de la interfaz
        self.setup_ui()
        
        # Lista de filtros recientes
        self.recent_filters = []
        
    def setup_ui(self):
        """Configura la interfaz de usuario"""
        # Layout principal
        layout = QHBoxLayout(self)
        layout.setContentsMargins(8, 4, 8, 4)
        layout.setSpacing(4)
        
        # Etiqueta "Filtro:"
        label = QLabel("Filtro:")
        layout.addWidget(label)
        
        # Campo de texto para el filtro
        self.filter_edit = QLineEdit()
        self.filter_edit.setPlaceholderText("Introduzca un filtro (por ejemplo: tcp, ip.src==192.168.1.1)")
        self.filter_edit.returnPressed.connect(self.apply_filter)
        layout.addWidget(self.filter_edit)
        
        # Botón para aplicar el filtro
        self.apply_button = QToolButton()
        self.apply_button.setText("Aplicar")
        self.apply_button.setIcon(QIcon(get_icon_path("filter")))
        self.apply_button.setToolButtonStyle(Qt.ToolButtonTextBesideIcon)
        self.apply_button.clicked.connect(self.apply_filter)
        layout.addWidget(self.apply_button)
        
        # Botón para limpiar el filtro
        self.clear_button = QToolButton()
        self.clear_button.setText("Limpiar")
        self.clear_button.clicked.connect(self.clear_filter)
        layout.addWidget(self.clear_button)
        
        # Botón para mostrar filtros recientes
        self.history_button = QToolButton()
        self.history_button.setText("Historial")
        self.history_button.setPopupMode(QToolButton.InstantPopup)
        self.history_button.setMenu(QMenu(self.history_button))
        layout.addWidget(self.history_button)
        
        # Configurar autocompletado
        self.setup_completer()
        
        # Actualizar el menú de filtros recientes
        self.update_recent_filters_menu()
        
    def setup_completer(self):
        """Configura el autocompletado para el campo de filtro"""
        # Lista de filtros comunes
        common_filters = [
            "tcp", "udp", "icmp", "arp", "dns", "http", "https",
            "ip.src==", "ip.dst==", "tcp.port==", "udp.port==",
            "tcp.flags.syn==1", "tcp.flags.ack==1", "tcp.flags.fin==1",
            "tcp.flags.rst==1", "ether.src==", "ether.dst=="
        ]
        
        # Crear completer
        completer = QCompleter(common_filters)
        completer.setCaseSensitivity(Qt.CaseInsensitive)
        self.filter_edit.setCompleter(completer)
        
    def apply_filter(self):
        """Aplica el filtro actual"""
        try:
            filter_text = self.filter_edit.text().strip()
            
            # Validar el filtro antes de aplicar
            try:
                from utils.filter_manager import FilterManager
                filter_manager = FilterManager()
                is_valid, error_message = filter_manager.validate_filter(filter_text)
                
                if not is_valid:
                    from PyQt5.QtWidgets import QMessageBox
                    QMessageBox.warning(self, "Error de filtro", 
                                      f"El filtro '{filter_text}' no es válido.\n\n{error_message}")
                    return
            except Exception as e:
                import logging
                logging.error(f"Error al validar filtro: {e}")
                import traceback
                logging.error(traceback.format_exc())
            
            # Añadir a recientes si no está vacío y es válido
            if filter_text and filter_text not in self.recent_filters:
                self.recent_filters.insert(0, filter_text)
                # Limitar a 10 filtros recientes
                if len(self.recent_filters) > 10:
                    self.recent_filters = self.recent_filters[:10]
                    
                # Actualizar menú
                self.update_recent_filters_menu()
                
            # Emitir señal
            self.filterApplied.emit(filter_text)
        except Exception as e:
            import logging
            logging.error(f"Error general en apply_filter: {e}")
            import traceback
            logging.error(traceback.format_exc())
        
    def clear_filter(self):
        """Limpia el filtro actual"""
        try:
            self.filter_edit.clear()
            self.filterApplied.emit("")
        except Exception as e:
            import logging
            logging.error(f"Error al limpiar filtro: {e}")
            import traceback
            logging.error(traceback.format_exc())
        
    def update_recent_filters_menu(self):
        """Actualiza el menú de filtros recientes"""
        try:
            # Asegurarse de que recent_filters exista
            if not hasattr(self, 'recent_filters'):
                self.recent_filters = []
                
            # Limpiar menú actual
            menu = self.history_button.menu()
            if menu is None:
                menu = QMenu(self.history_button)
                self.history_button.setMenu(menu)
            menu.clear()
            
            # Añadir filtros recientes
            for filter_text in self.recent_filters:
                action = QAction(filter_text, menu)
                # Usar una función lambda con cierre (closure) para capturar el valor actual
                action.triggered.connect(lambda checked=False, f=filter_text: self.apply_recent_filter(f))
                menu.addAction(action)
                
            # Añadir acción para limpiar historial
            if self.recent_filters:
                menu.addSeparator()
                clear_action = QAction("Limpiar historial", menu)
                clear_action.triggered.connect(self.clear_recent_filters)
                menu.addAction(clear_action)
        except Exception as e:
            import logging
            logging.error(f"Error en update_recent_filters_menu: {e}")
            import traceback
            logging.error(traceback.format_exc())
            
    def apply_recent_filter(self, filter_text):
        """Aplica un filtro reciente
        
        Args:
            filter_text: Texto del filtro a aplicar
        """
        try:
            self.filter_edit.setText(filter_text)
            self.apply_filter()
        except Exception as e:
            import logging
            logging.error(f"Error al aplicar filtro reciente: {e}")
            
    def clear_recent_filters(self):
        """Limpia la lista de filtros recientes"""
        try:
            self.recent_filters = []
            self.update_recent_filters_menu()
        except Exception as e:
            import logging
            logging.error(f"Error al limpiar filtros recientes: {e}")
