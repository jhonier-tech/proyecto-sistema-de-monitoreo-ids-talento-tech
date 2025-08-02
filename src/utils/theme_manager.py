#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Módulo para gestionar los temas de la aplicación
"""

import logging
from PyQt5.QtWidgets import QApplication
from PyQt5.QtGui import QPalette, QColor
from PyQt5.QtCore import Qt

class ThemeManager:
    """Clase para gestionar los temas de la aplicación"""
    
    def __init__(self):
        """Inicializa el gestor de temas"""
        self.current_theme = "system"
        
    def apply_theme(self, theme):
        """Aplica el tema especificado a la aplicación
        
        Args:
            theme (str): El tema a aplicar ("light", "dark" o "system")
        """
        self.current_theme = theme
        
        app = QApplication.instance()
        if not app:
            logging.error("No se puede aplicar el tema: No hay instancia de QApplication")
            return
            
        if theme == "system":
            # Usar tema del sistema
            app.setStyle("Fusion")
            app.setPalette(app.style().standardPalette())
            logging.info("Tema del sistema aplicado")
            return
            
        # Crear paleta personalizada
        palette = QPalette()
        
        if theme == "dark":
            # Tema oscuro
            palette.setColor(QPalette.Window, QColor(53, 53, 53))
            palette.setColor(QPalette.WindowText, Qt.white)
            palette.setColor(QPalette.Base, QColor(35, 35, 35))
            palette.setColor(QPalette.AlternateBase, QColor(53, 53, 53))
            palette.setColor(QPalette.ToolTipBase, QColor(25, 25, 25))
            palette.setColor(QPalette.ToolTipText, Qt.white)
            palette.setColor(QPalette.Text, Qt.white)
            palette.setColor(QPalette.Button, QColor(53, 53, 53))
            palette.setColor(QPalette.ButtonText, Qt.white)
            palette.setColor(QPalette.BrightText, Qt.red)
            palette.setColor(QPalette.Link, QColor(42, 130, 218))
            palette.setColor(QPalette.Highlight, QColor(42, 130, 218))
            palette.setColor(QPalette.HighlightedText, Qt.white)
            
            # Colores adicionales para elementos específicos
            palette.setColor(QPalette.Active, QPalette.Button, QColor(53, 53, 53))
            palette.setColor(QPalette.Disabled, QPalette.ButtonText, Qt.darkGray)
            palette.setColor(QPalette.Disabled, QPalette.WindowText, Qt.darkGray)
            palette.setColor(QPalette.Disabled, QPalette.Text, Qt.darkGray)
            palette.setColor(QPalette.Disabled, QPalette.Light, QColor(53, 53, 53))
            
            app.setStyle("Fusion")
            app.setPalette(palette)
            logging.info("Tema oscuro aplicado")
        else:
            # Tema claro (predeterminado)
            palette.setColor(QPalette.Window, QColor(240, 240, 240))
            palette.setColor(QPalette.WindowText, QColor(0, 0, 0))
            palette.setColor(QPalette.Base, QColor(255, 255, 255))
            palette.setColor(QPalette.AlternateBase, QColor(233, 233, 233))
            palette.setColor(QPalette.ToolTipBase, QColor(255, 255, 255))
            palette.setColor(QPalette.ToolTipText, QColor(0, 0, 0))
            palette.setColor(QPalette.Text, QColor(0, 0, 0))
            palette.setColor(QPalette.Button, QColor(240, 240, 240))
            palette.setColor(QPalette.ButtonText, QColor(0, 0, 0))
            palette.setColor(QPalette.BrightText, QColor(255, 0, 0))
            palette.setColor(QPalette.Link, QColor(0, 0, 255))
            palette.setColor(QPalette.Highlight, QColor(42, 130, 218))
            palette.setColor(QPalette.HighlightedText, QColor(255, 255, 255))
            
            app.setStyle("Fusion")
            app.setPalette(palette)
            logging.info("Tema claro aplicado")
            
    def get_current_theme(self):
        """Obtiene el tema actual
        
        Returns:
            str: El tema actual
        """
        return self.current_theme
