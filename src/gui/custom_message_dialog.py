#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Diálogo para configurar mensajes personalizados de alertas de seguridad
"""

import os
import sys
import logging
from PyQt5.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout, QTabWidget, QWidget,
                           QLabel, QLineEdit, QComboBox, QPushButton, QTableWidget,
                           QTableWidgetItem, QHeaderView, QMessageBox, QFormLayout,
                           QGroupBox, QDialogButtonBox, QCheckBox)
from PyQt5.QtCore import Qt, pyqtSignal, QSize

from security.alert_manager import alert_manager
from security.security_config import ALERT_MESSAGES, DEFAULT_OS

class CustomMessageDialog(QDialog):
    """Diálogo para configurar mensajes personalizados de alerta"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()
        self.load_messages()
        
    def setup_ui(self):
        """Configura la interfaz de usuario"""
        self.setWindowTitle("Configuración de Mensajes de Alerta")
        self.setMinimumSize(700, 500)
        
        main_layout = QVBoxLayout(self)
        
        # Título
        title_label = QLabel("<h2>Configurar Mensajes de Alerta por Sistema Operativo</h2>")
        title_label.setAlignment(Qt.AlignCenter)
        main_layout.addWidget(title_label)
        
        # Descripción
        desc_label = QLabel("Personalice los mensajes que se mostrarán en las alertas según el sistema operativo detectado:")
        main_layout.addWidget(desc_label)
        
        # Pestañas para cada sistema operativo
        self.tabs = QTabWidget()
        
        os_list = ["Windows", "Linux", "Android", "MacOS", "Desconocido"]
        self.message_inputs = {}  # Para almacenar los widgets de entrada
        
        for os_name in os_list:
            tab = QWidget()
            tab_layout = QVBoxLayout(tab)
            
            # Crear grupo para cada tipo de alerta
            form_group = QGroupBox(f"Mensajes para {os_name}")
            form_layout = QFormLayout()
            
            # Crear campos para cada tipo de alerta
            self.message_inputs[os_name] = {}
            alert_types = ["PING", "PING-FLOOD", "PORT-SCAN", "BLOCKED-IP", "ARP-SPOOF", "MANUAL-BLOCK"]
            
            for alert_type in alert_types:
                # Obtener mensaje predeterminado
                default_msg = ""
                if os_name in ALERT_MESSAGES and alert_type in ALERT_MESSAGES[os_name]:
                    default_msg = ALERT_MESSAGES[os_name][alert_type]
                elif DEFAULT_OS in ALERT_MESSAGES and alert_type in ALERT_MESSAGES[DEFAULT_OS]:
                    default_msg = ALERT_MESSAGES[DEFAULT_OS][alert_type]
                
                # Crear campo de entrada
                input_field = QLineEdit()
                input_field.setMinimumWidth(400)
                input_field.setPlaceholderText(default_msg)
                
                # Si hay un mensaje personalizado, usarlo
                if (os_name in alert_manager.custom_messages and 
                    alert_type in alert_manager.custom_messages[os_name]):
                    input_field.setText(alert_manager.custom_messages[os_name][alert_type])
                
                self.message_inputs[os_name][alert_type] = input_field
                form_layout.addRow(f"Alerta {alert_type}:", input_field)
            
            form_group.setLayout(form_layout)
            tab_layout.addWidget(form_group)
            
            # Botón para restablecer valores predeterminados
            reset_btn = QPushButton("Restablecer Valores Predeterminados")
            reset_btn.clicked.connect(lambda _, os=os_name: self.reset_messages(os))
            tab_layout.addWidget(reset_btn)
            
            self.tabs.addTab(tab, os_name)
        
        main_layout.addWidget(self.tabs)
        
        # Botones
        button_layout = QHBoxLayout()
        
        save_btn = QPushButton("Guardar Cambios")
        save_btn.setIcon(self.style().standardIcon(self.style().SP_DialogSaveButton))
        save_btn.clicked.connect(self.save_messages)
        button_layout.addWidget(save_btn)
        
        cancel_btn = QPushButton("Cancelar")
        cancel_btn.clicked.connect(self.reject)
        button_layout.addWidget(cancel_btn)
        
        main_layout.addLayout(button_layout)
    
    def load_messages(self):
        """Carga los mensajes personalizados existentes"""
        alert_manager.load_custom_config()
        
        for os_name in self.message_inputs:
            for alert_type, input_field in self.message_inputs[os_name].items():
                if (os_name in alert_manager.custom_messages and 
                    alert_type in alert_manager.custom_messages[os_name]):
                    input_field.setText(alert_manager.custom_messages[os_name][alert_type])
    
    def reset_messages(self, os_name):
        """Restablece los valores predeterminados para un sistema operativo"""
        reply = QMessageBox.question(self, "Confirmar", 
                                   f"¿Restablecer todos los mensajes para {os_name} a los valores predeterminados?",
                                   QMessageBox.Yes | QMessageBox.No)
        if reply == QMessageBox.No:
            return
        
        # Limpiar campos de entrada
        for alert_type, input_field in self.message_inputs[os_name].items():
            input_field.clear()
        
        # Eliminar mensajes personalizados para este SO
        if os_name in alert_manager.custom_messages:
            alert_manager.custom_messages[os_name] = {}
            alert_manager.save_custom_config()
            
        QMessageBox.information(self, "Valores Restablecidos", 
                             f"Los mensajes para {os_name} han sido restablecidos.")
    
    def save_messages(self):
        """Guarda los mensajes personalizados"""
        changes_made = False
        
        for os_name in self.message_inputs:
            for alert_type, input_field in self.message_inputs[os_name].items():
                text = input_field.text().strip()
                
                if text:  # Si hay un mensaje personalizado
                    alert_manager.set_custom_message(alert_type, os_name, text)
                    changes_made = True
                else:
                    # Si el campo está vacío pero había un mensaje personalizado, eliminarlo
                    if (os_name in alert_manager.custom_messages and 
                        alert_type in alert_manager.custom_messages[os_name]):
                        del alert_manager.custom_messages[os_name][alert_type]
                        changes_made = True
        
        if changes_made:
            alert_manager.save_custom_config()
            QMessageBox.information(self, "Cambios Guardados", 
                                 "Los mensajes de alerta personalizados han sido guardados.")
            self.accept()
        else:
            QMessageBox.information(self, "Sin Cambios", 
                                 "No se han realizado cambios en los mensajes.")
            self.reject()
