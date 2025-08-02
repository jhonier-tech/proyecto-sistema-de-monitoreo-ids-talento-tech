#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Módulo que proporciona la interfaz gráfica para la gestión de alertas de seguridad
"""

import os
import logging
from datetime import datetime
from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QTableWidget, 
                            QTableWidgetItem, QPushButton, QLabel, QHeaderView,
                            QAbstractItemView, QSplitter, QGroupBox, QTextEdit,
                            QComboBox, QDialog, QDialogButtonBox, QFormLayout,
                            QLineEdit, QMessageBox, QCheckBox)
from PyQt5.QtCore import Qt, pyqtSignal, QTimer
from PyQt5.QtGui import QIcon, QColor, QBrush, QFont

from security.alert_manager import alert_manager
from utils.icons import get_icon_path

class AlertDialog(QDialog):
    """Diálogo para mostrar información detallada de una alerta"""
    
    def __init__(self, alerta, parent=None):
        super().__init__(parent)
        self.alerta = alerta
        self.setup_ui()
        
    def setup_ui(self):
        """Configura la interfaz del diálogo"""
        self.setWindowTitle("Detalles de Alerta")
        self.setMinimumSize(500, 400)
        
        layout = QVBoxLayout(self)
        
        # Título con nivel de riesgo
        nivel = self.alerta.get('nivel_riesgo', 'Desconocido')
        color_text = ""
        if nivel == "Alto":
            color_text = "color: #ff4d4d;"
        elif nivel == "Medio":
            color_text = "color: #ffa64d;"
        else:
            color_text = "color: #4d94ff;"
            
        title_label = QLabel(f"<h2><span style='{color_text}'>{self.alerta.get('tipo', 'Alerta')}</span></h2>")
        title_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(title_label)
        
        # Información básica
        info_group = QGroupBox("Información de la Alerta")
        info_layout = QFormLayout()
        
        timestamp = self.alerta.get('timestamp', datetime.now())
        ip = self.alerta.get('ip', 'Desconocida')
        mensaje = self.alerta.get('mensaje', '')
        os_type = self.alerta.get('os_type', 'Desconocido')
        
        info_layout.addRow("Fecha y hora:", QLabel(timestamp.strftime("%d/%m/%Y %H:%M:%S")))
        info_layout.addRow("Dirección IP:", QLabel(ip))
        info_layout.addRow("Sistema operativo:", QLabel(os_type))
        info_layout.addRow("Nivel de riesgo:", QLabel(nivel))
        
        info_group.setLayout(info_layout)
        layout.addWidget(info_group)
        
        # Mensaje detallado
        msg_group = QGroupBox("Descripción")
        msg_layout = QVBoxLayout()
        
        msg_text = QTextEdit()
        msg_text.setReadOnly(True)
        msg_text.setPlainText(mensaje)
        msg_layout.addWidget(msg_text)
        
        msg_group.setLayout(msg_layout)
        layout.addWidget(msg_group)
        
        # Acciones
        action_layout = QHBoxLayout()
        
        # Botón para bloquear IP si no está bloqueada
        self.block_btn = QPushButton("Bloquear IP")
        self.block_btn.setIcon(QIcon(get_icon_path("block")))
        
        # Verificar si la IP ya está bloqueada
        if alert_manager.is_ip_blocked(ip):
            self.block_btn.setText("Desbloquear IP")
            self.block_btn.clicked.connect(lambda: self.unblock_ip(ip))
        else:
            self.block_btn.clicked.connect(lambda: self.block_ip(ip))
            
        action_layout.addWidget(self.block_btn)
        
        # Botón para cerrar
        close_btn = QPushButton("Cerrar")
        close_btn.clicked.connect(self.accept)
        action_layout.addWidget(close_btn)
        
        layout.addLayout(action_layout)
        
    def block_ip(self, ip):
        """Bloquea la dirección IP"""
        if alert_manager.block_ip(ip):
            QMessageBox.information(self, "IP Bloqueada", 
                                 f"La dirección IP {ip} ha sido bloqueada exitosamente.")
            self.block_btn.setText("Desbloquear IP")
            self.block_btn.clicked.disconnect()
            self.block_btn.clicked.connect(lambda: self.unblock_ip(ip))
        else:
            QMessageBox.warning(self, "Error", 
                               f"No se pudo bloquear la dirección IP {ip}.")
    
    def unblock_ip(self, ip):
        """Desbloquea la dirección IP"""
        if alert_manager.unblock_ip(ip):
            QMessageBox.information(self, "IP Desbloqueada", 
                                 f"La dirección IP {ip} ha sido desbloqueada exitosamente.")
            self.block_btn.setText("Bloquear IP")
            self.block_btn.clicked.disconnect()
            self.block_btn.clicked.connect(lambda: self.block_ip(ip))
        else:
            QMessageBox.warning(self, "Error", 
                               f"No se pudo desbloquear la dirección IP {ip}.")

class BlockIPDialog(QDialog):
    """Diálogo para bloquear una nueva IP manualmente"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()
        
    def setup_ui(self):
        """Configura la interfaz del diálogo"""
        self.setWindowTitle("Bloquear Dirección IP")
        self.setMinimumWidth(350)
        
        layout = QVBoxLayout(self)
        
        form_layout = QFormLayout()
        
        self.ip_input = QLineEdit()
        self.ip_input.setPlaceholderText("Ingrese dirección IP (ej: 192.168.1.1)")
        form_layout.addRow("Dirección IP:", self.ip_input)
        
        self.motivo_input = QLineEdit()
        self.motivo_input.setPlaceholderText("Motivo del bloqueo")
        form_layout.addRow("Motivo:", self.motivo_input)
        
        layout.addLayout(form_layout)
        
        # Botones
        button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        button_box.accepted.connect(self.accept)
        button_box.rejected.connect(self.reject)
        layout.addWidget(button_box)
        
    def get_data(self):
        """Retorna los datos ingresados"""
        return {
            'ip': self.ip_input.text().strip(),
            'motivo': self.motivo_input.text().strip()
        }

class AlertsManagerView(QWidget):
    """Vista para la gestión de alertas de seguridad"""
    
    alertsUpdated = pyqtSignal()
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()
        
        # Registrar callback para nuevas alertas
        alert_manager.register_alert_callback(self.on_new_alert)
        
        # Temporizador para actualizar la vista
        self.update_timer = QTimer()
        self.update_timer.setInterval(5000)  # 5 segundos
        self.update_timer.timeout.connect(self.refresh_alerts)
        self.update_timer.start()
        
        # Cargar datos iniciales
        self.refresh_alerts()
        self.refresh_blocked_ips()
        
    def setup_ui(self):
        """Configura la interfaz de usuario"""
        main_layout = QVBoxLayout(self)
        
        # Título
        title_label = QLabel("<h2>Gestión de Seguridad</h2>")
        title_label.setAlignment(Qt.AlignCenter)
        main_layout.addWidget(title_label)
        
        # Splitter principal
        splitter = QSplitter(Qt.Vertical)
        main_layout.addWidget(splitter)
        
        # Grupo de alertas
        alerts_group = QGroupBox("Alertas de Seguridad")
        alerts_layout = QVBoxLayout()
        
        # Tabla de alertas
        self.alerts_table = QTableWidget()
        self.alerts_table.setColumnCount(6)
        self.alerts_table.setHorizontalHeaderLabels(["Fecha/Hora", "Tipo", "IP", "SO", "Nivel", "Mensaje"])
        self.alerts_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.alerts_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.alerts_table.horizontalHeader().setSectionResizeMode(5, QHeaderView.Stretch)
        self.alerts_table.horizontalHeader().setStretchLastSection(True)
        self.alerts_table.doubleClicked.connect(self.show_alert_details)
        alerts_layout.addWidget(self.alerts_table)
        
        # Botones de alertas
        alerts_button_layout = QHBoxLayout()
        
        refresh_alerts_btn = QPushButton("Actualizar")
        refresh_alerts_btn.setIcon(QIcon(get_icon_path("refresh")))
        refresh_alerts_btn.clicked.connect(self.refresh_alerts)
        alerts_button_layout.addWidget(refresh_alerts_btn)
        
        clear_alerts_btn = QPushButton("Limpiar Alertas")
        clear_alerts_btn.clicked.connect(self.clear_alerts)
        alerts_button_layout.addWidget(clear_alerts_btn)
        
        config_messages_btn = QPushButton("Configurar Mensajes")
        config_messages_btn.clicked.connect(self.show_message_config)
        alerts_button_layout.addWidget(config_messages_btn)
        
        alerts_layout.addLayout(alerts_button_layout)
        alerts_group.setLayout(alerts_layout)
        
        # Grupo de IPs bloqueadas
        blocked_group = QGroupBox("IPs Bloqueadas")
        blocked_layout = QVBoxLayout()
        
        # Tabla de IPs bloqueadas
        self.blocked_table = QTableWidget()
        self.blocked_table.setColumnCount(1)
        self.blocked_table.setHorizontalHeaderLabels(["Dirección IP"])
        self.blocked_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.blocked_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.blocked_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        blocked_layout.addWidget(self.blocked_table)
        
        # Botones de IPs bloqueadas
        blocked_button_layout = QHBoxLayout()
        
        block_ip_btn = QPushButton("Bloquear IP")
        block_ip_btn.setIcon(QIcon(get_icon_path("block")))
        block_ip_btn.clicked.connect(self.show_block_ip_dialog)
        blocked_button_layout.addWidget(block_ip_btn)
        
        unblock_ip_btn = QPushButton("Desbloquear Seleccionada")
        unblock_ip_btn.clicked.connect(self.unblock_selected_ip)
        blocked_button_layout.addWidget(unblock_ip_btn)
        
        refresh_blocked_btn = QPushButton("Actualizar")
        refresh_blocked_btn.setIcon(QIcon(get_icon_path("refresh")))
        refresh_blocked_btn.clicked.connect(self.refresh_blocked_ips)
        blocked_button_layout.addWidget(refresh_blocked_btn)
        
        blocked_layout.addLayout(blocked_button_layout)
        blocked_group.setLayout(blocked_layout)
        
        # Agregar grupos al splitter
        splitter.addWidget(alerts_group)
        splitter.addWidget(blocked_group)
        
        # Configurar tamaños relativos
        splitter.setSizes([200, 100])
        
    def refresh_alerts(self):
        """Actualiza la lista de alertas"""
        alerts = alert_manager.get_alerts()
        
        self.alerts_table.setRowCount(len(alerts))
        
        for i, alert in enumerate(alerts):
            # Timestamp
            timestamp_item = QTableWidgetItem(alert['timestamp'].strftime("%d/%m/%Y %H:%M:%S"))
            self.alerts_table.setItem(i, 0, timestamp_item)
            
            # Tipo
            type_item = QTableWidgetItem(alert['tipo'])
            self.alerts_table.setItem(i, 1, type_item)
            
            # IP
            ip_item = QTableWidgetItem(alert['ip'])
            self.alerts_table.setItem(i, 2, ip_item)
            
            # Sistema Operativo
            os_type = alert.get('os_type', 'Desconocido')
            os_item = QTableWidgetItem(os_type)
            self.alerts_table.setItem(i, 3, os_item)
            
            # Nivel de riesgo
            nivel = alert['nivel_riesgo']
            level_item = QTableWidgetItem(nivel)
            
            # Colorear según nivel
            if nivel == "Alto":
                level_item.setForeground(QBrush(QColor(255, 77, 77)))
                level_item.setFont(QFont("", -1, QFont.Bold))
            elif nivel == "Medio":
                level_item.setForeground(QBrush(QColor(255, 166, 77)))
            
            self.alerts_table.setItem(i, 4, level_item)
            
            # Mensaje
            msg_item = QTableWidgetItem(alert['mensaje'])
            self.alerts_table.setItem(i, 5, msg_item)
        
        self.alerts_table.resizeColumnsToContents()
        self.alertsUpdated.emit()
        
    def refresh_blocked_ips(self):
        """Actualiza la lista de IPs bloqueadas"""
        blocked_ips = alert_manager.get_blocked_ips()
        
        self.blocked_table.setRowCount(len(blocked_ips))
        
        for i, ip in enumerate(blocked_ips):
            ip_item = QTableWidgetItem(ip)
            self.blocked_table.setItem(i, 0, ip_item)
            
    def show_alert_details(self):
        """Muestra los detalles de la alerta seleccionada"""
        selected_rows = self.alerts_table.selectionModel().selectedRows()
        if not selected_rows:
            return
            
        row = selected_rows[0].row()
        alerts = alert_manager.get_alerts()
        
        if row < len(alerts):
            alerta = alerts[row]
            dialog = AlertDialog(alerta, self)
            result = dialog.exec_()
            
            # Actualizar vistas después de cerrar el diálogo
            if result == QDialog.Accepted:
                self.refresh_alerts()
                self.refresh_blocked_ips()
                
    def show_block_ip_dialog(self):
        """Muestra el diálogo para bloquear una IP"""
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
                self.refresh_blocked_ips()
                self.refresh_alerts()
                QMessageBox.information(self, "IP Bloqueada", 
                                      f"La dirección IP {ip} ha sido bloqueada exitosamente.")
            else:
                QMessageBox.warning(self, "Error", 
                                 f"No se pudo bloquear la dirección IP {ip}.")
                
    def unblock_selected_ip(self):
        """Desbloquea la IP seleccionada"""
        selected_rows = self.blocked_table.selectionModel().selectedRows()
        if not selected_rows:
            QMessageBox.warning(self, "Selección requerida", 
                             "Debe seleccionar una IP para desbloquear")
            return
            
        row = selected_rows[0].row()
        ip = self.blocked_table.item(row, 0).text()
        
        reply = QMessageBox.question(self, "Confirmar desbloqueo", 
                                   f"¿Está seguro de desbloquear la IP {ip}?",
                                   QMessageBox.Yes | QMessageBox.No)
        
        if reply == QMessageBox.Yes:
            if alert_manager.unblock_ip(ip):
                self.refresh_blocked_ips()
                QMessageBox.information(self, "IP Desbloqueada", 
                                      f"La dirección IP {ip} ha sido desbloqueada exitosamente.")
            else:
                QMessageBox.warning(self, "Error", 
                                 f"No se pudo desbloquear la dirección IP {ip}.")
                
    def clear_alerts(self):
        """Limpia la lista de alertas"""
        reply = QMessageBox.question(self, "Confirmar", 
                                   "¿Está seguro de limpiar todas las alertas?",
                                   QMessageBox.Yes | QMessageBox.No)
        
        if reply == QMessageBox.Yes:
            alert_manager.alerts.clear()
            self.refresh_alerts()
    
    def show_message_config(self):
        """Muestra el diálogo de configuración de mensajes personalizados"""
        from gui.custom_message_dialog import CustomMessageDialog
        dialog = CustomMessageDialog(self)
        dialog.exec_()
        # No es necesario refrescar la vista ya que esto afecta solo a nuevas alertas
            
    def on_new_alert(self, alerta):
        """Callback llamado cuando se genera una nueva alerta"""
        # Actualizar la vista en la próxima actualización de UI
        QTimer.singleShot(100, self.refresh_alerts)
