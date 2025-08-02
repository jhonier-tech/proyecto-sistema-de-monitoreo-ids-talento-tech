#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Módulo para el diálogo Acerca de
"""

from PyQt5.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout, QLabel, 
                           QPushButton, QTabWidget, QWidget, QTextBrowser)
from PyQt5.QtGui import QIcon, QPixmap, QFont
from PyQt5.QtCore import Qt, QSize

from utils.icons import get_icon_path

class AboutDialog(QDialog):
    """Diálogo para mostrar información sobre la aplicación"""
    
    def __init__(self, parent=None):
        """Inicializa el diálogo Acerca de
        
        Args:
            parent: Widget padre
        """
        super().__init__(parent)
        
        # Configurar ventana
        self.setWindowTitle("Acerca del Sistema de monitoreo IDS")
        self.setWindowIcon(QIcon(get_icon_path("about")))
        self.resize(500, 400)
        
        # Configurar interfaz
        self.setup_ui()
        
    def setup_ui(self):
        """Configura la interfaz de usuario"""
        # Layout principal
        layout = QVBoxLayout(self)
        
        # Cabecera
        header_layout = QHBoxLayout()
        
        # Logo
        logo_label = QLabel()
        logo_path = get_icon_path("app_icon")
        
        # Intentar cargar el icono como .ico primero
        logo_pixmap = QPixmap(logo_path)
        
        # Si el icono se cargó correctamente y no está vacío
        if logo_pixmap and not logo_pixmap.isNull():
            logo_label.setPixmap(logo_pixmap.scaled(64, 64, Qt.KeepAspectRatio, Qt.SmoothTransformation))
        else:
            # Logo de fallback (texto)
            logo_label.setText("🔍")
            logo_label.setFont(QFont("Arial", 32))
            
        header_layout.addWidget(logo_label)
        
        # Información básica
        info_layout = QVBoxLayout()
        
        title_label = QLabel("Sistema de monitoreo IDS")
        title_label.setFont(QFont("Arial", 16, QFont.Bold))
        info_layout.addWidget(title_label)
        
        version_label = QLabel("Versión 1.0.0")
        info_layout.addWidget(version_label)
        
        desc_label = QLabel("Analizador de paquetes de red con interfaz gráfica")
        info_layout.addWidget(desc_label)
        
        copyright_label = QLabel("© 2025")
        copyright_label.setFont(QFont("Arial", 8))
        info_layout.addWidget(copyright_label)
        
        header_layout.addLayout(info_layout)
        header_layout.addStretch()
        
        layout.addLayout(header_layout)
        
        # Pestañas de información
        tab_widget = QTabWidget()
        
        # Pestaña "Acerca de"
        about_tab = QWidget()
        about_layout = QVBoxLayout(about_tab)
        
        about_text = QTextBrowser()
        about_text.setOpenExternalLinks(True)
        about_text.setHtml("""
            <p>Sistema de monitoreo IDS es un analizador de paquetes de red con interfaz gráfica,
            inspirado en Wireshark, desarrollado en Python.</p>
            
            <p>Características principales:</p>
            <ul>
                <li>Captura de paquetes de red en tiempo real</li>
                <li>Análisis detallado de protocolos</li>
                <li>Interfaz gráfica intuitiva y atractiva</li>
                <li>Filtrado de paquetes</li>
                <li>Visualización gráfica de tráfico de red</li>
                <li>Estadísticas en tiempo real</li>
            </ul>
            
            <p>Esta aplicación es software libre y de código abierto.</p>
        """)
        about_layout.addWidget(about_text)
        
        tab_widget.addTab(about_tab, "Acerca de")
        
        # Pestaña "Autores"
        authors_tab = QWidget()
        authors_layout = QVBoxLayout(authors_tab)
        
        authors_text = QTextBrowser()
        authors_text.setOpenExternalLinks(True)
        authors_text.setHtml("""
            <p><b>Desarrolladores:</b></p>
            <ul>
                <li>Equipo de desarrollo</li>
            </ul>
            
            <p><b>Agradecimientos:</b></p>
            <ul>
                <li>Proyecto Scapy - <a href="https://scapy.net/">https://scapy.net/</a></li>
                <li>Proyecto PyQt - <a href="https://riverbankcomputing.com/software/pyqt/">https://riverbankcomputing.com/software/pyqt/</a></li>
                <li>Proyecto Wireshark - <a href="https://www.wireshark.org/">https://www.wireshark.org/</a></li>
            </ul>
        """)
        authors_layout.addWidget(authors_text)
        
        tab_widget.addTab(authors_tab, "Autores")
        
        # Pestaña "Licencia"
        license_tab = QWidget()
        license_layout = QVBoxLayout(license_tab)
        
        license_text = QTextBrowser()
        license_text.setHtml("""
            <p><b>Licencia de Software Libre</b></p>
            
            <p>Este programa es software libre: puede redistribuirlo y/o modificarlo bajo los 
            términos de la Licencia Pública General GNU publicada por la Free Software 
            Foundation, ya sea la versión 3 de la Licencia, o (a su elección) cualquier 
            versión posterior.</p>
            
            <p>Este programa se distribuye con la esperanza de que sea útil, pero SIN NINGUNA 
            GARANTÍA; sin siquiera la garantía implícita de COMERCIABILIDAD o APTITUD PARA UN 
            PROPÓSITO PARTICULAR. Consulte la Licencia Pública General GNU para más detalles.</p>
        """)
        license_layout.addWidget(license_text)
        
        tab_widget.addTab(license_tab, "Licencia")
        
        # Pestaña "Bibliotecas"
        libraries_tab = QWidget()
        libraries_layout = QVBoxLayout(libraries_tab)
        
        libraries_text = QTextBrowser()
        libraries_text.setOpenExternalLinks(True)
        libraries_text.setHtml("""
            <p><b>Bibliotecas utilizadas:</b></p>
            <ul>
                <li>Python 3.8+</li>
                <li>Scapy - Biblioteca para manipulación de paquetes de red</li>
                <li>PyQt5 - Interfaz gráfica</li>
                <li>PyQtGraph - Visualización de datos</li>
                <li>Matplotlib - Gráficos y visualizaciones</li>
                <li>Pandas - Análisis de datos</li>
                <li>NumPy - Computación científica</li>
            </ul>
        """)
        libraries_layout.addWidget(libraries_text)
        
        tab_widget.addTab(libraries_tab, "Bibliotecas")
        
        layout.addWidget(tab_widget)
        
        # Botón Cerrar
        button_layout = QHBoxLayout()
        button_layout.addStretch()
        
        close_button = QPushButton("Cerrar")
        close_button.setDefault(True)
        close_button.clicked.connect(self.accept)
        button_layout.addWidget(close_button)
        
        layout.addLayout(button_layout)
