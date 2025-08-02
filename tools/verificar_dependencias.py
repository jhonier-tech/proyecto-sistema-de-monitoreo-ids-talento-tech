#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Script para verificar que todas las dependencias de NetSniffer estén instaladas correctamente
"""

import sys
import os

def check_dependency(name):
    """Verifica si una dependencia está instalada"""
    print(f"Verificando {name}...", end=" ")
    try:
        __import__(name)
        print("✓ Instalado correctamente")
        return True
    except ImportError as e:
        print(f"✗ No instalado: {e}")
        return False

def main():
    """Función principal para verificar dependencias"""
    print("="*70)
    print("      Verificación de dependencias para NetSniffer")
    print("="*70)
    print()
    
    # Lista de dependencias a verificar
    dependencies = {
        "scapy": "Biblioteca para manipulación de paquetes de red",
        "PyQt5": "Framework de interfaz gráfica",
        "pyqtgraph": "Biblioteca de visualización de datos para PyQt5",
        "colorama": "Biblioteca para salida de texto con colores",
        "psutil": "Biblioteca para información del sistema y procesos",
        "netifaces": "Biblioteca para información de interfaces de red",
        "matplotlib": "Biblioteca de visualización de datos",
        "pandas": "Biblioteca de análisis de datos"
    }
    
    # Verificar cada dependencia
    missing = []
    for dep_name, description in dependencies.items():
        print(f"{dep_name}: {description}")
        if not check_dependency(dep_name):
            missing.append(dep_name)
        print()
    
    # Mostrar resultados
    print("="*70)
    if not missing:
        print("✓ Todas las dependencias están instaladas correctamente.")
        print("  NetSniffer debería funcionar sin problemas de dependencias.")
    else:
        print(f"✗ Faltan {len(missing)} dependencias:")
        for dep in missing:
            print(f"  - {dep}")
        print("\nPuede instalarlas con estos comandos:")
        for dep in missing:
            print(f"  pip install {dep}")
    
    # Verificar Npcap (crucial para Windows)
    import platform
    if platform.system() == "Windows":
        print("\n=== Verificando Npcap (requerido para captura en Windows) ===")
        if os.path.exists("C:\\Windows\\System32\\Npcap"):
            print("✓ Npcap parece estar instalado (directorio encontrado)")
        else:
            print("✗ Npcap no está instalado o no se encuentra en la ruta esperada")
            print("  Descargue e instale Npcap desde: https://npcap.com")
    
    print("\nSi todo está instalado pero NetSniffer sigue fallando:")
    print("1. Asegúrese de ejecutar como administrador")
    print("2. Verifique la selección de interfaz de red correcta")
    print("3. Intente reinstalar Npcap (crucial para la captura de paquetes)")
    print("="*70)
    
    return 0 if not missing else 1

if __name__ == "__main__":
    sys.exit(main())
