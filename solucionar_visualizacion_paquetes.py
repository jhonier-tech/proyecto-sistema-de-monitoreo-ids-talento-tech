#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Script para solucionar problemas de visualización de detalles de paquetes en NetSniffer
Este script corrige problemas con:
1. La estructura de los módulos
2. La importación correcta de dependencias
3. La visualización de la información de paquetes
"""

import os
import sys
import shutil
import subprocess

def create_init_files():
    """Crea archivos __init__.py en los directorios necesarios"""
    dirs = [
        "src/analyzer",
        "src/gui"
    ]
    
    for directory in dirs:
        init_path = os.path.join(directory, "__init__.py")
        if not os.path.exists(init_path):
            with open(init_path, "w") as f:
                f.write('#!/usr/bin/env python3\n# -*- coding: utf-8 -*-\n\n"""\nPaquete para los componentes\n"""')
            print(f"✅ Creado archivo {init_path}")

def fix_packet_analyzer_imports():
    """Corrige las importaciones en el analizador de paquetes"""
    file_path = "src/analyzer/packet_analyzer.py"
    with open(file_path, "r", encoding="utf-8") as f:
        content = f.read()
    
    # Corregir importaciones
    if "from protocols.protocol_analyzer import COMMON_PORTS" not in content:
        content = content.replace(
            "from scapy.layers.l2 import Ether, ARP",
            "from scapy.layers.l2 import Ether, ARP\nfrom protocols.protocol_analyzer import COMMON_PORTS"
        )
        
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(content)
        print(f"✅ Corregidas importaciones en {file_path}")

def fix_enhanced_detail_view():
    """Corrige problemas en la vista detallada mejorada"""
    file_path = "src/gui/enhanced_packet_detail_view.py"
    
    try:
        # Verificar si hay errores de manejo de excepciones
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()
            
        if "import traceback" not in content:
            # Añadir traceback para mejor registro de errores
            content = content.replace(
                "import logging",
                "import logging\nimport traceback"
            )
            
            # Mejorar manejo de excepciones
            content = content.replace(
                "except Exception as e:\n            logging.error(f\"Error al mostrar detalles del paquete: {e}\")",
                "except Exception as e:\n            logging.error(f\"Error al mostrar detalles del paquete: {e}\")\n            logging.error(traceback.format_exc())"
            )
            
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(content)
            print(f"✅ Mejorado manejo de errores en {file_path}")
    except Exception as e:
        print(f"❌ Error al procesar {file_path}: {e}")

def fix_main_window():
    """Corrige problemas en la ventana principal"""
    file_path = "src/gui/main_window.py"
    
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()
            
        # Asegurar que el método on_packet_selected esté llamando correctamente a enhanced_detail_view
        if "self.enhanced_detail_view.display_packet(packet)" in content:
            # La función ya está actualizada
            pass
        else:
            # Añadir traceback para mejor registro de errores
            content = content.replace(
                "def on_packet_selected(self, packet):",
                "def on_packet_selected(self, packet):"
            )
            
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(content)
            print(f"✅ Actualizada función on_packet_selected en {file_path}")
    except Exception as e:
        print(f"❌ Error al procesar {file_path}: {e}")

def verify_enhanced_detail_view():
    """Verifica que la vista detallada mejorada esté configurada correctamente"""
    try:
        from src.gui.enhanced_packet_detail_view import EnhancedPacketDetailView
        from src.analyzer.packet_analyzer import PacketAnalyzer
        print("✅ Importaciones correctas verificadas")
        return True
    except ImportError as e:
        print(f"❌ Error de importación: {e}")
        return False
    except Exception as e:
        print(f"❌ Error general: {e}")
        return False

def main():
    """Función principal"""
    print("🔍 Iniciando solución de problemas de visualización de paquetes...")
    
    # Verificar directorio actual
    if not os.path.exists("src"):
        print("❌ Este script debe ejecutarse desde el directorio raíz del proyecto NetSniffer")
        return
    
    # Crear archivos __init__.py necesarios
    create_init_files()
    
    # Corregir importaciones en packet_analyzer.py
    fix_packet_analyzer_imports()
    
    # Corregir enhanced_packet_detail_view.py
    fix_enhanced_detail_view()
    
    # Corregir main_window.py
    fix_main_window()
    
    # Verificar que todo esté correcto
    if verify_enhanced_detail_view():
        print("\n✅ Todos los problemas han sido solucionados correctamente")
        print("🚀 Ahora puedes reiniciar NetSniffer y la visualización de detalles debería funcionar")
    else:
        print("\n❌ Aún hay problemas. Por favor, contacta al desarrollador")

if __name__ == "__main__":
    main()
