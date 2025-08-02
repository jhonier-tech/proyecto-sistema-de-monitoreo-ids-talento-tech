    @staticmethod
    def get_available_interfaces():
        """Obtiene una lista de interfaces de red disponibles
        
        Returns:
            list: Lista de nombres de interfaces disponibles
        """
        import logging
        
        # Implementar caché para reducir el tiempo de obtención de interfaces
        from functools import lru_cache
        import time
        
        @lru_cache(maxsize=1)
        def _cached_interfaces(timestamp):
            """Obtener interfaces con caché para mejorar rendimiento
            El parámetro timestamp se usa para invalidar la caché periódicamente
            """
            interfaces = []
            
            try:
                # Método 1: Obtener interfaces de Scapy
                for iface in conf.ifaces.values():
                    iface_info = {
                        'name': iface.name,
                        'description': iface.description if hasattr(iface, 'description') else '',
                        'mac': iface.mac if hasattr(iface, 'mac') else '',
                        'ip': iface.ip if hasattr(iface, 'ip') else ''
                    }
                    
                    logging.info(f"Interfaz detectada con Scapy: {iface_info['name']} - {iface_info['description']}")
                    interfaces.append(iface_info)
                
                # Método 2: Usar netifaces si no se encontraron interfaces con Scapy
                if not interfaces:
                    try:
                        import netifaces
                        logging.info("Intentando obtener interfaces con netifaces")
                        
                        for iface_name in netifaces.interfaces():
                            try:
                                addrs = netifaces.ifaddresses(iface_name)
                                
                                # Obtener dirección MAC
                                mac = ''
                                if netifaces.AF_LINK in addrs and addrs[netifaces.AF_LINK]:
                                    mac = addrs[netifaces.AF_LINK][0].get('addr', '')
                                
                                # Obtener dirección IP
                                ip = ''
                                if netifaces.AF_INET in addrs and addrs[netifaces.AF_INET]:
                                    ip = addrs[netifaces.AF_INET][0].get('addr', '')
                                    
                                interfaces.append({
                                    'name': iface_name,
                                    'description': f'Interfaz {iface_name}',
                                    'mac': mac,
                                    'ip': ip
                                })
                                logging.info(f"Interfaz detectada con netifaces: {iface_name} - IP: {ip}")
                            except Exception as e:
                                logging.error(f"Error con interfaz {iface_name}: {e}")
                    except ImportError:
                        logging.warning("No se pudo importar netifaces, usando método alternativo")
                
                # Método 3: Usar ipconfig/ifconfig como alternativa si no se han encontrado interfaces
                if not interfaces:
                    try:
                        import subprocess
                        import re
                        import platform
                        
                        if platform.system() == "Windows":
                            # Ejecutar ipconfig y capturar su salida
                            proc = subprocess.Popen("ipconfig /all", shell=True, stdout=subprocess.PIPE)
                            output = proc.stdout.read().decode('latin-1', errors='ignore')
                            
                            # Buscar interfaces con patrón simple
                            iface_blocks = re.split(r'\r?\n\r?\n', output)
                            for block in iface_blocks:
                                if not block.strip():
                                    continue
                                    
                                name_match = re.search(r'Adaptador.*: (.*?):', block)
                                if name_match:
                                    iface_name = name_match.group(1).strip()
                                    
                                    # Buscar MAC e IP
                                    mac_match = re.search(r'Direcci.n f.sica.*: (.*?)[\r\n]', block)
                                    mac = mac_match.group(1).strip() if mac_match else ''
                                    
                                    ip_match = re.search(r'Direcci.n IPv4.*: (.*?)[\r\n]', block)
                                    ip = ip_match.group(1).strip() if ip_match else ''
                                    
                                    if mac or ip:  # Solo agregar si tiene al menos MAC o IP
                                        interfaces.append({
                                            'name': iface_name,
                                            'description': f'Adaptador {iface_name}',
                                            'mac': mac,
                                            'ip': ip
                                        })
                                        logging.info(f"Interfaz detectada con ipconfig: {iface_name} - IP: {ip}")
                        else:
                            # En sistemas Unix/Linux, usar ifconfig
                            proc = subprocess.Popen("ifconfig -a", shell=True, stdout=subprocess.PIPE)
                            output = proc.stdout.read().decode('utf-8', errors='ignore')
                            
                            # Análisis simple de la salida de ifconfig
                            iface_blocks = re.split(r'\n(?=\w)', output)
                            for block in iface_blocks:
                                if not block.strip():
                                    continue
                                
                                name_match = re.search(r'^(\w+):', block)
                                if name_match:
                                    iface_name = name_match.group(1)
                                    
                                    # Buscar MAC e IP
                                    mac_match = re.search(r'ether (\S+)', block)
                                    mac = mac_match.group(1) if mac_match else ''
                                    
                                    ip_match = re.search(r'inet (\S+)', block)
                                    ip = ip_match.group(1) if ip_match else ''
                                    
                                    if mac or ip:
                                        interfaces.append({
                                            'name': iface_name,
                                            'description': f'Interfaz {iface_name}',
                                            'mac': mac,
                                            'ip': ip
                                        })
                                        logging.info(f"Interfaz detectada con ifconfig: {iface_name} - IP: {ip}")
                    except Exception as e:
                        logging.error(f"Error al usar método alternativo para detectar interfaces: {e}")
                
                logging.info(f"Total de interfaces detectadas: {len(interfaces)}")
                return interfaces
                
            except Exception as e:
                logging.error(f"Error al obtener interfaces: {e}")
                import traceback
                logging.error(traceback.format_exc())
                return []
        
        # Usar el timestamp actual redondeado a 5 minutos para permitir una actualización cada 5 minutos como máximo
        current_5min = int(time.time() / 300)
        return _cached_interfaces(current_5min)
