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
                self.statusBar().showMessage(f"Capturando en {self.current_interface_full}: {self.capture_count} paquetes")
                QApplication.processEvents()  # Permitir que la interfaz se actualice
                
        except Exception as e:
            logging.error(f"Error en procesamiento por lotes: {e}")
