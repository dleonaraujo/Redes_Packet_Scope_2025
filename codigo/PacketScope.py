#!/usr/bin/env python3
"""
PacketScope - Analizador y Visualizador de Tráfico LAN
Herramienta para capturar y analizar tráfico de red en tiempo real
"""

import sys
import os
import time
import threading
from datetime import datetime
from collections import defaultdict, Counter
from typing import Dict, List, Optional, Tuple
import json

# Verificar e instalar dependencias
try:
    from scapy.all import *
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.inet6 import IPv6
    from scapy.layers.l2 import Ether, ARP
    from scapy.utils import wrpcap, rdpcap
except ImportError:
    print("Error: Scapy no está instalado. Instala con: pip install scapy")
    sys.exit(1)

try:
    from PySide6.QtWidgets import *
    from PySide6.QtCore import *
    from PySide6.QtGui import *
except ImportError:
    print("Error: PySide6 no está instalado. Instala con: pip install PySide6")
    sys.exit(1)

class PacketCapture(QObject):
    """Clase para manejar la captura de paquetes"""
    
    packet_captured = Signal(object)
    error_occurred = Signal(str)
    packets_batch = Signal(list)  # Nueva señal para lotes de paquetes
    
    def __init__(self):
        super().__init__()
        self.interface = None
        self.is_capturing = False
        self.capture_thread = None
        self.packets = []
        self.packet_filter = ""
        self.packet_buffer = []  # Buffer para acumular paquetes
        self.buffer_timer = QTimer()
        self.buffer_timer.timeout.connect(self.flush_buffer)
        self.buffer_timer.start(500)  # Procesar cada 500ms
        self.max_packets = 10000  # Límite máximo de paquetes en memoria
        
    def start_capture(self, interface: str, packet_filter: str = ""):
        """Iniciar captura de paquetes"""
        if self.is_capturing:
            return
            
        self.interface = interface
        self.packet_filter = packet_filter
        self.is_capturing = True
        
        # Iniciar captura en hilo separado
        self.capture_thread = threading.Thread(target=self._capture_packets)
        self.capture_thread.daemon = True
        self.capture_thread.start()
        
    def stop_capture(self):
        """Detener captura de paquetes"""
        self.is_capturing = False
        if self.capture_thread:
            self.capture_thread.join(timeout=2)
            
    def _capture_packets(self):
        """Función de captura que ejecuta en hilo separado"""
        try:
            def packet_handler(packet):
                if self.is_capturing:
                    # Añadir al buffer en lugar de procesar inmediatamente
                    self.packet_buffer.append(packet)
                    
                    # Limitar memoria - eliminar paquetes antiguos si hay demasiados
                    if len(self.packets) > self.max_packets:
                        self.packets = self.packets[-self.max_packets//2:]  # Mantener la mitad más reciente
                    
            # Configurar filtro BPF si se especifica
            filter_str = self.packet_filter if self.packet_filter else None
            
            sniff(
                iface=self.interface,
                prn=packet_handler,
                stop_filter=lambda x: not self.is_capturing,
                filter=filter_str,
                store=0  # No almacenar en memoria de Scapy
            )
        except Exception as e:
            self.error_occurred.emit(f"Error en captura: {str(e)}")
            
    def flush_buffer(self):
        """Procesar paquetes del buffer de forma controlada"""
        if not self.packet_buffer:
            return
            
        # Procesar máximo 50 paquetes por vez para no trabar la GUI
        batch_size = min(50, len(self.packet_buffer))
        current_batch = self.packet_buffer[:batch_size]
        self.packet_buffer = self.packet_buffer[batch_size:]
        
        # Añadir a la lista principal
        self.packets.extend(current_batch)
        
        # Emitir señal con el lote
        self.packets_batch.emit(current_batch)
            
    def save_packets(self, filename: str):
        """Guardar paquetes capturados en formato PCAP"""
        if self.packets:
            wrpcap(filename, self.packets)
            
    def load_packets(self, filename: str):
        """Cargar paquetes desde archivo PCAP"""
        try:
            self.packets = rdpcap(filename)
            for packet in self.packets:
                self.packet_captured.emit(packet)
        except Exception as e:
            self.error_occurred.emit(f"Error cargando archivo: {str(e)}")

class ProtocolDecoder:
    """Decodificador de protocolos"""
    
    @staticmethod
    def decode_packet(packet) -> Dict:
        """Decodificar paquete y extraer información"""
        info = {
            'timestamp': datetime.now().strftime('%H:%M:%S.%f')[:-3],
            'length': len(packet),
            'protocols': [],
            'src': '',
            'dst': '',
            'info': '',
            'details': {}
        }
        
        # Analizar capa Ethernet
        if packet.haslayer(Ether):
            eth = packet[Ether]
            info['protocols'].append('Ethernet')
            info['details']['Ethernet'] = {
                'src': eth.src,
                'dst': eth.dst,
                'type': hex(eth.type)
            }
            
        # Analizar ARP
        if packet.haslayer(ARP):
            arp = packet[ARP]
            info['protocols'].append('ARP')
            info['src'] = arp.psrc
            info['dst'] = arp.pdst
            info['info'] = f"ARP {'Request' if arp.op == 1 else 'Reply'}"
            info['details']['ARP'] = {
                'op': arp.op,
                'hwsrc': arp.hwsrc,
                'hwdst': arp.hwdst,
                'psrc': arp.psrc,
                'pdst': arp.pdst
            }
            
        # Analizar IPv4
        if packet.haslayer(IP):
            ip = packet[IP]
            info['protocols'].append('IPv4')
            info['src'] = ip.src
            info['dst'] = ip.dst
            info['details']['IPv4'] = {
                'version': ip.version,
                'ihl': ip.ihl,
                'tos': ip.tos,
                'len': ip.len,
                'id': ip.id,
                'flags': ip.flags,
                'frag': ip.frag,
                'ttl': ip.ttl,
                'proto': ip.proto,
                'chksum': ip.chksum,
                'src': ip.src,
                'dst': ip.dst
            }
            
        # Analizar IPv6
        if packet.haslayer(IPv6):
            ipv6 = packet[IPv6]
            info['protocols'].append('IPv6')
            info['src'] = ipv6.src
            info['dst'] = ipv6.dst
            info['details']['IPv6'] = {
                'version': ipv6.version,
                'tc': ipv6.tc,
                'fl': ipv6.fl,
                'plen': ipv6.plen,
                'nh': ipv6.nh,
                'hlim': ipv6.hlim,
                'src': ipv6.src,
                'dst': ipv6.dst
            }
            
        # Analizar TCP
        if packet.haslayer(TCP):
            tcp = packet[TCP]
            info['protocols'].append('TCP')
            info['info'] = f"TCP {tcp.sport} → {tcp.dport}"
            info['details']['TCP'] = {
                'sport': tcp.sport,
                'dport': tcp.dport,
                'seq': tcp.seq,
                'ack': tcp.ack,
                'dataofs': tcp.dataofs,
                'reserved': tcp.reserved,
                'flags': tcp.flags,
                'window': tcp.window,
                'chksum': tcp.chksum,
                'urgptr': tcp.urgptr
            }
            
        # Analizar UDP
        if packet.haslayer(UDP):
            udp = packet[UDP]
            info['protocols'].append('UDP')
            info['info'] = f"UDP {udp.sport} → {udp.dport}"
            info['details']['UDP'] = {
                'sport': udp.sport,
                'dport': udp.dport,
                'len': udp.len,
                'chksum': udp.chksum
            }
            
        # Analizar ICMP
        if packet.haslayer(ICMP):
            icmp = packet[ICMP]
            info['protocols'].append('ICMP')
            info['info'] = f"ICMP Type {icmp.type}"
            info['details']['ICMP'] = {
                'type': icmp.type,
                'code': icmp.code,
                'chksum': icmp.chksum,
                'id': icmp.id,
                'seq': icmp.seq
            }
            
        return info

class PacketTableModel(QAbstractTableModel):
    """Modelo de tabla para mostrar paquetes"""
    
    def __init__(self):
        super().__init__()
        self.packets = []
        self.headers = ['#', 'Tiempo', 'Origen', 'Destino', 'Protocolo', 'Longitud', 'Info']
        self.max_display_packets = 5000  # Límite para mostrar en tabla
        
    def rowCount(self, parent=QModelIndex()):
        return len(self.packets)
        
    def columnCount(self, parent=QModelIndex()):
        return len(self.headers)
        
    def data(self, index, role=Qt.DisplayRole):
        if not index.isValid() or index.row() >= len(self.packets):
            return None
            
        packet_info = self.packets[index.row()]
        
        if role == Qt.DisplayRole:
            col = index.column()
            if col == 0:  # Número
                return index.row() + 1
            elif col == 1:  # Tiempo
                return packet_info['timestamp']
            elif col == 2:  # Origen
                return packet_info['src']
            elif col == 3:  # Destino
                return packet_info['dst']
            elif col == 4:  # Protocolo
                return ' / '.join(packet_info['protocols'])
            elif col == 5:  # Longitud
                return packet_info['length']
            elif col == 6:  # Info
                return packet_info['info']
                
        return None
        
    def headerData(self, section, orientation, role=Qt.DisplayRole):
        if orientation == Qt.Horizontal and role == Qt.DisplayRole:
            return self.headers[section]
        return None
        
    def add_packet(self, packet_info):
        self.beginInsertRows(QModelIndex(), len(self.packets), len(self.packets))
        self.packets.append(packet_info)
        self.endInsertRows()
        
        # Limitar paquetes mostrados para mantener rendimiento
        if len(self.packets) > self.max_display_packets:
            excess = len(self.packets) - self.max_display_packets
            self.beginRemoveRows(QModelIndex(), 0, excess - 1)
            self.packets = self.packets[excess:]
            self.endRemoveRows()
        
    def add_packets_batch(self, packet_infos):
        """Añadir múltiples paquetes de una vez - más eficiente"""
        if not packet_infos:
            return
            
        start_row = len(self.packets)
        end_row = start_row + len(packet_infos) - 1
        
        self.beginInsertRows(QModelIndex(), start_row, end_row)
        self.packets.extend(packet_infos)
        self.endInsertRows()
        
        # Limitar paquetes mostrados
        if len(self.packets) > self.max_display_packets:
            excess = len(self.packets) - self.max_display_packets
            self.beginRemoveRows(QModelIndex(), 0, excess - 1)
            self.packets = self.packets[excess:]
            self.endRemoveRows()
        
    def clear(self):
        self.beginResetModel()
        self.packets.clear()
        self.endResetModel()

class ProtocolTreeWidget(QTreeWidget):
    """Widget para mostrar el árbol de protocolos"""
    
    def __init__(self):
        super().__init__()
        self.setHeaderLabel("Detalles del Protocolo")
        
    def display_packet(self, packet_info):
        """Mostrar detalles de un paquete"""
        self.clear()
        
        for protocol, details in packet_info['details'].items():
            protocol_item = QTreeWidgetItem([protocol])
            protocol_item.setExpanded(True)
            
            for key, value in details.items():
                detail_item = QTreeWidgetItem([f"{key}: {value}"])
                protocol_item.addChild(detail_item)
                
            self.addTopLevelItem(protocol_item)

class StatisticsWidget(QWidget):
    """Widget para mostrar estadísticas"""
    
    def __init__(self):
        super().__init__()
        self.init_ui()
        self.reset_stats()
        
    def init_ui(self):
        layout = QVBoxLayout()
        
        # Estadísticas generales
        self.stats_label = QLabel("Estadísticas de Captura")
        self.stats_label.setStyleSheet("font-weight: bold; font-size: 14px;")
        layout.addWidget(self.stats_label)
        
        self.packet_count_label = QLabel("Paquetes capturados: 0")
        layout.addWidget(self.packet_count_label)
        
        self.avg_size_label = QLabel("Tamaño promedio: 0 bytes")
        layout.addWidget(self.avg_size_label)
        
        # Top talkers
        layout.addWidget(QLabel("Top Talkers (IPs):"))
        self.top_talkers_list = QListWidget()
        self.top_talkers_list.setMaximumHeight(150)
        layout.addWidget(self.top_talkers_list)
        
        # Puertos más usados
        layout.addWidget(QLabel("Puertos más usados:"))
        self.top_ports_list = QListWidget()
        self.top_ports_list.setMaximumHeight(150)
        layout.addWidget(self.top_ports_list)
        
        # Protocolos
        layout.addWidget(QLabel("Distribución de protocolos:"))
        self.protocols_list = QListWidget()
        self.protocols_list.setMaximumHeight(150)
        layout.addWidget(self.protocols_list)
        
        layout.addStretch()
        self.setLayout(layout)
        
    def reset_stats(self):
        """Reiniciar estadísticas"""
        self.packet_count = 0
        self.total_size = 0
        self.ip_counter = Counter()
        self.port_counter = Counter()
        self.protocol_counter = Counter()
        
    def update_stats(self, packet_info):
        """Actualizar estadísticas con nuevo paquete"""
        self.packet_count += 1
        self.total_size += packet_info['length']
        
        # Actualizar contadores
        if packet_info['src']:
            self.ip_counter[packet_info['src']] += 1
        if packet_info['dst']:
            self.ip_counter[packet_info['dst']] += 1
            
        # Puertos TCP/UDP
        if 'TCP' in packet_info['details']:
            self.port_counter[packet_info['details']['TCP']['sport']] += 1
            self.port_counter[packet_info['details']['TCP']['dport']] += 1
        if 'UDP' in packet_info['details']:
            self.port_counter[packet_info['details']['UDP']['sport']] += 1
            self.port_counter[packet_info['details']['UDP']['dport']] += 1
            
        # Protocolos
        for protocol in packet_info['protocols']:
            self.protocol_counter[protocol] += 1
            
        self.refresh_display()
        
    def refresh_display(self):
        """Actualizar visualización de estadísticas"""
        # Estadísticas generales
        self.packet_count_label.setText(f"Paquetes capturados: {self.packet_count}")
        avg_size = self.total_size / self.packet_count if self.packet_count > 0 else 0
        self.avg_size_label.setText(f"Tamaño promedio: {avg_size:.1f} bytes")
        
        # Top talkers
        self.top_talkers_list.clear()
        for ip, count in self.ip_counter.most_common(10):
            self.top_talkers_list.addItem(f"{ip}: {count} paquetes")
            
        # Top ports
        self.top_ports_list.clear()
        for port, count in self.port_counter.most_common(10):
            self.top_ports_list.addItem(f"Puerto {port}: {count} paquetes")
            
        # Protocolos
        self.protocols_list.clear()
        for protocol, count in self.protocol_counter.most_common():
            percentage = (count / self.packet_count) * 100 if self.packet_count > 0 else 0
            self.protocols_list.addItem(f"{protocol}: {count} ({percentage:.1f}%)")

class PacketScopeMainWindow(QMainWindow):
    """Ventana principal de PacketScope"""
    
    def __init__(self):
        super().__init__()
        self.capture = PacketCapture()
        self.decoder = ProtocolDecoder()
        self.init_ui()
        self.connect_signals()
        
    def init_ui(self):
        self.setWindowTitle("PacketScope - Analizador de Tráfico LAN")
        self.setWindowIcon(QIcon())
        self.resize(1200, 800)
        
        # Widget central
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # Layout principal
        main_layout = QVBoxLayout(central_widget)
        
        # Barra de herramientas
        self.create_toolbar()
        
        # Splitter principal
        main_splitter = QSplitter(Qt.Horizontal)
        
        # Panel izquierdo - Lista de paquetes
        left_panel = QWidget()
        left_layout = QVBoxLayout(left_panel)
        
        # Controles de captura
        controls_layout = QHBoxLayout()
        
        self.interface_combo = QComboBox()
        self.populate_interfaces()
        controls_layout.addWidget(QLabel("Interfaz:"))
        controls_layout.addWidget(self.interface_combo)
        
        self.filter_edit = QLineEdit()
        self.filter_edit.setPlaceholderText("Filtro BPF (ej: tcp port 80)")
        controls_layout.addWidget(QLabel("Filtro:"))
        controls_layout.addWidget(self.filter_edit)
        
        self.start_button = QPushButton("Iniciar Captura")
        self.start_button.clicked.connect(self.start_capture)
        controls_layout.addWidget(self.start_button)
        
        self.stop_button = QPushButton("Detener")
        self.stop_button.clicked.connect(self.stop_capture)
        self.stop_button.setEnabled(False)
        controls_layout.addWidget(self.stop_button)
        
        # Checkbox para auto-scroll
        self.auto_scroll_check = QCheckBox("Auto-scroll")
        self.auto_scroll_check.setChecked(True)
        controls_layout.addWidget(self.auto_scroll_check)
        
        # Label de estado de captura
        self.capture_status = QLabel("Paquetes: 0")
        controls_layout.addWidget(self.capture_status)
        
        left_layout.addLayout(controls_layout)
        
        # Tabla de paquetes
        self.packet_model = PacketTableModel()
        self.packet_table = QTableView()
        self.packet_table.setModel(self.packet_model)
        self.packet_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.packet_table.selectionModel().selectionChanged.connect(self.on_packet_selected)
        left_layout.addWidget(self.packet_table)
        
        main_splitter.addWidget(left_panel)
        
        # Panel derecho - Detalles y estadísticas
        right_panel = QWidget()
        right_layout = QVBoxLayout(right_panel)
        
        # Tabs para detalles
        self.details_tabs = QTabWidget()
        
        # Tab de detalles del protocolo
        self.protocol_tree = ProtocolTreeWidget()
        self.details_tabs.addTab(self.protocol_tree, "Detalles del Protocolo")
        
        # Tab de estadísticas
        self.stats_widget = StatisticsWidget()
        self.details_tabs.addTab(self.stats_widget, "Estadísticas")
        
        right_layout.addWidget(self.details_tabs)
        main_splitter.addWidget(right_panel)
        
        # Configurar tamaños del splitter
        main_splitter.setSizes([800, 400])
        main_layout.addWidget(main_splitter)
        
        # Barra de estado
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Listo para capturar")
        
    def create_toolbar(self):
        """Crear barra de herramientas"""
        toolbar = self.addToolBar("Archivo")
        
        # Acción abrir
        open_action = QAction("Abrir PCAP", self)
        open_action.setShortcut("Ctrl+O")
        open_action.triggered.connect(self.open_pcap)
        toolbar.addAction(open_action)
        
        # Acción guardar
        save_action = QAction("Guardar PCAP", self)
        save_action.setShortcut("Ctrl+S")
        save_action.triggered.connect(self.save_pcap)
        toolbar.addAction(save_action)
        
        toolbar.addSeparator()
        
        # Acción limpiar
        clear_action = QAction("Limpiar", self)
        clear_action.triggered.connect(self.clear_packets)
        toolbar.addAction(clear_action)
        
    def populate_interfaces(self):
        """Poblar combo box con interfaces de red"""
        try:
            interfaces = get_if_list()
            self.interface_combo.addItems(interfaces)
        except Exception as e:
            QMessageBox.warning(self, "Error", f"No se pudieron obtener las interfaces: {str(e)}")
            
    def connect_signals(self):
        """Conectar señales"""
        self.capture.packet_captured.connect(self.on_packet_captured)
        self.capture.packets_batch.connect(self.on_packets_batch)  # Nueva señal
        self.capture.error_occurred.connect(self.on_capture_error)
        
    def start_capture(self):
        """Iniciar captura"""
        interface = self.interface_combo.currentText()
        filter_text = self.filter_edit.text().strip()
        
        if not interface:
            QMessageBox.warning(self, "Error", "Selecciona una interfaz de red")
            return
            
        try:
            # Verificar que la interfaz esté disponible
            if os.name == 'nt':  # Windows
                try:
                    # Verificar que Npcap/WinPcap funcione
                    test_sniff = sniff(iface=interface, count=1, timeout=1)
                except Exception as e:
                    error_msg = (
                        "Error de captura en Windows. Posibles soluciones:\n\n"
                        "1. INSTALAR NPCAP:\n"
                        "   • Descargar: https://npcap.org/\n"
                        "   • Instalar con 'WinPcap API compatibility'\n\n"
                        "2. EJECUTAR COMO ADMINISTRADOR:\n"
                        "   • Clic derecho → 'Ejecutar como administrador'\n\n"
                        "3. VERIFICAR INTERFAZ:\n"
                        "   • Prueba con otra interfaz de red\n\n"
                        f"Error técnico: {str(e)}"
                    )
                    QMessageBox.critical(self, "Error de Configuración", error_msg)
                    return
            
            self.capture.start_capture(interface, filter_text)
            self.start_button.setEnabled(False)
            self.stop_button.setEnabled(True)
            self.status_bar.showMessage(f"Capturando en {interface}...")
            
        except Exception as e:
            error_msg = f"No se pudo iniciar la captura: {str(e)}"
            if "winpcap" in str(e).lower() or "npcap" in str(e).lower():
                error_msg += "\n\nInstala Npcap desde: https://npcap.org/"
            QMessageBox.critical(self, "Error", error_msg)
            
    def stop_capture(self):
        """Detener captura"""
        self.capture.stop_capture()
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.status_bar.showMessage("Captura detenida")
        
    def clear_packets(self):
        """Limpiar lista de paquetes"""
        self.packet_model.clear()
        self.protocol_tree.clear()
        self.stats_widget.reset_stats()
        self.stats_widget.refresh_display()
        self.capture_status.setText("Paquetes: 0")
        
    def on_packet_captured(self, packet):
        """Manejar paquete capturado individualmente (para archivos)"""
        packet_info = self.decoder.decode_packet(packet)
        self.packet_model.add_packet(packet_info)
        self.stats_widget.update_stats(packet_info)
        
        # Auto-scroll solo si está habilitado y es el último paquete
        if self.auto_scroll_check.isChecked():
            last_row = self.packet_model.rowCount() - 1
            self.packet_table.scrollTo(self.packet_model.index(last_row, 0))
    
    def on_packets_batch(self, packets):
        """Manejar lote de paquetes capturados - MUCHO MÁS EFICIENTE"""
        if not packets:
            return
            
        # Procesar todos los paquetes del lote
        packet_infos = []
        for packet in packets:
            packet_info = self.decoder.decode_packet(packet)
            packet_infos.append(packet_info)
            self.stats_widget.update_stats(packet_info)
        
        # Añadir todos de una vez - evita múltiples actualizaciones de UI
        self.packet_model.add_packets_batch(packet_infos)
        
        # Actualizar contador
        total_packets = len(self.capture.packets)
        self.capture_status.setText(f"Paquetes: {total_packets}")
        
        # Auto-scroll solo si está habilitado
        if self.auto_scroll_check.isChecked():
            last_row = self.packet_model.rowCount() - 1
            self.packet_table.scrollTo(self.packet_model.index(last_row, 0))
        
    def on_packet_selected(self, selected, deselected):
        """Manejar selección de paquete"""
        indexes = selected.indexes()
        if indexes:
            row = indexes[0].row()
            packet_info = self.packet_model.packets[row]
            self.protocol_tree.display_packet(packet_info)
            
    def on_capture_error(self, error_msg):
        """Manejar errores de captura"""
        QMessageBox.critical(self, "Error de Captura", error_msg)
        self.stop_capture()
        
    def open_pcap(self):
        """Abrir archivo PCAP"""
        filename, _ = QFileDialog.getOpenFileName(
            self, "Abrir archivo PCAP", "", "PCAP Files (*.pcap *.pcapng);;All Files (*)"
        )
        
        if filename:
            self.clear_packets()
            self.capture.load_packets(filename)
            self.status_bar.showMessage(f"Archivo cargado: {filename}")
            
    def save_pcap(self):
        """Guardar archivo PCAP"""
        if not self.capture.packets:
            QMessageBox.information(self, "Info", "No hay paquetes para guardar")
            return
            
        filename, _ = QFileDialog.getSaveFileName(
            self, "Guardar archivo PCAP", "", "PCAP Files (*.pcap);;All Files (*)"
        )
        
        if filename:
            try:
                self.capture.save_packets(filename)
                self.status_bar.showMessage(f"Archivo guardado: {filename}")
                QMessageBox.information(self, "Éxito", f"Archivo guardado: {filename}")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Error guardando archivo: {str(e)}")

def check_privileges():
    """Verificar privilegios necesarios para captura"""
    if os.name == 'nt':  # Windows
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin()
        except:
            return False
    else:  # Linux/Unix
        return os.geteuid() == 0

def check_winpcap_npcap():
    """Verificar si WinPcap/Npcap está instalado en Windows"""
    if os.name != 'nt':
        return True
        
    try:
        # Intentar importar y usar scapy para verificar
        from scapy.arch.windows import get_windows_if_list
        interfaces = get_windows_if_list()
        return len(interfaces) > 0
    except Exception as e:
        return False, str(e)
    
    return True

def main():
    app = QApplication(sys.argv)
    
    # Verificar privilegios
    if not check_privileges():
        msg = QMessageBox()
        msg.setIcon(QMessageBox.Warning)
        msg.setWindowTitle("Privilegios Requeridos")
        msg.setText("PacketScope necesita privilegios de administrador para capturar paquetes.")
        msg.setInformativeText(
            "En Windows: Ejecutar como administrador\n"
            "En Linux/macOS: Ejecutar con sudo"
        )
        msg.setStandardButtons(QMessageBox.Ok | QMessageBox.Cancel)
        
        if msg.exec() == QMessageBox.Cancel:
            sys.exit(1)
    
    # Verificar WinPcap/Npcap en Windows
    if os.name == 'nt':
        pcap_check = check_winpcap_npcap()
        if not pcap_check:
            msg = QMessageBox()
            msg.setIcon(QMessageBox.Critical)
            msg.setWindowTitle("WinPcap/Npcap Requerido")
            msg.setText("PacketScope necesita WinPcap o Npcap para funcionar en Windows.")
            msg.setInformativeText(
                "SOLUCIONES:\n\n"
                "1. INSTALAR NPCAP (RECOMENDADO):\n"
                "   • Descargar desde: https://npcap.org/\n"
                "   • Instalar con modo WinPcap compatible\n\n"
                "2. INSTALAR WINPCAP (ALTERNATIVO):\n"
                "   • Descargar desde: https://www.winpcap.org/\n\n"
                "3. USAR ALTERNATIVA SIN ADMIN:\n"
                "   • Usar modo de solo lectura de archivos PCAP\n\n"
                "¿Deseas continuar solo para abrir archivos PCAP?"
            )
            msg.setStandardButtons(QMessageBox.Yes | QMessageBox.No)
            
            if msg.exec() == QMessageBox.No:
                sys.exit(1)
    
    # Crear y mostrar ventana principal
    window = PacketScopeMainWindow()
    window.show()
    
    sys.exit(app.exec())

if __name__ == "__main__":
    main()