import sys
import threading
import time
import json
import csv
import socket
import struct
import re
import ipaddress
import subprocess
from datetime import datetime
from PyQt5.QtWidgets import (QApplication, QMainWindow, QTableWidget, QTableWidgetItem, 
                           QVBoxLayout, QHBoxLayout, QWidget, QPushButton, QFileDialog, 
                           QLabel, QComboBox, QProgressBar, QHeaderView, QMessageBox,
                           QTextEdit, QInputDialog, QMenu, QGroupBox, QSpinBox, QCheckBox)
from PyQt5.QtCore import Qt, QTimer, pyqtSignal, pyqtSlot, QMetaObject, Q_ARG
from PyQt5.QtGui import QIcon, QFont
import os
from queue import Queue
from scapy.all import ARP, Ether, srp, conf, AsyncSniffer, get_if_list
import requests

# Try to import scapy with better platform detection
SCAPY_AVAILABLE = False
try:
    from scapy.all import ARP, Ether, srp, conf, AsyncSniffer, get_if_list
    SCAPY_AVAILABLE = True
except ImportError:
    pass

class MacVendorDB:
    """Class to handle MAC vendor lookups"""
    
    def __init__(self):
        # Initialize with a small embedded database of common vendors
        self.vendors = {
            "00:00:0C": "Cisco Systems",
            "00:01:42": "Cisco Systems",
            "00:18:8B": "Dell",
            "00:50:56": "VMware",
            "00:1A:A0": "Dell",
            "00:25:90": "Super Micro Computer",
            "E4:54:E8": "Dell",
            "00:50:BA": "D-Link",
            "00:1D:7E": "Cisco-Linksys",
            "B8:27:EB": "Raspberry Pi Foundation",
            "DC:A6:32": "Raspberry Pi",
            "00:0C:29": "VMware",
            "00:1A:11": "Google",
            "00:03:93": "Apple",
            "00:05:02": "Apple",
            "00:0A:27": "Apple",
            "00:0A:95": "Apple",
            "00:1B:63": "Apple",
            "00:1E:C2": "Apple",
            "00:17:F2": "Apple",
            "00:11:24": "Apple",
            "04:0C:CE": "Apple",
            "24:AB:81": "Apple",
            "8C:85:90": "Apple",
            "B8:5D:0A": "HP",
            "00:26:55": "HP",
            "18:A9:05": "Hewlett Packard",
            "00:0F:1F": "Dell",
        }
        
    def lookup(self, mac_address):
        """Look up vendor based on MAC address"""
        if not mac_address:
            return "Unknown"
            
        # Format: convert any MAC format to XX:XX:XX
        mac_prefix = mac_address.upper().replace('-', ':')[:8]
        
        # Try to find vendor by first 3 bytes (OUI)
        vendor = self.vendors.get(mac_prefix, "Unknown")
        return vendor

class NetworkInterface:
    """Class to represent a network interface with all relevant information"""
    
    def __init__(self, name, description, ip=None, netmask=None, mac=None):
        self.name = name
        self.description = description
        self.ip = ip
        self.netmask = netmask
        self.mac = mac
        self.subnet = None
        
        # Calculate subnet if we have IP and netmask
        if ip and netmask:
            self.calculate_subnet()
            
    def calculate_subnet(self):
        """Calculate subnet from IP and netmask"""
        if not self.ip or not self.netmask:
            return
            
        try:
            # Convert IP and netmask to integers
            ip_int = struct.unpack('!I', socket.inet_aton(self.ip))[0]
            mask_int = struct.unpack('!I', socket.inet_aton(self.netmask))[0]
            
            # Calculate network address
            network_int = ip_int & mask_int
            network = socket.inet_ntoa(struct.pack('!I', network_int))
            
            # Calculate CIDR
            cidr = bin(mask_int).count('1')
            
            # Set subnet
            self.subnet = f"{network}/{cidr}"
        except Exception:
            self.subnet = None
            
    def __str__(self):
        return (f"Interface: {self.name}\n"
                f"Description: {self.description}\n"
                f"IP: {self.ip if self.ip else 'Not assigned'}\n"
                f"Subnet: {self.subnet if self.subnet else 'Unknown'}\n"
                f"MAC: {self.mac if self.mac else 'Unknown'}")

class NetworkScanner(QMainWindow):
    """Main application window for network scanning"""
    
    # Define custom signals
    scan_progress = pyqtSignal(int)
    scan_complete = pyqtSignal()
    add_device = pyqtSignal(dict)
    update_log = pyqtSignal(str)
    port_scan_progress = pyqtSignal(str, int)
    service_detected = pyqtSignal(str, int, str)
    vulnerability_detected = pyqtSignal(str, str)
    os_detected = pyqtSignal(str, str)
    device_status_changed = pyqtSignal(str, bool)
    
    def __init__(self):
        super().__init__()
        
        # Initialize vulnerability database
        self.known_vulnerabilities = {
            'SMB': {
                'MS17-010': {
                    'name': 'EternalBlue',
                    'description': 'SMB Remote Code Execution Vulnerability',
                    'cvss': 9.3,
                    'check': self.check_eternal_blue
                }
            },
            'HTTP': {
                'CVE-2021-44228': {
                    'name': 'Log4Shell',
                    'description': 'Log4j Remote Code Execution Vulnerability',
                    'cvss': 10.0,
                    'check': self.check_log4j
                },
                'CVE-2021-45046': {
                    'name': 'Log4j RCE',
                    'description': 'Log4j Remote Code Execution Vulnerability',
                    'cvss': 9.0,
                    'check': self.check_log4j
                }
            },
            'SSH': {
                'CVE-2021-28041': {
                    'name': 'OpenSSH Privilege Escalation',
                    'description': 'OpenSSH Privilege Escalation Vulnerability',
                    'cvss': 7.8,
                    'check': self.check_ssh_vuln
                }
            },
            'FTP': {
                'CVE-2021-3226': {
                    'name': 'vsftpd DoS',
                    'description': 'vsftpd Denial of Service Vulnerability',
                    'cvss': 5.0,
                    'check': self.check_ftp_vuln
                }
            }
        }
        
        # Initialize OS signatures database
        self.os_signatures = {
            'Windows': {
                'ports': [135, 139, 445, 3389],
                'ttl_range': (110, 128),
                'services': {
                    445: 'SMB',
                    3389: 'RDP',
                    135: 'RPC',
                    139: 'NetBIOS'
                }
            },
            'Linux': {
                'ports': [22, 111, 2049],
                'ttl_range': (50, 64),
                'services': {
                    22: 'SSH',
                    111: 'NFS/RPC',
                    2049: 'NFS'
                }
            },
            'MacOS': {
                'ports': [22, 548, 5009],
                'ttl_range': (50, 64),
                'services': {
                    548: 'AFP',
                    5009: 'Airport',
                    22: 'SSH'
                }
            },
            'Network Device': {
                'ports': [23, 80, 443, 161],
                'ttl_range': (240, 255),
                'services': {
                    23: 'Telnet',
                    80: 'HTTP',
                    443: 'HTTPS',
                    161: 'SNMP'
                }
            }
        }
        
        # Initialize the rest of the scanner
        self.init_scanner()
        
    def init_scanner(self):
        """Initialize scanner components"""
        # Initialize queues and locks
        self.scan_queue = Queue()
        self.results_lock = threading.Lock()
        
        # Initialize scanning variables
        self.scanning = False
        self.scanner_thread = None
        self.scan_threads = []
        self.max_threads = os.cpu_count() or 4
        self.devices = []
        self.interfaces = []
        
        # Create log_text
        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        self.log_text.setMaximumHeight(120)
        
        # Initialize vendor database
        self.vendor_db = MacVendorDB()
        
        # Initialize UI
        self.init_ui()
        
        # Initialize advanced features
        self.init_advanced_features()
        
        # Check Scapy availability
        if not SCAPY_AVAILABLE:
            QMessageBox.warning(self, "Dependency Warning", 
                              "Scapy is not installed. Some functionality may be limited.\n"
                              "Install it using: pip install scapy")
        
        # Get interfaces on startup
        self.refresh_interfaces()
        
        # Connect signals
        self.scan_progress.connect(self.update_progress)
        self.scan_complete.connect(self.on_scan_complete)
        self.add_device.connect(self.on_device_found)
        self.update_log.connect(self.add_log_message)
        self.port_scan_progress.connect(self.update_port_scan_progress)
        self.service_detected.connect(self.on_service_detected)
        self.vulnerability_detected.connect(self.on_vulnerability_detected)
        self.os_detected.connect(self.on_os_detected)
        self.device_status_changed.connect(self.on_device_status_changed)
        
    def init_advanced_features(self):
        """Initialize advanced scanning features"""
        # Initialize packet capture if available
        self.packet_capture_enabled = False
        if SCAPY_AVAILABLE:
            try:
                self.sniffer = AsyncSniffer()
                self.packet_capture_enabled = True
            except:
                pass
        
        # Initialize network monitoring
        self.monitoring_active = False
        self.monitor_timer = QTimer()
        self.monitor_timer.timeout.connect(self.check_device_status)
        
        # Initialize vulnerability database
        self.update_vulnerability_database()
        
    def init_ui(self):
        """Initialize the user interface"""
        # Main widget and layout
        main_widget = QWidget()
        main_layout = QVBoxLayout()
        
        # Add advanced scanning options group
        advanced_group = QGroupBox("Advanced Options")
        advanced_layout = QVBoxLayout()
        
        # Thread control
        thread_layout = QHBoxLayout()
        thread_label = QLabel("Parallel Threads:")
        self.thread_spinner = QSpinBox()
        self.thread_spinner.setRange(1, self.max_threads)
        self.thread_spinner.setValue(self.max_threads // 2)  # Default to half of CPU cores
        self.thread_spinner.setToolTip("Number of parallel scanning threads")
        thread_layout.addWidget(thread_label)
        thread_layout.addWidget(self.thread_spinner)
        thread_layout.addStretch()
        advanced_layout.addLayout(thread_layout)
        
        # Scan options
        self.vuln_scan_check = QCheckBox("Enable Vulnerability Scanning")
        self.os_detect_check = QCheckBox("Enable OS Detection")
        self.monitor_check = QCheckBox("Enable Continuous Monitoring")
        self.monitor_check.stateChanged.connect(self.toggle_monitoring)
        
        advanced_layout.addWidget(self.vuln_scan_check)
        advanced_layout.addWidget(self.os_detect_check)
        advanced_layout.addWidget(self.monitor_check)
        
        advanced_group.setLayout(advanced_layout)
        
        # Network interface selection
        interface_layout = QHBoxLayout()
        interface_label = QLabel("Network Interface:")
        self.interface_combo = QComboBox()
        self.interface_combo.setMinimumWidth(400)
        self.interface_combo.currentIndexChanged.connect(self.update_interface_info)
        interface_layout.addWidget(interface_label)
        interface_layout.addWidget(self.interface_combo)
        interface_layout.addStretch()
        
        # Interface information
        self.interface_info = QLabel("No network interface selected")
        self.interface_info.setTextFormat(Qt.RichText)
        self.interface_info.setStyleSheet("background-color: #f0f0f0; padding: 10px; border-radius: 5px;")
        
        # Control buttons
        button_layout = QHBoxLayout()
        self.scan_button = QPushButton("Start Scan")
        self.scan_button.clicked.connect(self.toggle_scan)
        self.scan_button.setEnabled(False)
        
        self.refresh_button = QPushButton("Refresh Interfaces")
        self.refresh_button.clicked.connect(self.refresh_interfaces)
        
        self.export_button = QPushButton("Export Results")
        self.export_button.clicked.connect(self.export_results)
        self.export_button.setEnabled(False)
        
        button_layout.addWidget(self.scan_button)
        button_layout.addWidget(self.refresh_button)
        button_layout.addWidget(self.export_button)
        button_layout.addStretch()
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setValue(0)
        
        # Status label
        self.status_label = QLabel("Ready")
        
        # Log area
        log_layout = QVBoxLayout()
        log_label = QLabel("Activity Log:")
        log_layout.addWidget(log_label)
        log_layout.addWidget(self.log_text)
        
        # Results table
        self.results_table = QTableWidget()
        self.results_table.setColumnCount(8)
        self.results_table.setHorizontalHeaderLabels([
            "IP Address", "MAC Address", "Vendor", "Response Time (ms)", 
            "Last Seen", "Hostname", "Open Ports", "OS Guess"
        ])
        self.results_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        
        # Add all elements to main layout
        main_layout.addLayout(interface_layout)
        main_layout.addWidget(self.interface_info)
        main_layout.addWidget(advanced_group)  # Add advanced options group
        main_layout.addLayout(button_layout)
        main_layout.addWidget(self.progress_bar)
        main_layout.addWidget(self.status_label)
        main_layout.addLayout(log_layout)
        main_layout.addWidget(self.results_table)
        
        # Set the main layout
        main_widget.setLayout(main_layout)
        self.setCentralWidget(main_widget)
    
    def get_network_interfaces(self):
        """Get a list of network interfaces with IP addresses"""
        self.add_log_message("Detecting network interfaces...")
        interfaces = []
        
        # Try different methods to get interface information
        try:
            # Method 1: Try ipconfig
            self.add_log_message("Trying to get interfaces from ipconfig...")
            ipconfig_interfaces = self.get_interfaces_from_ipconfig()
            
            if ipconfig_interfaces:
                self.add_log_message(f"Found {len(ipconfig_interfaces)} interfaces from ipconfig")
                interfaces.extend(ipconfig_interfaces)
            else:
                self.add_log_message("No interfaces found from ipconfig")
            
            # Method 2: Try Scapy
            self.add_log_message("Trying to get interfaces from Scapy...")
            scapy_interfaces = self.get_interfaces_from_scapy()
            
            # Try socket method for at least one interface
            self.add_log_message("Trying to get interfaces from socket...")
            socket_interface = self.get_interface_from_socket()
            
            if socket_interface and socket_interface.ip:
                self.add_log_message(f"Found active connection: {socket_interface.ip}")
                # Check if we already have this IP
                if not any(interface.ip == socket_interface.ip for interface in interfaces):
                    interfaces.append(socket_interface)
            else:
                self.add_log_message("No interface found from socket method")
                
            # NEW: Try local hostname method if we still don't have interfaces
            if not interfaces or not any(i.ip for i in interfaces):
                self.add_log_message("Trying to get local interfaces...")
                local_interfaces = self.get_local_interfaces()
                if local_interfaces:
                    interfaces.extend(local_interfaces)
            
            # Filter out interfaces with no IP address
            valid_interfaces = [i for i in interfaces if i.ip]
            
            if valid_interfaces:
                self.add_log_message(f"Found {len(valid_interfaces)} valid interfaces with IP addresses")
            else:
                self.add_log_message("WARNING: No interfaces with valid IP addresses found")
                
                # If no interfaces with IP, include all interfaces
                valid_interfaces = interfaces
            
            return valid_interfaces
            
        except Exception as e:
            self.add_log_message(f"Error getting network interfaces: {str(e)}")
            # Return at least one default interface
            return [NetworkInterface("loopback", "Loopback Interface", "127.0.0.1", "255.0.0.0")]

    def get_interfaces_from_ipconfig(self):
        """Get network interfaces from ipconfig command"""
        interfaces = []
        
        try:
            # Check if we're on Windows
            if sys.platform.startswith('win'):
                # Run ipconfig /all command
                output = subprocess.check_output("ipconfig /all", shell=True).decode('utf-8', errors='ignore')
            else:
                # On Linux/Mac, use ifconfig
                try:
                    output = subprocess.check_output("ifconfig -a", shell=True).decode('utf-8', errors='ignore')
                except:
                    # Some Linux distros might use ip instead
                    output = subprocess.check_output("ip addr show", shell=True).decode('utf-8', errors='ignore')
            
            # Parse the output based on platform
            if sys.platform.startswith('win'):
                # Parse Windows ipconfig output
                current_if = None
                current_if_name = None
                current_if_desc = None
                
                for line in output.splitlines():
                    line = line.strip()
                    
                    # Check if this is a new interface section
                    if not line.startswith(" ") and line:
                        # Save the previous interface if it exists
                        if current_if_name and current_if_desc and current_if:
                            interfaces.append(current_if)
                        
                        # Start a new interface
                        current_if_name = line.rstrip(":")
                        current_if_desc = None
                        current_if = None
                    
                    # Get the description
                    elif "Description" in line:
                        current_if_desc = line.split(":", 1)[1].strip()
                        
                        # Create new interface object
                        if current_if_name and current_if_desc:
                            current_if = NetworkInterface(current_if_name, current_if_desc)
                    
                    # Get the IP address
                    elif "IPv4 Address" in line and current_if:
                        ip_parts = line.split(":", 1)
                        if len(ip_parts) > 1:
                            ip = ip_parts[1].strip().split("(")[0].strip()
                            current_if.ip = ip
                    
                    # Get the subnet mask
                    elif "Subnet Mask" in line and current_if:
                        mask_parts = line.split(":", 1)
                        if len(mask_parts) > 1:
                            mask = mask_parts[1].strip()
                            current_if.netmask = mask
                            
                            # Calculate subnet if we have both IP and mask
                            if current_if.ip and current_if.netmask:
                                current_if.calculate_subnet()
                    
                    # Get MAC address
                    elif "Physical Address" in line and current_if:
                        mac_parts = line.split(":", 1)
                        if len(mac_parts) > 1:
                            mac = mac_parts[1].strip()
                            current_if.mac = mac
                
                # Save the last interface if needed
                if current_if_name and current_if_desc and current_if and current_if not in interfaces:
                    interfaces.append(current_if)
            else:
                # Parse Linux/Mac output (simplified)
                current_if = None
                
                for line in output.splitlines():
                    # New interface starts with name
                    if not line.startswith(" ") and ":" in line and not line.startswith("   "):
                        name = line.split(":", 1)[0].strip()
                        current_if = NetworkInterface(name, name)
                        interfaces.append(current_if)
                    
                    # Get IP address
                    elif current_if and ("inet " in line or "inet addr:" in line):
                        parts = line.split()
                        for i, part in enumerate(parts):
                            if part == "inet" and i + 1 < len(parts):
                                ip = parts[i + 1].split("/")[0]
                                if "addr:" in ip:
                                    ip = ip.split(":", 1)[1]
                                current_if.ip = ip
                            elif part == "netmask" and i + 1 < len(parts):
                                current_if.netmask = parts[i + 1]
                    
                    # Get MAC address
                    elif current_if and ("ether " in line or "HWaddr " in line):
                        parts = line.split()
                        for i, part in enumerate(parts):
                            if part in ["ether", "HWaddr"] and i + 1 < len(parts):
                                current_if.mac = parts[i + 1]
                
                # Calculate subnets for all interfaces with IP and netmask
                for iface in interfaces:
                    if iface.ip and iface.netmask:
                        iface.calculate_subnet()
                
            return interfaces
            
        except Exception as e:
            self.add_log_message(f"Error getting interfaces from ipconfig/ifconfig: {str(e)}")
            return []
    
    def get_interfaces_from_scapy(self):
        """Get network interfaces using Scapy"""
        interfaces = []
        
        if not SCAPY_AVAILABLE:
            return []
        
        try:
            # Use platform-appropriate method
            if sys.platform.startswith('win'):
                # Windows-specific handling (fallback to socket method)
                return self.get_interface_from_socket()
            else:
                # Linux/Unix systems
                for iface_name in get_if_list():
                    try:
                        # Get interface IP
                        ip = conf.route.route("0.0.0.0")[1]
                        # Create interface object
                        net_if = NetworkInterface(
                            name=iface_name,
                            description=f"Interface {iface_name}",
                            ip=ip
                        )
                        interfaces.append(net_if)
                    except:
                        continue
        
            return interfaces
            
        except Exception as e:
            self.add_log_message(f"Error getting interfaces from Scapy: {str(e)}")
            return []
    
    def get_interface_from_socket(self):
        """Get at least one interface with the current IP using socket"""
        try:
            # Create a socket and connect to an external server
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(0.5)  # Short timeout
            
            # Try multiple DNS servers in case one is blocked
            dns_servers = ["8.8.8.8", "1.1.1.1", "208.67.222.222"]
            connected = False
            
            for dns in dns_servers:
                try:
                    s.connect((dns, 80))
                    connected = True
                    break
                except:
                    continue
                    
            if connected:
                ip = s.getsockname()[0]
                s.close()
                
                # Create a basic interface with this IP
                self.add_log_message(f"Socket method found active connection: {ip}")
                return NetworkInterface(
                    "active_connection", 
                    f"Active connection ({ip})", 
                    ip, 
                    "255.255.255.0"  # Assume a standard netmask
                )
            else:
                s.close()
                self.add_log_message("Socket method couldn't connect to any DNS server")
                return None
        except Exception as e:
            self.add_log_message(f"Error getting interface from socket: {str(e)}")
            return None

    def get_local_interfaces(self):
        """Get local interfaces using socket.gethostbyname_ex"""
        try:
            hostname = socket.gethostname()
            self.add_log_message(f"Detecting local interfaces for hostname: {hostname}")
            
            # Get all IPs for this hostname
            _, _, ips = socket.gethostbyname_ex(hostname)
            
            if ips:
                interfaces = []
                for ip in ips:
                    # Skip localhost
                    if ip.startswith("127."):
                        continue
                        
                    # Create interface object
                    interface = NetworkInterface(
                        f"local_{ip}", 
                        f"Local interface ({ip})", 
                        ip, 
                        "255.255.255.0"  # Assume standard netmask
                    )
                    interfaces.append(interface)
                    self.add_log_message(f"Found local interface with IP: {ip}")
                
                return interfaces
            else:
                self.add_log_message("No local interfaces found")
                return []
        except Exception as e:
            self.add_log_message(f"Error getting local interfaces: {str(e)}")
            return []

    def merge_interface_data(self, primary_interfaces, secondary_interfaces):
        """Merge data from secondary interfaces into primary interfaces"""
        # Create lookup by name
        secondary_by_name = {i.name: i for i in secondary_interfaces}
        
        for primary in primary_interfaces:
            if primary.name in secondary_by_name:
                secondary = secondary_by_name[primary.name]
                
                # Copy any missing data
                if not primary.ip and secondary.ip:
                    primary.ip = secondary.ip
                if not primary.netmask and secondary.netmask:
                    primary.netmask = secondary.netmask
                if not primary.mac and secondary.mac:
                    primary.mac = secondary.mac
                
                # Recalculate subnet if needed
                if primary.ip and primary.netmask:
                    primary.calculate_subnet()
    
    def refresh_interfaces(self):
        """Refresh the list of network interfaces"""
        # Clear current interfaces
        self.interface_combo.clear()
        
        # Add a refresh message
        self.status_label.setText("Refreshing network interfaces...")
        QApplication.processEvents()  # Force UI update
        
        # Get new interfaces
        self.interfaces = self.get_network_interfaces()
        
        # Add to combo box
        if self.interfaces:
            # Add interfaces with IP addresses first
            has_ip_interfaces = [i for i in self.interfaces if i.ip]
            for interface in has_ip_interfaces:
                # Show IP in the dropdown for clarity
                display_text = f"{interface.description} [{interface.ip}]"
                self.interface_combo.addItem(display_text, interface)
            
            # Then add interfaces without IP
            no_ip_interfaces = [i for i in self.interfaces if not i.ip]
            for interface in no_ip_interfaces:
                display_text = f"{interface.description} [No IP]"
                self.interface_combo.addItem(display_text, interface)
        
        # Update interface info
        self.update_interface_info()
        
        # Enable scan button if we have interfaces with IPs
        self.scan_button.setEnabled(any(interface.ip for interface in self.interfaces))
        
        # Show status
        if self.interfaces:
            valid_interfaces = [i for i in self.interfaces if i.ip]
            self.status_label.setText(f"Found {len(self.interfaces)} network interfaces ({len(valid_interfaces)} with valid IP addresses)")
        else:
            self.status_label.setText("No network interfaces found")
            
        # Debug output to log
        for interface in self.interfaces:
            self.add_log_message(f"Interface: {interface.name}, IP: {interface.ip or 'None'}, Subnet: {interface.subnet or 'Unknown'}")
    
    def update_interface_info(self):
        """Update the interface information display"""
        if self.interface_combo.count() == 0:
            self.interface_info.setText("No network interfaces found")
            self.scan_button.setEnabled(False)
            return
            
        selected_interface = self.interface_combo.currentData()
        if not selected_interface:
            return
        
        # Format interface info with HTML for better readability
        info_text = f"""
        <b>Interface:</b> {selected_interface.name}<br>
        <b>Description:</b> {selected_interface.description}<br>
        <b>IP Address:</b> <span style='color: {'green' if selected_interface.ip else 'red'};'>
            {selected_interface.ip if selected_interface.ip else 'Not assigned'}</span><br>
        <b>Subnet:</b> {selected_interface.subnet if selected_interface.subnet else 'Unknown'}<br>
        <b>MAC:</b> {selected_interface.mac if selected_interface.mac else 'Unknown'}
        """
        
        # Display interface information
        self.interface_info.setText(info_text)
        
        # Enable/disable scan button based on IP presence
        self.scan_button.setEnabled(bool(selected_interface.ip))
    
    def toggle_scan(self):
        """Start or stop the network scan"""
        if self.scanning:
            self.stop_scan()
        else:
            self.start_scan()
    
    def start_scan(self):
        """Start the network scan"""
        if self.scanning:
            return
        
        # Clear previous results
        self.devices = []
        self.results_table.setRowCount(0)
        self.export_button.setEnabled(False)
        
        # Clear and reset the scan queue
        while not self.scan_queue.empty():
            try:
                self.scan_queue.get_nowait()
            except Empty:
                break
        
        # Get selected interface
        selected_interface = self.interface_combo.currentData()
        if not selected_interface:
            self.show_error("No network interface selected")
            return
        
        # Get IP address and subnet
        if not selected_interface.ip:
            self.show_error("Selected interface has no IP address")
            return
            
        # Get subnet
        subnet = selected_interface.subnet
        if not subnet:
            # Try to create a subnet based on the IP
            ip_parts = selected_interface.ip.split('.')
            if len(ip_parts) == 4:
                subnet = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"
            else:
                subnet = f"{selected_interface.ip}/24"
        
        # Log the scan details
        self.add_log_message(f"Starting scan on interface {selected_interface.name} with IP {selected_interface.ip}")
        self.add_log_message(f"Scanning subnet: {subnet}")
            
        # Update UI
        self.scanning = True
        self.scan_button.setText("Stop Scan")
        self.status_label.setText(f"Scanning network: {subnet}")
        self.progress_bar.setValue(0)
        
        # Start scanner thread
        self.scanner_thread = threading.Thread(
            target=self.run_parallel_scan,
            args=(selected_interface, subnet)
        )
        self.scanner_thread.daemon = True
        self.scanner_thread.start()
    
    def stop_scan(self):
        """Stop the network scan"""
        if not self.scanning:
            return
            
        self.scanning = False
        self.scan_button.setText("Start Scan")
        self.status_label.setText("Scan stopped")
        self.add_log_message("Scan stopped by user")
        
        # Enable export if we have results
        if len(self.devices) > 0:
            self.export_button.setEnabled(True)
    
    def run_parallel_scan(self, interface, subnet):
        """Run network scan using parallel processing"""
        try:
            network = ipaddress.ip_network(subnet, strict=False)
            total_ips = network.num_addresses - 2  # Exclude network and broadcast
            
            # Clear and populate IP queue
            while not self.scan_queue.empty():
                try:
                    self.scan_queue.get_nowait()
                except Empty:
                    break
                    
            # Add IPs to queue
            for ip in network.hosts():
                self.scan_queue.put(str(ip))
            
            # Get number of threads from spinner or use default
            num_threads = getattr(self, 'thread_spinner', None)
            if num_threads is None:
                num_threads = self.max_threads // 2  # Default to half of CPU cores
            else:
                num_threads = num_threads.value()
            
            # Create worker threads
            self.scan_threads = []
            for _ in range(num_threads):
                thread = threading.Thread(target=self.scan_worker)
                thread.daemon = True
                thread.start()
                self.scan_threads.append(thread)
            
            # Monitor progress
            scanned = 0
            while not self.scan_queue.empty() and self.scanning:
                remaining = self.scan_queue.qsize()
                scanned = total_ips - remaining
                progress = int((scanned / total_ips) * 100)
                self.scan_progress.emit(progress)
                time.sleep(0.1)
            
            # Wait for threads to complete
            for thread in self.scan_threads:
                thread.join(timeout=1)
            
        except Exception as e:
            self.update_log.emit(f"Parallel scan error: {str(e)}")
        finally:
            self.scan_complete.emit()
            
    def scan_worker(self):
        """Worker function for parallel scanning"""
        while self.scanning:
            try:
                # Get next IP from queue
                ip = self.scan_queue.get_nowait()
            except Empty:
                break
                
            try:
                # Basic connectivity check
                response_time = self.ping_host(ip)
                if response_time:
                    # Get device info
                    device_info = self.get_device_info(ip)
                    
                    # Additional scans if enabled
                    if self.vuln_scan_check.isChecked():
                        self.scan_vulnerabilities(ip, device_info)
                    if self.os_detect_check.isChecked():
                        self.detect_os(ip, device_info)
                    
                    # Add device to results
                    with self.results_lock:
                        self.add_device.emit(device_info)
                        
            except Exception as e:
                self.update_log.emit(f"Worker error scanning {ip}: {str(e)}")
            finally:
                self.scan_queue.task_done()
                
    def get_device_info(self, ip):
        """Get comprehensive device information"""
        info = {
            'ip': ip,
            'mac': self.get_mac_from_ip(ip),
            'response_time': self.ping_host(ip),
            'last_seen': datetime.now().strftime("%H:%M:%S"),
            'hostname': '',
            'open_ports': [],
            'os_guess': '',
            'vulnerabilities': []
        }
        
        # Try to get hostname
        try:
            info['hostname'] = socket.gethostbyaddr(ip)[0]
        except:
            pass
            
        # Quick port scan of common ports
        for port in [21, 22, 23, 80, 443, 445, 3389]:
            if self.check_port(ip, port):
                info['open_ports'].append(port)
                
        # Get vendor info if MAC available
        if info['mac']:
            info['vendor'] = self.vendor_db.lookup(info['mac'][:8])
        else:
            info['vendor'] = 'Unknown'
            
        return info
        
    def scan_vulnerabilities(self, ip, device_info):
        """Scan for known vulnerabilities"""
        for port in device_info['open_ports']:
            service = self.identify_service(ip, port)
            if service in self.known_vulnerabilities:
                for vuln in self.known_vulnerabilities[service]:
                    if self.check_vulnerability(ip, port, vuln):
                        self.vulnerability_detected.emit(ip, vuln)
                        device_info['vulnerabilities'].append(vuln)
                        
    def check_vulnerability(self, ip, port, vuln):
        """Check for specific vulnerability"""
        try:
            if vuln == 'MS17-010':  # EternalBlue
                return self.check_eternal_blue(ip)
            elif vuln.startswith('CVE-2021-44228'):  # Log4j
                return self.check_log4j(ip, port)
            # Add more vulnerability checks as needed
        except:
            pass
        return False
        
    def detect_os(self, ip, device_info):
        """Enhanced OS detection using multiple methods"""
        try:
            os_scores = {os: 0 for os in self.os_signatures}
            
            # Method 1: TTL Analysis
            ttl = self.get_ping_ttl(ip)
            if ttl:
                for os_name, sig in self.os_signatures.items():
                    if sig['ttl_range'][0] <= ttl <= sig['ttl_range'][1]:
                        os_scores[os_name] += 3  # Higher weight for TTL match
                        
            # Method 2: Port signature analysis
            open_ports = device_info.get('open_ports', [])
            for os_name, sig in self.os_signatures.items():
                matching_ports = set(sig['ports']) & set(open_ports)
                os_scores[os_name] += len(matching_ports)
                
            # Method 3: Service fingerprinting
            for port in open_ports:
                service = self.identify_service(ip, port)
                for os_name, sig in self.os_signatures.items():
                    if port in sig['services'] and sig['services'][port] in service:
                        os_scores[os_name] += 2
                        
            # Method 4: Response pattern analysis
            response_pattern = self.get_response_pattern(ip)
            if response_pattern:
                if "Windows" in response_pattern:
                    os_scores['Windows'] += 2
                elif "Linux" in response_pattern:
                    os_scores['Linux'] += 2
                elif "Darwin" in response_pattern:
                    os_scores['MacOS'] += 2
                    
            # Determine most likely OS
            if os_scores:
                likely_os, score = max(os_scores.items(), key=lambda x: x[1])
                confidence = min(100, int((score / 10) * 100))  # Calculate confidence percentage
                
                if score > 0:
                    os_guess = f"{likely_os} ({confidence}% confidence)"
                    device_info['os_guess'] = os_guess
                    self.os_detected.emit(ip, os_guess)
                    
        except Exception as e:
            self.add_log_message(f"OS detection error for {ip}: {str(e)}")
            
    def get_response_pattern(self, ip):
        """Get response pattern from host for OS detection"""
        try:
            if sys.platform.startswith('win'):
                cmd = f"ping -n 1 -w 1000 {ip}"
            else:
                cmd = f"ping -c 1 -W 1 {ip}"
                
            output = subprocess.check_output(cmd, shell=True).decode('utf-8')
            
            # Look for OS-specific patterns in response
            if "bytes=32" in output:  # Windows pattern
                return "Windows"
            elif "64 bytes" in output:  # Unix/Linux pattern
                return "Linux"
            elif "Darwin" in output:  # MacOS pattern
                return "Darwin"
                
        except:
            pass
        return None
        
    def analyze_service_fingerprint(self, ip, port, service):
        """Analyze service fingerprint for OS hints"""
        try:
            if not service:
                return None
                
            # HTTP server analysis
            if port in [80, 443]:
                response = requests.get(f"http{'s' if port == 443 else ''}://{ip}:{port}/",
                                     timeout=2,
                                     verify=False)
                server = response.headers.get('Server', '')
                
                if 'IIS' in server:
                    return 'Windows'
                elif 'Apache' in server:
                    return 'Linux'
                elif 'nginx' in server:
                    return 'Linux'
                    
            # SSH analysis
            elif port == 22:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                sock.connect((ip, port))
                banner = sock.recv(1024).decode('utf-8', errors='ignore')
                sock.close()
                
                if 'OpenSSH' in banner:
                    if 'Windows' in banner:
                        return 'Windows'
                    else:
                        return 'Linux'
                        
        except:
            pass
        return None

    def toggle_monitoring(self, state):
        """Toggle continuous network monitoring"""
        self.monitoring_active = bool(state)
        if self.monitoring_active:
            self.monitor_timer.start(60000)  # Check every minute
            self.add_log_message("Continuous monitoring enabled")
        else:
            self.monitor_timer.stop()
            self.add_log_message("Continuous monitoring disabled")
            
    def check_device_status(self):
        """Check status of known devices"""
        if not self.devices:
            return
        
        self.add_log_message("Checking device status...")
        for device in self.devices:
            ip = device['ip']
            is_alive = bool(self.ping_host(ip))
            self.device_status_changed.emit(ip, is_alive)
            
            if is_alive:
                device['last_seen'] = datetime.now().strftime("%H:%M:%S")
            
            # Update display
            self.update_device_display(device)

    def update_device_display(self, device):
        """Update device display in results table"""
        for row in range(self.results_table.rowCount()):
            if self.results_table.item(row, 0).text() == device['ip']:
                self.results_table.item(row, 4).setText(device['last_seen'])
                break

    @pyqtSlot(int)
    def update_progress(self, value):
        """Update progress bar value"""
        self.progress_bar.setValue(value)
    
    @pyqtSlot()
    def on_scan_complete(self):
        """Handle scan completion"""
        self.scanning = False
        self.scan_button.setText("Start Scan")
        self.status_label.setText("Scan completed")
        self.progress_bar.setValue(100)
        
        # Log results
        self.add_log_message(f"Scan completed. Found {len(self.devices)} devices.")
    
    @pyqtSlot(dict)
    def on_device_found(self, device_info):
        """Handle newly found device"""
        # Add to devices list
        self.devices.append(device_info)
        
        # Add to results table
        row = self.results_table.rowCount()
        self.results_table.insertRow(row)
        
        # Set data in table
        self.results_table.setItem(row, 0, QTableWidgetItem(device_info['ip']))
        self.results_table.setItem(row, 1, QTableWidgetItem(device_info['mac'] or 'Unknown'))
        self.results_table.setItem(row, 2, QTableWidgetItem(device_info['vendor']))
        self.results_table.setItem(row, 3, QTableWidgetItem(str(device_info['response_time'])))
        self.results_table.setItem(row, 4, QTableWidgetItem(device_info['last_seen']))
        self.results_table.setItem(row, 5, QTableWidgetItem(device_info['hostname']))
        self.results_table.setItem(row, 6, QTableWidgetItem(', '.join(map(str, device_info['open_ports']))))
        self.results_table.setItem(row, 7, QTableWidgetItem(device_info['os_guess']))
        
        # Enable export button
        self.export_button.setEnabled(True)

    def add_log_message(self, message):
        """Add a message to the log with safety checks"""
        try:
            timestamp = datetime.now().strftime("%H:%M:%S")
            if hasattr(self, 'log_text') and self.log_text is not None:
                self.log_text.append(f"[{timestamp}] {message}")
                # Ensure the new message is visible
                self.log_text.ensureCursorVisible()
            else:
                print(f"[{timestamp}] {message}")  # Fallback to console logging
        except Exception as e:
            print(f"Logging error: {str(e)}")  # Fallback error handling

    # Make sure show_error is called from the main thread
    def show_error(self, message):
        """Show an error message"""
        # Use invokeMethod to safely call from any thread
        QMetaObject.invokeMethod(self, "_show_error_main_thread", 
                                Qt.QueuedConnection,
                                Q_ARG(str, message))
    
    @pyqtSlot(str)
    def _show_error_main_thread(self, message):
        QMessageBox.critical(self, "Error", message)
    
    def export_results(self):
        """Export scan results to file"""
        try:
            file_name, selected_filter = QFileDialog.getSaveFileName(
                self,
                "Export Results",
                "",
                "HTML Report (*.html);;CSV Files (*.csv);;JSON Files (*.json);;All Files (*.*)"
            )
            
            if not file_name:
                return
                
            if file_name.endswith('.html'):
                report = self.generate_html_report()
                with open(file_name, 'w', encoding='utf-8') as f:
                    f.write(report)
            elif file_name.endswith('.csv'):
                self.export_to_csv(file_name)
            elif file_name.endswith('.json'):
                self.export_to_json(file_name)
            else:
                # Default to HTML
                if not '.' in file_name:
                    file_name += '.html'
                report = self.generate_html_report()
                with open(file_name, 'w', encoding='utf-8') as f:
                    f.write(report)
                    
            self.add_log_message(f"Results exported to {file_name}")
            
        except Exception as e:
            self.show_error(f"Export error: {str(e)}")

    def export_to_csv(self, filename):
        """Export results to CSV file"""
        with open(filename, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=[
                'ip', 'mac', 'vendor', 'response_time', 'last_seen',
                'hostname', 'open_ports', 'os_guess', 'vulnerabilities'
            ])
            writer.writeheader()
            writer.writerows(self.devices)

    def export_to_json(self, filename):
        """Export results to JSON file"""
        with open(filename, 'w') as f:
            json.dump(self.devices, f, indent=2)

    def generate_html_report(self):
        """Generate HTML report data"""
        # ... existing HTML report generation code ...

    def update_port_scan_progress(self, ip, progress):
        """Update port scan progress"""
        if progress == 100:
            self.port_scan_button.setText("Port Scan Selected")
            self.status_label.setText("Port scan completed")
        else:
            self.status_label.setText(f"Scanning ports for {ip}: {progress}%")

    def on_service_detected(self, ip, port, service):
        """Handle detected service"""
        self.add_log_message(f"Found {service} on {ip}:{port}")

    def on_vulnerability_detected(self, ip, vuln):
        """Handle detected vulnerability"""
        self.add_log_message(f"Found vulnerability: {vuln} on {ip}")

    def on_os_detected(self, ip, os):
        """Handle detected OS"""
        self.add_log_message(f"Detected OS: {os} on {ip}")

    def on_device_status_changed(self, ip, is_alive):
        """Handle device status changes"""
        status = "Online" if is_alive else "Offline"
        self.add_log_message(f"Device {ip} is {status}")
        
        # Update device display
        for row in range(self.results_table.rowCount()):
            if self.results_table.item(row, 0).text() == ip:
                # Update status indication (e.g., change row color)
                for col in range(self.results_table.columnCount()):
                    item = self.results_table.item(row, col)
                    if item:
                        item.setBackground(Qt.green if is_alive else Qt.red)

    def update_vulnerability_database(self):
        """Initialize and update the vulnerability database"""
        try:
            # Initialize basic vulnerability database
            self.vulnerability_db = {
                'SMB': {
                    'MS17-010': {
                        'description': 'EternalBlue SMB Remote Code Execution',
                        'cvss': 9.3,
                        'ports': [445],
                        'check': self.check_eternal_blue
                    }
                },
                'HTTP': {
                    'CVE-2021-44228': {
                        'description': 'Log4j Remote Code Execution (Log4Shell)',
                        'cvss': 10.0,
                        'ports': [80, 443, 8080],
                        'check': self.check_log4j
                    },
                    'CVE-2021-45046': {
                        'description': 'Log4j Remote Code Execution',
                        'cvss': 9.0,
                        'ports': [80, 443, 8080],
                        'check': self.check_log4j
                    }
                },
                'SSH': {
                    'CVE-2021-28041': {
                        'description': 'OpenSSH Privilege Escalation',
                        'cvss': 7.8,
                        'ports': [22],
                        'check': None
                    },
                    'CVE-2021-41617': {
                        'description': 'OpenSSH Authentication Bypass',
                        'cvss': 7.5,
                        'ports': [22],
                        'check': None
                    }
                },
                'FTP': {
                    'CVE-2021-3226': {
                        'description': 'vsftpd Denial of Service',
                        'cvss': 5.0,
                        'ports': [21],
                        'check': None
                    }
                }
            }
            
            # Add methods for vulnerability checks
            self.vuln_checks = {
                'eternal_blue': self.check_eternal_blue,
                'log4j': self.check_log4j
            }
            
            self.add_log_message("Vulnerability database initialized")
            
        except Exception as e:
            self.add_log_message(f"Error initializing vulnerability database: {str(e)}")
            
    def check_eternal_blue(self, ip):
        """Check for EternalBlue vulnerability (MS17-010)"""
        try:
            # Basic check for SMB vulnerability
            if not self.check_port(ip, 445):
                return False
                
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((ip, 445))
            
            # SMB protocol negotiation
            negotiate_proto_request = bytes([
                0x00, 0x00, 0x00, 0x85, 0xFF, 0x53, 0x4D, 0x42,
                0x72, 0x00, 0x00, 0x00, 0x00, 0x18, 0x53, 0xC0
            ] + [0x00] * 12 + [
                0xFF, 0xFE, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00
            ])
            
            sock.send(negotiate_proto_request)
            response = sock.recv(1024)
            
            # Check for vulnerable response pattern
            if len(response) >= 40 and response[39] == 0xFF:
                return True
                
            return False
            
        except:
            return False
        finally:
            try:
                sock.close()
            except:
                pass
                
    def check_log4j(self, ip, port):
        """Check for Log4j vulnerability (CVE-2021-44228)"""
        try:
            if not self.check_port(ip, port):
                return False
                
            # Test string that would trigger Log4j vulnerability
            test_payload = "${jndi:ldap://127.0.0.1:1389/Exploit}"
            
            # Headers to test
            headers = {
                'User-Agent': test_payload,
                'X-Api-Version': test_payload,
                'Referer': test_payload
            }
            
            # Make request with test payload
            url = f"http://{ip}:{port}/"
            response = requests.get(url, headers=headers, timeout=2)
            
            # Check for potential vulnerability indicators
            if response.status_code in [500, 404]:
                return True
                
            return False
            
        except:
            return False
            
    def check_ssh_vuln(self, ip):
        """Check for SSH vulnerabilities"""
        try:
            if not self.check_port(ip, 22):
                return False
                
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((ip, 22))
            
            # Get SSH banner
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            
            # Check for vulnerable versions
            vulnerable_versions = ['OpenSSH_7', 'OpenSSH_6']
            for version in vulnerable_versions:
                if version in banner:
                    return True
                    
            return False
            
        except:
            return False
        finally:
            try:
                sock.close()
            except:
                pass
                
    def check_ftp_vuln(self, ip):
        """Check for FTP vulnerabilities"""
        try:
            if not self.check_port(ip, 21):
                return False
                
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((ip, 21))
            
            # Get FTP banner
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            
            # Check for vulnerable versions
            vulnerable_versions = ['vsftpd 2.3.4', 'vsftpd 2.3.5']
            for version in banner.split('\n'):
                for vuln_ver in vulnerable_versions:
                    if vuln_ver in version:
                        return True
                        
            return False
            
        except:
            return False
        finally:
            try:
                sock.close()
            except:
                pass

    def ping_host(self, ip):
        """Ping a host and return response time in milliseconds"""
        try:
            # Determine the best ping command for the platform
            if sys.platform.startswith('win'):
                ping_cmd = f"ping -n 1 -w 1000 {ip}"
            else:
                ping_cmd = f"ping -c 1 -W 1 {ip}"
            
            start_time = time.time()
            result = subprocess.run(
                ping_cmd, 
                shell=True, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE,
                text=True
            )
            end_time = time.time()
            
            # Check if ping was successful
            if result.returncode == 0:
                # Calculate response time
                response_time = (end_time - start_time) * 1000  # Convert to ms
                return round(response_time, 2)
            
            return None
            
        except Exception as e:
            self.add_log_message(f"Ping error for {ip}: {str(e)}")
            return None

    def get_mac_from_ip(self, ip):
        """Get MAC address for an IP using ARP"""
        try:
            if SCAPY_AVAILABLE:
                # Use Scapy for ARP resolution
                ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), timeout=2, verbose=0)
                if ans:
                    return ans[0][1].hwsrc
            else:
                # Fallback to system ARP table
                if sys.platform.startswith('win'):
                    # Windows
                    cmd = f"arp -a {ip}"
                    output = subprocess.check_output(cmd, shell=True).decode('utf-8')
                    matches = re.findall(r"([0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2})", output)
                    if matches:
                        return matches[0]
                else:
                    # Linux/Unix
                    cmd = f"arp -n {ip}"
                    output = subprocess.check_output(cmd, shell=True).decode('utf-8')
                    matches = re.findall(r"([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})", output)
                    if matches:
                        return matches[0]
        
            return None
            
        except Exception as e:
            self.add_log_message(f"MAC lookup error for {ip}: {str(e)}")
            return None

    def get_ping_ttl(self, ip):
        """Get TTL value from ping response for OS detection"""
        try:
            if sys.platform.startswith('win'):
                cmd = f"ping -n 1 {ip}"
            else:
                cmd = f"ping -c 1 {ip}"
            
            output = subprocess.check_output(cmd, shell=True).decode('utf-8')
            
            # Try to extract TTL value
            ttl_match = re.search(r"TTL=(\d+)", output, re.IGNORECASE)
            if ttl_match:
                return int(ttl_match.group(1))
            
            return None
            
        except Exception:
            return None

    def check_port(self, ip, port):
        """Check if a port is open"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((ip, port))
            sock.close()
            return result == 0
        except:
            return False

    def identify_service(self, ip, port):
        """Identify service running on a port"""
        try:
            # Common port mappings
            common_ports = {
                21: "FTP",
                22: "SSH",
                23: "Telnet",
                25: "SMTP",
                53: "DNS",
                80: "HTTP",
                443: "HTTPS",
                445: "SMB",
                3306: "MySQL",
                3389: "RDP",
                5432: "PostgreSQL"
            }
            
            service = common_ports.get(port, "Unknown")
            
            # Try to get service banner
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                sock.connect((ip, port))
                
                # Send HTTP GET for web ports
                if port in [80, 443, 8080]:
                    sock.send(b"GET / HTTP/1.0\r\n\r\n")
                
                # Read response
                banner = sock.recv(1024).decode('utf-8', errors='ignore')
                sock.close()
                
                # Parse banner for common services
                if "SSH" in banner:
                    service = f"SSH ({banner.split()[0]})"
                elif "FTP" in banner:
                    service = f"FTP ({banner.split()[0]})"
                elif "HTTP" in banner:
                    service = f"HTTP ({banner.split()[0]})"
                
            except:
                pass
            
            return service
            
        except Exception as e:
            self.add_log_message(f"Service detection error on {ip}:{port}: {str(e)}")
            return "Unknown"

def main():
    """Main application entry point"""
    app = QApplication(sys.argv)
    scanner = NetworkScanner()
    scanner.show()
    sys.exit(app.exec_())

if __name__ == '__main__':
    main()
    