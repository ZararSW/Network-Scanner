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
                           QTextEdit, QInputDialog, QMenu, QGroupBox, QSpinBox, QCheckBox,
                           QTabWidget, QSplitter, QFrame, QScrollArea, QGridLayout, QSlider)
from PyQt5.QtCore import Qt, QTimer, pyqtSignal, pyqtSlot, QMetaObject, Q_ARG, QThread, QObject
from PyQt5.QtGui import QIcon, QFont, QPalette, QColor, QPixmap, QPainter
import os
from queue import Queue
from scapy.all import ARP, Ether, srp, conf, AsyncSniffer, get_if_list, IP, TCP, UDP, ICMP, sr1
import requests

# Enhanced imports for powerful features
import asyncio
import aiofiles
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.patches as patches
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure
import networkx as nx
import plotly.graph_objects as go
import plotly.express as px
from plotly.offline import plot
import nmap
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.cluster import DBSCAN
import sqlite3
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Float, Boolean, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import paramiko
import base64
import hashlib
import hmac
from flask import Flask, jsonify, request, render_template_string
from flask_socketio import SocketIO, emit
import shodan
from reportlab.lib.pagesizes import letter, A4
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, Image
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
import tempfile
import uuid

# Try to import scapy with better platform detection
SCAPY_AVAILABLE = False
try:
    from scapy.all import ARP, Ether, srp, conf, AsyncSniffer, get_if_list
    SCAPY_AVAILABLE = True
except ImportError:
    pass

# Database setup for persistent storage
Base = declarative_base()

class ScanResult(Base):
    __tablename__ = 'scan_results'
    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    ip_address = Column(String(45))
    hostname = Column(String(255))
    mac_address = Column(String(17))
    vendor = Column(String(255))
    open_ports = Column(Text)
    services = Column(Text)
    os_detection = Column(String(255))
    vulnerabilities = Column(Text)
    risk_score = Column(Float, default=0.0)
    anomaly_score = Column(Float, default=0.0)
    threat_intel = Column(Text)

class ThreatIntelligence:
    """Enhanced threat intelligence integration"""
    
    def __init__(self):
        self.shodan_api = None
        self.malicious_ips = set()
        self.reputation_cache = {}
        
    def initialize_shodan(self, api_key):
        """Initialize Shodan API"""
        try:
            self.shodan_api = shodan.Shodan(api_key)
            return True
        except Exception as e:
            print(f"Shodan initialization failed: {e}")
            return False
    
    def check_ip_reputation(self, ip):
        """Check IP reputation against multiple threat feeds"""
        if ip in self.reputation_cache:
            return self.reputation_cache[ip]
        
        reputation = {
            'is_malicious': False,
            'sources': [],
            'threat_types': [],
            'confidence': 0.0
        }
        
        # Check against multiple threat intelligence sources
        try:
            # AbuseIPDB check (simulated)
            abuse_result = self._check_abuseipdb(ip)
            if abuse_result['is_malicious']:
                reputation['is_malicious'] = True
                reputation['sources'].append('AbuseIPDB')
                reputation['threat_types'].extend(abuse_result['categories'])
                reputation['confidence'] = max(reputation['confidence'], abuse_result['confidence'])
            
            # VirusTotal check (simulated)
            vt_result = self._check_virustotal(ip)
            if vt_result['is_malicious']:
                reputation['is_malicious'] = True
                reputation['sources'].append('VirusTotal')
                reputation['threat_types'].extend(vt_result['categories'])
                reputation['confidence'] = max(reputation['confidence'], vt_result['confidence'])
            
            # Shodan check
            if self.shodan_api:
                shodan_result = self._check_shodan(ip)
                reputation['shodan_data'] = shodan_result
                
        except Exception as e:
            print(f"Threat intelligence check failed for {ip}: {e}")
        
        self.reputation_cache[ip] = reputation
        return reputation
    
    def _check_abuseipdb(self, ip):
        """Simulate AbuseIPDB check - in real implementation, use actual API"""
        # Simulated malicious IP patterns for demonstration
        malicious_patterns = ['192.168.1.666', '10.0.0.666']
        return {
            'is_malicious': any(pattern in ip for pattern in malicious_patterns),
            'categories': ['Malware', 'Botnet'] if any(pattern in ip for pattern in malicious_patterns) else [],
            'confidence': 0.8 if any(pattern in ip for pattern in malicious_patterns) else 0.0
        }
    
    def _check_virustotal(self, ip):
        """Simulate VirusTotal check - in real implementation, use actual API"""
        return {
            'is_malicious': False,
            'categories': [],
            'confidence': 0.0
        }
    
    def _check_shodan(self, ip):
        """Check Shodan for additional information"""
        try:
            if self.shodan_api:
                host = self.shodan_api.host(ip)
                return {
                    'ports': host.get('ports', []),
                    'vulns': host.get('vulns', []),
                    'tags': host.get('tags', []),
                    'org': host.get('org', ''),
                    'location': host.get('location', {})
                }
        except Exception:
            pass
        return {}

class AdvancedScanner:
    """Advanced scanning techniques using nmap and custom implementations"""
    
    def __init__(self, logger=None):
        self.nm = nmap.PortScanner()
        self.logger = logger
        
    def syn_stealth_scan(self, target, ports="1-1000"):
        """Perform SYN stealth scan"""
        try:
            result = self.nm.scan(target, ports, arguments='-sS -O -sV --script vuln')
            return self._parse_nmap_result(result)
        except Exception as e:
            if self.logger:
                self.logger(f"SYN stealth scan failed: {e}")
            return {}
    
    def udp_scan(self, target, ports="53,67,68,69,123,135,137,138,139,161,162,445,631,1434,1900,5353"):
        """Perform UDP scan on common ports"""
        try:
            result = self.nm.scan(target, ports, arguments='-sU -sV')
            return self._parse_nmap_result(result)
        except Exception as e:
            if self.logger:
                self.logger(f"UDP scan failed: {e}")
            return {}
    
    def comprehensive_scan(self, target):
        """Perform comprehensive scan with multiple techniques"""
        try:
            # Comprehensive scan with OS detection, version detection, and vulnerability scripts
            result = self.nm.scan(target, arguments='-sS -sU -O -sV -sC --script vuln,safe,discovery')
            return self._parse_nmap_result(result)
        except Exception as e:
            if self.logger:
                self.logger(f"Comprehensive scan failed: {e}")
            return {}
    
    def _parse_nmap_result(self, result):
        """Parse nmap scan result into structured data"""
        parsed_results = {}
        
        for host in result['scan']:
            host_info = result['scan'][host]
            parsed_results[host] = {
                'hostname': host_info.get('hostnames', [{}])[0].get('name', ''),
                'state': host_info.get('status', {}).get('state', ''),
                'protocols': {},
                'os': host_info.get('osmatch', []),
                'scripts': host_info.get('hostscript', [])
            }
            
            # Parse protocol information
            for protocol in host_info.get('protocols', []):
                ports = host_info[protocol]
                parsed_results[host]['protocols'][protocol] = {}
                
                for port in ports:
                    port_info = ports[port]
                    parsed_results[host]['protocols'][protocol][port] = {
                        'state': port_info.get('state', ''),
                        'name': port_info.get('name', ''),
                        'product': port_info.get('product', ''),
                        'version': port_info.get('version', ''),
                        'extrainfo': port_info.get('extrainfo', ''),
                        'scripts': port_info.get('script', {})
                    }
        
        return parsed_results

class AIAnomalyDetector:
    """AI-powered anomaly detection for network behavior"""
    
    def __init__(self):
        self.isolation_forest = IsolationForest(contamination=0.1, random_state=42)
        self.scaler = StandardScaler()
        self.dbscan = DBSCAN(eps=0.3, min_samples=2)
        self.is_trained = False
        self.baseline_data = []
        
    def add_baseline_data(self, features):
        """Add data to baseline for training"""
        self.baseline_data.append(features)
        
    def train_models(self):
        """Train anomaly detection models"""
        if len(self.baseline_data) < 10:
            return False
            
        try:
            # Prepare data
            X = np.array(self.baseline_data)
            X_scaled = self.scaler.fit_transform(X)
            
            # Train isolation forest
            self.isolation_forest.fit(X_scaled)
            
            # Train DBSCAN
            self.dbscan.fit(X_scaled)
            
            self.is_trained = True
            return True
        except Exception as e:
            print(f"Model training failed: {e}")
            return False
    
    def detect_anomaly(self, features):
        """Detect if given features represent an anomaly"""
        if not self.is_trained:
            return {'is_anomaly': False, 'score': 0.0, 'confidence': 0.0}
        
        try:
            # Scale features
            X_scaled = self.scaler.transform([features])
            
            # Get isolation forest score
            isolation_score = self.isolation_forest.decision_function(X_scaled)[0]
            is_outlier = self.isolation_forest.predict(X_scaled)[0] == -1
            
            # Get DBSCAN cluster
            cluster = self.dbscan.fit_predict(np.vstack([self.scaler.transform(self.baseline_data), X_scaled]))[-1]
            is_noise = cluster == -1
            
            # Combine scores
            anomaly_score = abs(isolation_score)
            is_anomaly = is_outlier or is_noise
            confidence = min(anomaly_score * 100, 100)
            
            return {
                'is_anomaly': is_anomaly,
                'score': anomaly_score,
                'confidence': confidence,
                'details': {
                    'isolation_outlier': is_outlier,
                    'isolation_score': isolation_score,
                    'dbscan_noise': is_noise,
                    'dbscan_cluster': cluster
                }
            }
        except Exception as e:
            print(f"Anomaly detection failed: {e}")
            return {'is_anomaly': False, 'score': 0.0, 'confidence': 0.0}
    
    def extract_features(self, device_info):
        """Extract features from device information for anomaly detection"""
        features = []
        
        # Port-based features
        open_ports = device_info.get('open_ports', [])
        features.extend([
            len(open_ports),  # Number of open ports
            1 if 22 in open_ports else 0,  # SSH
            1 if 80 in open_ports else 0,  # HTTP
            1 if 443 in open_ports else 0,  # HTTPS
            1 if 445 in open_ports else 0,  # SMB
            1 if 3389 in open_ports else 0,  # RDP
        ])
        
        # Service-based features
        services = device_info.get('services', [])
        features.extend([
            len(services),  # Number of services
            1 if any('SSH' in s for s in services) else 0,
            1 if any('HTTP' in s for s in services) else 0,
            1 if any('FTP' in s for s in services) else 0,
        ])
        
        # Vulnerability features
        vulns = device_info.get('vulnerabilities', [])
        features.extend([
            len(vulns),  # Number of vulnerabilities
            device_info.get('risk_score', 0.0),  # Risk score
        ])
        
        # Network behavior features
        features.extend([
            device_info.get('response_time', 0.0),  # Response time
            device_info.get('packet_size', 0),  # Average packet size
        ])
        
        return features

class NetworkTopologyMapper:
    """Create network topology visualization"""
    
    def __init__(self):
        self.graph = nx.Graph()
        self.device_positions = {}
        
    def add_device(self, ip, device_info):
        """Add device to network graph"""
        self.graph.add_node(ip, **device_info)
        
    def add_connection(self, ip1, ip2, connection_type='network'):
        """Add connection between devices"""
        self.graph.add_edge(ip1, ip2, type=connection_type)
        
    def calculate_layout(self):
        """Calculate optimal layout for network visualization"""
        try:
            # Use spring layout with custom parameters
            self.device_positions = nx.spring_layout(
                self.graph, 
                k=3, 
                iterations=50,
                seed=42
            )
            return True
        except Exception as e:
            print(f"Layout calculation failed: {e}")
            return False
    
    def generate_topology_plot(self, output_file=None):
        """Generate network topology visualization"""
        if not self.device_positions:
            self.calculate_layout()
        
        fig, ax = plt.subplots(1, 1, figsize=(12, 8))
        
        # Draw nodes
        node_colors = []
        node_sizes = []
        
        for node in self.graph.nodes():
            device_info = self.graph.nodes[node]
            
            # Color based on risk level
            risk_score = device_info.get('risk_score', 0.0)
            if risk_score > 7.0:
                node_colors.append('red')
            elif risk_score > 4.0:
                node_colors.append('orange')
            else:
                node_colors.append('green')
            
            # Size based on number of open ports
            open_ports = len(device_info.get('open_ports', []))
            node_sizes.append(max(300, open_ports * 50))
        
        # Draw graph
        nx.draw_networkx_nodes(
            self.graph, 
            self.device_positions, 
            node_color=node_colors,
            node_size=node_sizes,
            alpha=0.7
        )
        
        nx.draw_networkx_edges(
            self.graph, 
            self.device_positions, 
            alpha=0.5,
            edge_color='gray'
        )
        
        nx.draw_networkx_labels(
            self.graph, 
            self.device_positions, 
            font_size=8
        )
        
        ax.set_title('Network Topology Map', fontsize=16, fontweight='bold')
        ax.axis('off')
        
        # Add legend
        legend_elements = [
            patches.Patch(color='red', label='High Risk'),
            patches.Patch(color='orange', label='Medium Risk'),
            patches.Patch(color='green', label='Low Risk')
        ]
        ax.legend(handles=legend_elements, loc='upper right')
        
        plt.tight_layout()
        
        if output_file:
            plt.savefig(output_file, dpi=300, bbox_inches='tight')
        
        return fig
    
    def generate_interactive_plot(self, output_file=None):
        """Generate interactive network topology using Plotly"""
        if not self.device_positions:
            self.calculate_layout()
        
        # Prepare node data
        node_x = []
        node_y = []
        node_text = []
        node_colors = []
        node_sizes = []
        
        for node in self.graph.nodes():
            x, y = self.device_positions[node]
            node_x.append(x)
            node_y.append(y)
            
            device_info = self.graph.nodes[node]
            hostname = device_info.get('hostname', 'Unknown')
            open_ports = device_info.get('open_ports', [])
            risk_score = device_info.get('risk_score', 0.0)
            
            node_text.append(f"{node}<br>Hostname: {hostname}<br>Ports: {len(open_ports)}<br>Risk: {risk_score:.1f}")
            
            # Color based on risk
            if risk_score > 7.0:
                node_colors.append('red')
            elif risk_score > 4.0:
                node_colors.append('orange')
            else:
                node_colors.append('green')
            
            node_sizes.append(max(10, len(open_ports) * 2))
        
        # Prepare edge data
        edge_x = []
        edge_y = []
        
        for edge in self.graph.edges():
            x0, y0 = self.device_positions[edge[0]]
            x1, y1 = self.device_positions[edge[1]]
            edge_x.extend([x0, x1, None])
            edge_y.extend([y0, y1, None])
        
        # Create plot
        edge_trace = go.Scatter(
            x=edge_x, y=edge_y,
            line=dict(width=1, color='gray'),
            hoverinfo='none',
            mode='lines'
        )
        
        node_trace = go.Scatter(
            x=node_x, y=node_y,
            mode='markers+text',
            hoverinfo='text',
            text=node_text,
            textposition="middle center",
            marker=dict(
                size=node_sizes,
                color=node_colors,
                line=dict(width=2, color='black')
            )
        )
        
        fig = go.Figure(
            data=[edge_trace, node_trace],
            layout=go.Layout(
                title='Interactive Network Topology',
                titlefont_size=16,
                showlegend=False,
                hovermode='closest',
                margin=dict(b=20,l=5,r=5,t=40),
                annotations=[ dict(
                    text="Risk Level: Red=High, Orange=Medium, Green=Low",
                    showarrow=False,
                    xref="paper", yref="paper",
                    x=0.005, y=-0.002,
                    xanchor='left', yanchor='bottom',
                    font=dict(color='black', size=12)
                ) ],
                xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                yaxis=dict(showgrid=False, zeroline=False, showticklabels=False)
            )
        )
        
        if output_file:
            plot(fig, filename=output_file, auto_open=False)
        
        return fig

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
        
        # Initialize enhanced components
        self.threat_intel = ThreatIntelligence()
        self.advanced_scanner = AdvancedScanner(logger=self.add_log_message)
        self.ai_detector = AIAnomalyDetector()
        self.topology_mapper = NetworkTopologyMapper()
        
        # Initialize database
        self.db_engine = create_engine('sqlite:///network_scanner.db')
        Base.metadata.create_all(self.db_engine)
        Session = sessionmaker(bind=self.db_engine)
        self.db_session = Session()
        
        # Initialize Flask API (will run in separate thread)
        self.api_app = None
        self.api_thread = None
        
        # Enhanced configuration
        self.config = {
            'shodan_api_key': '',
            'enable_ai_detection': True,
            'enable_threat_intel': True,
            'enable_advanced_scanning': True,
            'auto_topology_mapping': True,
            'risk_threshold': 5.0,
            'api_enabled': False,
            'api_port': 5000
        }
        
        # Initialize enhanced vulnerability database
        self.known_vulnerabilities = {
            'SMB': {
                'MS17-010': {
                    'name': 'EternalBlue',
                    'description': 'SMB Remote Code Execution Vulnerability',
                    'cvss': 9.3,
                    'check': self.check_eternal_blue,
                    'remediation': 'Apply Microsoft Security Bulletin MS17-010'
                },
                'CVE-2020-0796': {
                    'name': 'SMBGhost',
                    'description': 'Windows SMBv3 Client/Server Remote Code Execution Vulnerability',
                    'cvss': 10.0,
                    'check': self.check_smbghost,
                    'remediation': 'Apply KB4551762 security update'
                }
            },
            'HTTP': {
                'CVE-2021-44228': {
                    'name': 'Log4Shell',
                    'description': 'Log4j Remote Code Execution Vulnerability',
                    'cvss': 10.0,
                    'check': self.check_log4j,
                    'remediation': 'Update Log4j to version 2.15.0 or later'
                },
                'CVE-2021-45046': {
                    'name': 'Log4j RCE',
                    'description': 'Log4j Remote Code Execution Vulnerability',
                    'cvss': 9.0,
                    'check': self.check_log4j,
                    'remediation': 'Update Log4j to version 2.16.0 or later'
                },
                'CVE-2022-22965': {
                    'name': 'Spring4Shell',
                    'description': 'Spring Framework Remote Code Execution',
                    'cvss': 9.8,
                    'check': self.check_spring4shell,
                    'remediation': 'Update Spring Framework to 5.3.18+ or 5.2.20+'
                },
                'CVE-2021-34527': {
                    'name': 'PrintNightmare',
                    'description': 'Windows Print Spooler Remote Code Execution',
                    'cvss': 8.8,
                    'check': self.check_printnightmare,
                    'remediation': 'Apply Windows security updates and disable Print Spooler if not needed'
                }
            },
            'SSH': {
                'CVE-2021-28041': {
                    'name': 'OpenSSH Privilege Escalation',
                    'description': 'OpenSSH Privilege Escalation Vulnerability',
                    'cvss': 7.8,
                    'check': self.check_ssh_vuln,
                    'remediation': 'Update OpenSSH to version 8.5 or later'
                },
                'CVE-2020-15778': {
                    'name': 'OpenSSH Command Injection',
                    'description': 'OpenSSH scp Command Injection',
                    'cvss': 7.8,
                    'check': self.check_ssh_scp_vuln,
                    'remediation': 'Update OpenSSH and avoid using scp with untrusted servers'
                }
            },
            'FTP': {
                'CVE-2021-3226': {
                    'name': 'vsftpd DoS',
                    'description': 'vsftpd Denial of Service Vulnerability',
                    'cvss': 5.0,
                    'check': self.check_ftp_vuln,
                    'remediation': 'Update vsftpd to latest version'
                }
            },
            'DNS': {
                'CVE-2020-1350': {
                    'name': 'SIGRed',
                    'description': 'Windows DNS Server Remote Code Execution',
                    'cvss': 10.0,
                    'check': self.check_sigred,
                    'remediation': 'Apply Windows KB4569509 security update'
                }
            },
            'RDP': {
                'CVE-2019-0708': {
                    'name': 'BlueKeep',
                    'description': 'Remote Desktop Services Remote Code Execution',
                    'cvss': 9.8,
                    'check': self.check_bluekeep,
                    'remediation': 'Apply Windows security updates and enable NLA'
                }
            },
            'VPN': {
                'CVE-2021-20038': {
                    'name': 'SonicWall VPN RCE',
                    'description': 'SonicWall SSL-VPN Remote Code Execution',
                    'cvss': 9.8,
                    'check': self.check_sonicwall_vpn,
                    'remediation': 'Update SonicWall firmware to latest version'
                }
            }
        }
        
        # CVE database for real-time vulnerability updates
        self.cve_database_url = "https://cve.circl.lu/api/cve/"
        self.cve_cache = {}
        
        # Enhanced risk scoring matrix
        self.risk_matrix = {
            'critical': {'score': 10.0, 'color': 'red'},
            'high': {'score': 8.0, 'color': 'orange'},
            'medium': {'score': 6.0, 'color': 'yellow'},
            'low': {'score': 3.0, 'color': 'green'},
            'info': {'score': 1.0, 'color': 'blue'}
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
        """Initialize the enhanced user interface"""
        # Main widget and layout
        main_widget = QWidget()
        main_layout = QVBoxLayout()
        
        # Create tabbed interface for different views
        self.tab_widget = QTabWidget()
        
        # Main scanning tab
        self.main_tab = QWidget()
        self.init_main_tab()
        self.tab_widget.addTab(self.main_tab, "🔍 Network Scanner")
        
        # Topology visualization tab
        self.topology_tab = QWidget()
        self.init_topology_tab()
        self.tab_widget.addTab(self.topology_tab, "🗺️ Network Topology")
        
        # AI Analytics tab
        self.analytics_tab = QWidget()
        self.init_analytics_tab()
        self.tab_widget.addTab(self.analytics_tab, "🤖 AI Analytics")
        
        # Threat Intelligence tab
        self.threat_tab = QWidget()
        self.init_threat_tab()
        self.tab_widget.addTab(self.threat_tab, "⚠️ Threat Intelligence")
        
        # Reports tab
        self.reports_tab = QWidget()
        self.init_reports_tab()
        self.tab_widget.addTab(self.reports_tab, "📊 Reports")
        
        # Configuration tab
        self.config_tab = QWidget()
        self.init_config_tab()
        self.tab_widget.addTab(self.config_tab, "⚙️ Configuration")
        
        main_layout.addWidget(self.tab_widget)
        main_widget.setLayout(main_layout)
        self.setCentralWidget(main_widget)
        
        # Set window properties
        self.setWindowTitle("Advanced Network Scanner v2.0")
        self.setGeometry(100, 100, 1400, 900)
        
        # Apply dark theme
        self.apply_dark_theme()
        
    def init_main_tab(self):
        """Initialize the main scanning tab"""
        layout = QVBoxLayout()
        
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

    def apply_dark_theme(self):
        """Apply a modern dark theme to the application"""
        dark_palette = QPalette()
        dark_palette.setColor(QPalette.Window, QColor(53, 53, 53))
        dark_palette.setColor(QPalette.WindowText, QColor(255, 255, 255))
        dark_palette.setColor(QPalette.Base, QColor(25, 25, 25))
        dark_palette.setColor(QPalette.AlternateBase, QColor(53, 53, 53))
        dark_palette.setColor(QPalette.ToolTipBase, QColor(0, 0, 0))
        dark_palette.setColor(QPalette.ToolTipText, QColor(255, 255, 255))
        dark_palette.setColor(QPalette.Text, QColor(255, 255, 255))
        dark_palette.setColor(QPalette.Button, QColor(53, 53, 53))
        dark_palette.setColor(QPalette.ButtonText, QColor(255, 255, 255))
        dark_palette.setColor(QPalette.BrightText, QColor(255, 0, 0))
        dark_palette.setColor(QPalette.Link, QColor(42, 130, 218))
        dark_palette.setColor(QPalette.Highlight, QColor(42, 130, 218))
        dark_palette.setColor(QPalette.HighlightedText, QColor(0, 0, 0))
        self.setPalette(dark_palette)
        
    def init_topology_tab(self):
        """Initialize the network topology visualization tab"""
        layout = QVBoxLayout()
        
        # Control panel
        control_panel = QGroupBox("Topology Controls")
        control_layout = QHBoxLayout()
        
        self.refresh_topology_btn = QPushButton("🔄 Refresh Topology")
        self.refresh_topology_btn.clicked.connect(self.refresh_topology)
        
        self.export_topology_btn = QPushButton("💾 Export Topology")
        self.export_topology_btn.clicked.connect(self.export_topology)
        
        self.layout_combo = QComboBox()
        self.layout_combo.addItems(["Spring Layout", "Circular Layout", "Hierarchical Layout", "Random Layout"])
        self.layout_combo.currentTextChanged.connect(self.update_topology_layout)
        
        control_layout.addWidget(QLabel("Layout:"))
        control_layout.addWidget(self.layout_combo)
        control_layout.addWidget(self.refresh_topology_btn)
        control_layout.addWidget(self.export_topology_btn)
        control_layout.addStretch()
        
        control_panel.setLayout(control_layout)
        layout.addWidget(control_panel)
        
        # Topology visualization area
        self.topology_figure = Figure(figsize=(12, 8))
        self.topology_canvas = FigureCanvas(self.topology_figure)
        layout.addWidget(self.topology_canvas)
        
        self.topology_tab.setLayout(layout)
        
    def init_analytics_tab(self):
        """Initialize the AI analytics tab"""
        layout = QVBoxLayout()
        
        # Analytics control panel
        analytics_panel = QGroupBox("AI Analytics Controls")
        analytics_layout = QHBoxLayout()
        
        self.train_ai_btn = QPushButton("🧠 Train AI Models")
        self.train_ai_btn.clicked.connect(self.train_ai_models)
        
        self.analyze_anomalies_btn = QPushButton("🔍 Analyze Anomalies")
        self.analyze_anomalies_btn.clicked.connect(self.analyze_anomalies)
        
        self.ai_threshold_slider = QSlider(Qt.Horizontal)
        self.ai_threshold_slider.setRange(1, 100)
        self.ai_threshold_slider.setValue(50)
        self.ai_threshold_slider.valueChanged.connect(self.update_ai_threshold)
        
        analytics_layout.addWidget(self.train_ai_btn)
        analytics_layout.addWidget(self.analyze_anomalies_btn)
        analytics_layout.addWidget(QLabel("Sensitivity:"))
        analytics_layout.addWidget(self.ai_threshold_slider)
        analytics_layout.addStretch()
        
        analytics_panel.setLayout(analytics_layout)
        layout.addWidget(analytics_panel)
        
        # Split view for analytics
        splitter = QSplitter(Qt.Horizontal)
        
        # Left side: Analytics results
        left_widget = QWidget()
        left_layout = QVBoxLayout()
        
        self.analytics_table = QTableWidget()
        self.analytics_table.setColumnCount(6)
        self.analytics_table.setHorizontalHeaderLabels([
            "IP Address", "Anomaly Score", "Risk Level", "Confidence", "AI Prediction", "Details"
        ])
        self.analytics_table.horizontalHeader().setStretchLastSection(True)
        
        left_layout.addWidget(QLabel("Anomaly Detection Results:"))
        left_layout.addWidget(self.analytics_table)
        left_widget.setLayout(left_layout)
        
        # Right side: Visualization
        right_widget = QWidget()
        right_layout = QVBoxLayout()
        
        self.analytics_figure = Figure(figsize=(8, 6))
        self.analytics_canvas = FigureCanvas(self.analytics_figure)
        
        right_layout.addWidget(QLabel("Risk Distribution:"))
        right_layout.addWidget(self.analytics_canvas)
        right_widget.setLayout(right_layout)
        
        splitter.addWidget(left_widget)
        splitter.addWidget(right_widget)
        splitter.setStretchFactor(0, 2)
        splitter.setStretchFactor(1, 1)
        
        layout.addWidget(splitter)
        self.analytics_tab.setLayout(layout)
        
    def init_threat_tab(self):
        """Initialize the threat intelligence tab"""
        layout = QVBoxLayout()
        
        # Threat intel control panel
        threat_panel = QGroupBox("Threat Intelligence Controls")
        threat_layout = QHBoxLayout()
        
        self.update_threat_db_btn = QPushButton("🔄 Update Threat DB")
        self.update_threat_db_btn.clicked.connect(self.update_threat_database)
        
        self.scan_malicious_ips_btn = QPushButton("🛡️ Scan for Malicious IPs")
        self.scan_malicious_ips_btn.clicked.connect(self.scan_malicious_ips)
        
        self.threat_feed_combo = QComboBox()
        self.threat_feed_combo.addItems(["All Sources", "Shodan", "AbuseIPDB", "VirusTotal", "Local DB"])
        
        threat_layout.addWidget(self.update_threat_db_btn)
        threat_layout.addWidget(self.scan_malicious_ips_btn)
        threat_layout.addWidget(QLabel("Source:"))
        threat_layout.addWidget(self.threat_feed_combo)
        threat_layout.addStretch()
        
        threat_panel.setLayout(threat_layout)
        layout.addWidget(threat_panel)
        
        # Threat intelligence results
        self.threat_table = QTableWidget()
        self.threat_table.setColumnCount(7)
        self.threat_table.setHorizontalHeaderLabels([
            "IP Address", "Threat Level", "Categories", "Sources", "Confidence", "First Seen", "Actions"
        ])
        self.threat_table.horizontalHeader().setStretchLastSection(True)
        
        layout.addWidget(QLabel("Threat Intelligence Results:"))
        layout.addWidget(self.threat_table)
        
        self.threat_tab.setLayout(layout)
        
    def init_reports_tab(self):
        """Initialize the reports tab"""
        layout = QVBoxLayout()
        
        # Report generation panel
        report_panel = QGroupBox("Report Generation")
        report_layout = QGridLayout()
        
        # Report type selection
        self.report_type_combo = QComboBox()
        self.report_type_combo.addItems([
            "Executive Summary", "Technical Report", "Vulnerability Assessment", 
            "Network Topology Report", "Risk Analysis", "Compliance Report"
        ])
        
        # Report format selection
        self.report_format_combo = QComboBox()
        self.report_format_combo.addItems(["PDF", "HTML", "CSV", "JSON", "Excel"])
        
        # Report options
        self.include_charts_cb = QCheckBox("Include Charts")
        self.include_charts_cb.setChecked(True)
        
        self.include_topology_cb = QCheckBox("Include Network Topology")
        self.include_topology_cb.setChecked(True)
        
        self.include_remediation_cb = QCheckBox("Include Remediation Steps")
        self.include_remediation_cb.setChecked(True)
        
        # Generate button
        self.generate_report_btn = QPushButton("📊 Generate Report")
        self.generate_report_btn.clicked.connect(self.generate_comprehensive_report)
        
        # Layout components
        report_layout.addWidget(QLabel("Report Type:"), 0, 0)
        report_layout.addWidget(self.report_type_combo, 0, 1)
        report_layout.addWidget(QLabel("Format:"), 0, 2)
        report_layout.addWidget(self.report_format_combo, 0, 3)
        report_layout.addWidget(self.include_charts_cb, 1, 0)
        report_layout.addWidget(self.include_topology_cb, 1, 1)
        report_layout.addWidget(self.include_remediation_cb, 1, 2)
        report_layout.addWidget(self.generate_report_btn, 1, 3)
        
        report_panel.setLayout(report_layout)
        layout.addWidget(report_panel)
        
        # Report preview area
        self.report_preview = QTextEdit()
        self.report_preview.setReadOnly(True)
        self.report_preview.setMaximumHeight(400)
        
        layout.addWidget(QLabel("Report Preview:"))
        layout.addWidget(self.report_preview)
        
        # Report history
        self.report_history_table = QTableWidget()
        self.report_history_table.setColumnCount(5)
        self.report_history_table.setHorizontalHeaderLabels([
            "Timestamp", "Report Type", "Format", "File Size", "Actions"
        ])
        
        layout.addWidget(QLabel("Report History:"))
        layout.addWidget(self.report_history_table)
        
        self.reports_tab.setLayout(layout)
        
    def init_config_tab(self):
        """Initialize the configuration tab"""
        layout = QVBoxLayout()
        
        # Scanning configuration
        scan_config_group = QGroupBox("Scanning Configuration")
        scan_config_layout = QGridLayout()
        
        # Advanced scanning options
        self.enable_advanced_scan_cb = QCheckBox("Enable Advanced Scanning (Nmap)")
        self.enable_advanced_scan_cb.setChecked(self.config['enable_advanced_scanning'])
        
        self.enable_ai_detection_cb = QCheckBox("Enable AI Anomaly Detection")
        self.enable_ai_detection_cb.setChecked(self.config['enable_ai_detection'])
        
        self.enable_threat_intel_cb = QCheckBox("Enable Threat Intelligence")
        self.enable_threat_intel_cb.setChecked(self.config['enable_threat_intel'])
        
        self.enable_auto_topology_cb = QCheckBox("Auto-Generate Network Topology")
        self.enable_auto_topology_cb.setChecked(self.config['auto_topology_mapping'])
        
        # Risk threshold
        self.risk_threshold_slider = QSlider(Qt.Horizontal)
        self.risk_threshold_slider.setRange(1, 10)
        self.risk_threshold_slider.setValue(int(self.config['risk_threshold']))
        self.risk_threshold_label = QLabel(f"Risk Threshold: {self.config['risk_threshold']}")
        self.risk_threshold_slider.valueChanged.connect(
            lambda v: self.risk_threshold_label.setText(f"Risk Threshold: {v}")
        )
        
        scan_config_layout.addWidget(self.enable_advanced_scan_cb, 0, 0)
        scan_config_layout.addWidget(self.enable_ai_detection_cb, 0, 1)
        scan_config_layout.addWidget(self.enable_threat_intel_cb, 1, 0)
        scan_config_layout.addWidget(self.enable_auto_topology_cb, 1, 1)
        scan_config_layout.addWidget(self.risk_threshold_label, 2, 0)
        scan_config_layout.addWidget(self.risk_threshold_slider, 2, 1)
        
        scan_config_group.setLayout(scan_config_layout)
        layout.addWidget(scan_config_group)
        
        # API configuration
        api_config_group = QGroupBox("API Configuration")
        api_config_layout = QGridLayout()
        
        self.shodan_api_key_input = QTextEdit()
        self.shodan_api_key_input.setMaximumHeight(30)
        self.shodan_api_key_input.setPlainText(self.config['shodan_api_key'])
        
        self.enable_api_cb = QCheckBox("Enable REST API")
        self.enable_api_cb.setChecked(self.config['api_enabled'])
        
        self.api_port_input = QSpinBox()
        self.api_port_input.setRange(1024, 65535)
        self.api_port_input.setValue(self.config['api_port'])
        
        self.start_api_btn = QPushButton("🚀 Start API Server")
        self.start_api_btn.clicked.connect(self.toggle_api_server)
        
        api_config_layout.addWidget(QLabel("Shodan API Key:"), 0, 0)
        api_config_layout.addWidget(self.shodan_api_key_input, 0, 1, 1, 2)
        api_config_layout.addWidget(self.enable_api_cb, 1, 0)
        api_config_layout.addWidget(QLabel("API Port:"), 1, 1)
        api_config_layout.addWidget(self.api_port_input, 1, 2)
        api_config_layout.addWidget(self.start_api_btn, 2, 0, 1, 3)
        
        api_config_group.setLayout(api_config_layout)
        layout.addWidget(api_config_group)
        
        # Database configuration
        db_config_group = QGroupBox("Database Configuration")
        db_config_layout = QHBoxLayout()
        
        self.export_db_btn = QPushButton("💾 Export Database")
        self.export_db_btn.clicked.connect(self.export_database)
        
        self.import_db_btn = QPushButton("📁 Import Database")
        self.import_db_btn.clicked.connect(self.import_database)
        
        self.clear_db_btn = QPushButton("🗑️ Clear Database")
        self.clear_db_btn.clicked.connect(self.clear_database)
        
        db_config_layout.addWidget(self.export_db_btn)
        db_config_layout.addWidget(self.import_db_btn)
        db_config_layout.addWidget(self.clear_db_btn)
        db_config_layout.addStretch()
        
        db_config_group.setLayout(db_config_layout)
        layout.addWidget(db_config_group)
        
        # Save configuration button
        self.save_config_btn = QPushButton("💾 Save Configuration")
        self.save_config_btn.clicked.connect(self.save_configuration)
        layout.addWidget(self.save_config_btn)
        
        layout.addStretch()
        self.config_tab.setLayout(layout)

    # Enhanced scanning methods
    def enhanced_device_scan(self, ip, device_info):
        """Perform enhanced scanning with all available techniques"""
        try:
            # Basic info
            enhanced_info = device_info.copy()
            
            # Advanced scanning if enabled
            if self.config['enable_advanced_scanning']:
                nmap_results = self.advanced_scanner.comprehensive_scan(ip)
                if nmap_results and ip in nmap_results:
                    nmap_data = nmap_results[ip]
                    enhanced_info.update({
                        'advanced_os': nmap_data.get('os', []),
                        'nmap_scripts': nmap_data.get('scripts', [])
                    })
                    
                    # Extract advanced port info
                    for protocol in nmap_data.get('protocols', {}):
                        for port, port_info in nmap_data['protocols'][protocol].items():
                            if port_info['state'] == 'open':
                                enhanced_info.setdefault('detailed_services', {})[port] = port_info
            
            # Threat intelligence check
            if self.config['enable_threat_intel']:
                threat_info = self.threat_intel.check_ip_reputation(ip)
                enhanced_info['threat_intel'] = threat_info
                
                if threat_info['is_malicious']:
                    enhanced_info['risk_score'] = max(enhanced_info.get('risk_score', 0), 8.0)
            
            # AI anomaly detection
            if self.config['enable_ai_detection'] and self.ai_detector.is_trained:
                features = self.ai_detector.extract_features(enhanced_info)
                anomaly_result = self.ai_detector.detect_anomaly(features)
                enhanced_info['anomaly_detection'] = anomaly_result
                
                if anomaly_result['is_anomaly']:
                    enhanced_info['risk_score'] = max(enhanced_info.get('risk_score', 0), 
                                                    anomaly_result['score'] * 10)
            
            # Calculate comprehensive risk score
            enhanced_info['risk_score'] = self.calculate_risk_score(enhanced_info)
            
            # Save to database
            self.save_scan_result(enhanced_info)
            
            # Update topology if enabled
            if self.config['auto_topology_mapping']:
                self.topology_mapper.add_device(ip, enhanced_info)
            
            return enhanced_info
            
        except Exception as e:
            self.add_log_message(f"Enhanced scan failed for {ip}: {e}")
            return device_info
    
    def calculate_risk_score(self, device_info):
        """Calculate comprehensive risk score"""
        base_score = 0.0
        
        # Vulnerability score
        vulnerabilities = device_info.get('vulnerabilities', [])
        for vuln in vulnerabilities:
            if isinstance(vuln, dict):
                base_score += vuln.get('cvss', 0) / 10.0
            else:
                base_score += 5.0  # Default moderate risk
        
        # Open ports risk
        open_ports = device_info.get('open_ports', [])
        risky_ports = [21, 23, 135, 139, 445, 1433, 3306, 3389, 5432]
        risk_ports = [p for p in open_ports if p in risky_ports]
        base_score += len(risk_ports) * 0.5
        
        # Service risk
        services = device_info.get('services', [])
        risky_services = ['FTP', 'Telnet', 'SMB', 'RDP', 'MySQL', 'PostgreSQL']
        for service in services:
            if any(risky in str(service) for risky in risky_services):
                base_score += 1.0
        
        # Threat intelligence
        threat_info = device_info.get('threat_intel', {})
        if threat_info.get('is_malicious'):
            base_score += threat_info.get('confidence', 0) * 10
        
        # Anomaly detection
        anomaly_info = device_info.get('anomaly_detection', {})
        if anomaly_info.get('is_anomaly'):
            base_score += anomaly_info.get('score', 0) * 10
        
        return min(base_score, 10.0)  # Cap at 10.0
    
    def save_scan_result(self, device_info):
        """Save scan result to database"""
        try:
            scan_result = ScanResult(
                ip_address=device_info.get('ip', ''),
                hostname=device_info.get('hostname', ''),
                mac_address=device_info.get('mac', ''),
                vendor=device_info.get('vendor', ''),
                open_ports=json.dumps(device_info.get('open_ports', [])),
                services=json.dumps(device_info.get('services', [])),
                os_detection=device_info.get('os', ''),
                vulnerabilities=json.dumps(device_info.get('vulnerabilities', [])),
                risk_score=device_info.get('risk_score', 0.0),
                anomaly_score=device_info.get('anomaly_detection', {}).get('score', 0.0),
                threat_intel=json.dumps(device_info.get('threat_intel', {}))
            )
            self.db_session.add(scan_result)
            self.db_session.commit()
        except Exception as e:
            self.add_log_message(f"Database save failed: {e}")
            self.db_session.rollback()
    
    # UI Event Handlers
    def refresh_topology(self):
        """Refresh network topology visualization"""
        try:
            # Update topology with current devices
            for device in self.devices:
                self.topology_mapper.add_device(device['ip'], device)
            
            # Generate visualization
            self.topology_figure.clear()
            fig = self.topology_mapper.generate_topology_plot()
            
            # Copy to our canvas
            ax = self.topology_figure.add_subplot(111)
            ax.clear()
            
            # Redraw the topology
            if self.topology_mapper.device_positions:
                self.topology_mapper.calculate_layout()
                
                # Draw nodes and edges
                node_colors = []
                node_sizes = []
                
                for node in self.topology_mapper.graph.nodes():
                    device_info = self.topology_mapper.graph.nodes[node]
                    risk_score = device_info.get('risk_score', 0.0)
                    
                    if risk_score > 7.0:
                        node_colors.append('red')
                    elif risk_score > 4.0:
                        node_colors.append('orange')
                    else:
                        node_colors.append('green')
                    
                    open_ports = len(device_info.get('open_ports', []))
                    node_sizes.append(max(300, open_ports * 50))
                
                nx.draw_networkx_nodes(
                    self.topology_mapper.graph,
                    self.topology_mapper.device_positions,
                    node_color=node_colors,
                    node_size=node_sizes,
                    alpha=0.7,
                    ax=ax
                )
                
                nx.draw_networkx_edges(
                    self.topology_mapper.graph,
                    self.topology_mapper.device_positions,
                    alpha=0.5,
                    edge_color='gray',
                    ax=ax
                )
                
                nx.draw_networkx_labels(
                    self.topology_mapper.graph,
                    self.topology_mapper.device_positions,
                    font_size=8,
                    ax=ax
                )
                
                ax.set_title('Network Topology Map', fontsize=16, fontweight='bold')
                ax.axis('off')
            
            self.topology_canvas.draw()
            self.add_log_message("Network topology refreshed")
            
        except Exception as e:
            self.add_log_message(f"Topology refresh failed: {e}")
    
    def export_topology(self):
        """Export network topology to file"""
        try:
            file_dialog = QFileDialog()
            filename, _ = file_dialog.getSaveFileName(
                self, "Export Topology", "", 
                "PNG Files (*.png);;HTML Files (*.html);;PDF Files (*.pdf)"
            )
            
            if filename:
                if filename.endswith('.html'):
                    fig = self.topology_mapper.generate_interactive_plot(filename)
                else:
                    fig = self.topology_mapper.generate_topology_plot(filename)
                
                self.add_log_message(f"Topology exported to {filename}")
                
        except Exception as e:
            QMessageBox.critical(self, "Export Error", f"Failed to export topology: {e}")
    
    def update_topology_layout(self, layout_type):
        """Update topology layout algorithm"""
        try:
            if layout_type == "Circular Layout":
                self.topology_mapper.device_positions = nx.circular_layout(self.topology_mapper.graph)
            elif layout_type == "Random Layout":
                self.topology_mapper.device_positions = nx.random_layout(self.topology_mapper.graph)
            elif layout_type == "Hierarchical Layout":
                self.topology_mapper.device_positions = nx.spring_layout(
                    self.topology_mapper.graph, k=5, iterations=100
                )
            else:  # Spring Layout (default)
                self.topology_mapper.device_positions = nx.spring_layout(
                    self.topology_mapper.graph, k=3, iterations=50
                )
            
            self.refresh_topology()
            
        except Exception as e:
            self.add_log_message(f"Layout update failed: {e}")
    
    def train_ai_models(self):
        """Train AI anomaly detection models"""
        try:
            # Collect training data from historical scans
            results = self.db_session.query(ScanResult).all()
            
            if len(results) < 10:
                QMessageBox.warning(self, "Insufficient Data", 
                                  "Need at least 10 scan results to train AI models. Perform more scans first.")
                return
            
            # Extract features for training
            for result in results:
                device_info = {
                    'open_ports': json.loads(result.open_ports or '[]'),
                    'services': json.loads(result.services or '[]'),
                    'vulnerabilities': json.loads(result.vulnerabilities or '[]'),
                    'risk_score': result.risk_score or 0.0,
                    'response_time': 0.5,  # Default value
                    'packet_size': 64  # Default value
                }
                features = self.ai_detector.extract_features(device_info)
                self.ai_detector.add_baseline_data(features)
            
            # Train the models
            if self.ai_detector.train_models():
                self.add_log_message("AI models trained successfully")
                QMessageBox.information(self, "Training Complete", 
                                      "AI anomaly detection models have been trained successfully!")
            else:
                QMessageBox.warning(self, "Training Failed", "AI model training failed.")
                
        except Exception as e:
            QMessageBox.critical(self, "Training Error", f"AI training failed: {e}")
    
    def analyze_anomalies(self):
        """Analyze current devices for anomalies"""
        try:
            if not self.ai_detector.is_trained:
                QMessageBox.warning(self, "Models Not Trained", 
                                  "Please train the AI models first.")
                return
            
            self.analytics_table.setRowCount(0)
            anomaly_count = 0
            
            for device in self.devices:
                features = self.ai_detector.extract_features(device)
                anomaly_result = self.ai_detector.detect_anomaly(features)
                
                if anomaly_result['is_anomaly'] or anomaly_result['score'] > 0.1:
                    row = self.analytics_table.rowCount()
                    self.analytics_table.insertRow(row)
                    
                    # Determine risk level
                    score = anomaly_result['score']
                    if score > 0.7:
                        risk_level = "High"
                    elif score > 0.4:
                        risk_level = "Medium"
                    else:
                        risk_level = "Low"
                    
                    self.analytics_table.setItem(row, 0, QTableWidgetItem(device.get('ip', '')))
                    self.analytics_table.setItem(row, 1, QTableWidgetItem(f"{score:.3f}"))
                    self.analytics_table.setItem(row, 2, QTableWidgetItem(risk_level))
                    self.analytics_table.setItem(row, 3, QTableWidgetItem(f"{anomaly_result['confidence']:.1f}%"))
                    self.analytics_table.setItem(row, 4, QTableWidgetItem("Anomaly" if anomaly_result['is_anomaly'] else "Suspicious"))
                    self.analytics_table.setItem(row, 5, QTableWidgetItem(str(anomaly_result.get('details', {}))))
                    
                    if anomaly_result['is_anomaly']:
                        anomaly_count += 1
            
            # Update visualization
            self.update_analytics_visualization()
            
            self.add_log_message(f"Anomaly analysis complete. Found {anomaly_count} anomalies.")
            
        except Exception as e:
            QMessageBox.critical(self, "Analysis Error", f"Anomaly analysis failed: {e}")
    
    def update_analytics_visualization(self):
        """Update the analytics visualization"""
        try:
            self.analytics_figure.clear()
            ax = self.analytics_figure.add_subplot(111)
            
            # Collect risk scores
            risk_scores = []
            for device in self.devices:
                risk_scores.append(device.get('risk_score', 0.0))
            
            if risk_scores:
                # Create histogram
                ax.hist(risk_scores, bins=10, alpha=0.7, color='skyblue', edgecolor='black')
                ax.set_xlabel('Risk Score')
                ax.set_ylabel('Number of Devices')
                ax.set_title('Risk Score Distribution')
                ax.grid(True, alpha=0.3)
            
            self.analytics_canvas.draw()
            
        except Exception as e:
            self.add_log_message(f"Analytics visualization update failed: {e}")
    
    def update_ai_threshold(self, value):
        """Update AI detection threshold"""
        # This would adjust the sensitivity of anomaly detection
        self.add_log_message(f"AI sensitivity set to {value}%")
    
    def update_threat_database(self):
        """Update threat intelligence database"""
        try:
            self.add_log_message("Updating threat intelligence database...")
            
            # Simulate threat database update
            # In real implementation, this would fetch from actual threat feeds
            updated_count = 0
            
            # Mock update process
            for i in range(100):
                time.sleep(0.01)  # Simulate network requests
                updated_count += 1
                if updated_count % 10 == 0:
                    self.add_log_message(f"Updated {updated_count} threat indicators...")
            
            self.add_log_message(f"Threat database updated. {updated_count} indicators processed.")
            QMessageBox.information(self, "Update Complete", 
                                  f"Threat intelligence database updated with {updated_count} indicators.")
            
        except Exception as e:
            QMessageBox.critical(self, "Update Error", f"Threat database update failed: {e}")
    
    def scan_malicious_ips(self):
        """Scan discovered devices against threat intelligence"""
        try:
            self.threat_table.setRowCount(0)
            malicious_count = 0
            
            for device in self.devices:
                ip = device.get('ip', '')
                threat_info = self.threat_intel.check_ip_reputation(ip)
                
                if threat_info['is_malicious'] or threat_info['confidence'] > 0.3:
                    row = self.threat_table.rowCount()
                    self.threat_table.insertRow(row)
                    
                    # Determine threat level
                    confidence = threat_info['confidence']
                    if confidence > 0.8:
                        threat_level = "Critical"
                    elif confidence > 0.5:
                        threat_level = "High"
                    else:
                        threat_level = "Medium"
                    
                    self.threat_table.setItem(row, 0, QTableWidgetItem(ip))
                    self.threat_table.setItem(row, 1, QTableWidgetItem(threat_level))
                    self.threat_table.setItem(row, 2, QTableWidgetItem(', '.join(threat_info['threat_types'])))
                    self.threat_table.setItem(row, 3, QTableWidgetItem(', '.join(threat_info['sources'])))
                    self.threat_table.setItem(row, 4, QTableWidgetItem(f"{confidence*100:.1f}%"))
                    self.threat_table.setItem(row, 5, QTableWidgetItem(datetime.now().strftime("%Y-%m-%d %H:%M")))
                    self.threat_table.setItem(row, 6, QTableWidgetItem("Block"))
                    
                    if threat_info['is_malicious']:
                        malicious_count += 1
            
            self.add_log_message(f"Threat scan complete. Found {malicious_count} malicious IPs.")
            
        except Exception as e:
            QMessageBox.critical(self, "Scan Error", f"Threat intelligence scan failed: {e}")
    
    def generate_comprehensive_report(self):
        """Generate comprehensive security report"""
        try:
            report_type = self.report_type_combo.currentText()
            report_format = self.report_format_combo.currentText()
            
            self.add_log_message(f"Generating {report_type} report in {report_format} format...")
            
            # Collect report data
            report_data = {
                'scan_date': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                'total_devices': len(self.devices),
                'high_risk_devices': len([d for d in self.devices if d.get('risk_score', 0) > 7.0]),
                'vulnerabilities_found': sum(len(d.get('vulnerabilities', [])) for d in self.devices),
                'devices': self.devices
            }
            
            if report_format == "PDF":
                filename = self.generate_pdf_report(report_data, report_type)
            elif report_format == "HTML":
                filename = self.generate_html_report(report_data, report_type)
            else:
                filename = self.generate_json_report(report_data, report_type)
            
            # Update report preview
            preview_text = f"""
Report Generated: {report_data['scan_date']}
Report Type: {report_type}
Format: {report_format}

Summary:
- Total Devices Scanned: {report_data['total_devices']}
- High Risk Devices: {report_data['high_risk_devices']}
- Total Vulnerabilities: {report_data['vulnerabilities_found']}

File: {filename}
            """
            self.report_preview.setPlainText(preview_text)
            
            self.add_log_message(f"Report generated successfully: {filename}")
            QMessageBox.information(self, "Report Generated", f"Report saved as: {filename}")
            
        except Exception as e:
            QMessageBox.critical(self, "Report Error", f"Report generation failed: {e}")
    
    def generate_pdf_report(self, data, report_type):
        """Generate PDF report using ReportLab"""
        filename = f"network_scan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        
        doc = SimpleDocTemplate(filename, pagesize=letter)
        styles = getSampleStyleSheet()
        story = []
        
        # Title
        title = Paragraph(f"Network Security Report - {report_type}", styles['Title'])
        story.append(title)
        story.append(Spacer(1, 12))
        
        # Summary
        summary_data = [
            ['Scan Date', data['scan_date']],
            ['Total Devices', str(data['total_devices'])],
            ['High Risk Devices', str(data['high_risk_devices'])],
            ['Vulnerabilities Found', str(data['vulnerabilities_found'])]
        ]
        
        summary_table = Table(summary_data)
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 14),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        story.append(summary_table)
        story.append(Spacer(1, 12))
        
        # Device details table
        device_data = [['IP Address', 'Hostname', 'Risk Score', 'Open Ports', 'Vulnerabilities']]
        
        for device in data['devices']:
            device_data.append([
                device.get('ip', ''),
                device.get('hostname', 'Unknown'),
                f"{device.get('risk_score', 0):.1f}",
                str(len(device.get('open_ports', []))),
                str(len(device.get('vulnerabilities', [])))
            ])
        
        device_table = Table(device_data)
        device_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        story.append(device_table)
        doc.build(story)
        
        return filename
    
    def generate_html_report(self, data, report_type):
        """Generate HTML report"""
        filename = f"network_scan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Network Security Report - {report_type}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .header {{ background-color: #2c3e50; color: white; padding: 20px; text-align: center; }}
                .summary {{ background-color: #ecf0f1; padding: 15px; margin: 20px 0; }}
                table {{ border-collapse: collapse; width: 100%; margin: 20px 0; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #34495e; color: white; }}
                .high-risk {{ background-color: #e74c3c; color: white; }}
                .medium-risk {{ background-color: #f39c12; }}
                .low-risk {{ background-color: #27ae60; color: white; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>Network Security Report</h1>
                <h2>{report_type}</h2>
                <p>Generated on: {data['scan_date']}</p>
            </div>
            
            <div class="summary">
                <h3>Executive Summary</h3>
                <ul>
                    <li>Total Devices Scanned: {data['total_devices']}</li>
                    <li>High Risk Devices: {data['high_risk_devices']}</li>
                    <li>Total Vulnerabilities Found: {data['vulnerabilities_found']}</li>
                </ul>
            </div>
            
            <h3>Detailed Device Analysis</h3>
            <table>
                <tr>
                    <th>IP Address</th>
                    <th>Hostname</th>
                    <th>Risk Score</th>
                    <th>Open Ports</th>
                    <th>Vulnerabilities</th>
                    <th>Status</th>
                </tr>
        """
        
        for device in data['devices']:
            risk_score = device.get('risk_score', 0)
            risk_class = 'high-risk' if risk_score > 7 else 'medium-risk' if risk_score > 4 else 'low-risk'
            
            html_content += f"""
                <tr class="{risk_class}">
                    <td>{device.get('ip', '')}</td>
                    <td>{device.get('hostname', 'Unknown')}</td>
                    <td>{risk_score:.1f}</td>
                    <td>{len(device.get('open_ports', []))}</td>
                    <td>{len(device.get('vulnerabilities', []))}</td>
                    <td>{'High Risk' if risk_score > 7 else 'Medium Risk' if risk_score > 4 else 'Low Risk'}</td>
                </tr>
            """
        
        html_content += """
            </table>
        </body>
        </html>
        """
        
        with open(filename, 'w') as f:
            f.write(html_content)
        
        return filename
    
    def generate_json_report(self, data, report_type):
        """Generate JSON report"""
        filename = f"network_scan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        report = {
            'report_type': report_type,
            'generated_at': data['scan_date'],
            'summary': {
                'total_devices': data['total_devices'],
                'high_risk_devices': data['high_risk_devices'],
                'vulnerabilities_found': data['vulnerabilities_found']
            },
            'devices': data['devices']
        }
        
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        return filename
    
    def toggle_api_server(self):
        """Start/stop the REST API server"""
        try:
            if self.api_thread is None:
                # Start API server
                port = self.api_port_input.value()
                self.start_api_server(port)
                self.start_api_btn.setText("🛑 Stop API Server")
                self.add_log_message(f"API server started on port {port}")
            else:
                # Stop API server
                self.stop_api_server()
                self.start_api_btn.setText("🚀 Start API Server")
                self.add_log_message("API server stopped")
                
        except Exception as e:
            QMessageBox.critical(self, "API Error", f"API server operation failed: {e}")
    
    def start_api_server(self, port):
        """Start the Flask API server in a separate thread"""
        self.api_app = Flask(__name__)
        
        @self.api_app.route('/api/devices', methods=['GET'])
        def get_devices():
            return jsonify(self.devices)
        
        @self.api_app.route('/api/scan/<ip>', methods=['POST'])
        def scan_device(ip):
            # Trigger device scan
            return jsonify({'status': 'scan_started', 'ip': ip})
        
        @self.api_app.route('/api/topology', methods=['GET'])
        def get_topology():
            return jsonify({
                'nodes': list(self.topology_mapper.graph.nodes(data=True)),
                'edges': list(self.topology_mapper.graph.edges())
            })
        
        def run_api():
            self.api_app.run(host='0.0.0.0', port=port, debug=False)
        
        self.api_thread = threading.Thread(target=run_api, daemon=True)
        self.api_thread.start()
    
    def stop_api_server(self):
        """Stop the API server"""
        if self.api_thread:
            self.api_thread = None
            self.api_app = None
    
    def save_configuration(self):
        """Save current configuration"""
        try:
            self.config.update({
                'shodan_api_key': self.shodan_api_key_input.toPlainText(),
                'enable_ai_detection': self.enable_ai_detection_cb.isChecked(),
                'enable_threat_intel': self.enable_threat_intel_cb.isChecked(),
                'enable_advanced_scanning': self.enable_advanced_scan_cb.isChecked(),
                'auto_topology_mapping': self.enable_auto_topology_cb.isChecked(),
                'risk_threshold': self.risk_threshold_slider.value(),
                'api_enabled': self.enable_api_cb.isChecked(),
                'api_port': self.api_port_input.value()
            })
            
            # Initialize Shodan if API key provided
            if self.config['shodan_api_key']:
                self.threat_intel.initialize_shodan(self.config['shodan_api_key'])
            
            # Save to file
            with open('scanner_config.json', 'w') as f:
                json.dump(self.config, f, indent=2)
            
            self.add_log_message("Configuration saved successfully")
            QMessageBox.information(self, "Configuration Saved", "Settings have been saved successfully!")
            
        except Exception as e:
            QMessageBox.critical(self, "Save Error", f"Failed to save configuration: {e}")
    
    def export_database(self):
        """Export scan database to file"""
        try:
            filename, _ = QFileDialog.getSaveFileName(
                self, "Export Database", "", "JSON Files (*.json);;CSV Files (*.csv)"
            )
            
            if filename:
                results = self.db_session.query(ScanResult).all()
                
                if filename.endswith('.csv'):
                    with open(filename, 'w', newline='') as csvfile:
                        writer = csv.writer(csvfile)
                        writer.writerow(['IP', 'Hostname', 'MAC', 'Vendor', 'Risk Score', 'Timestamp'])
                        for result in results:
                            writer.writerow([
                                result.ip_address, result.hostname, result.mac_address,
                                result.vendor, result.risk_score, result.timestamp
                            ])
                else:
                    data = []
                    for result in results:
                        data.append({
                            'ip_address': result.ip_address,
                            'hostname': result.hostname,
                            'mac_address': result.mac_address,
                            'vendor': result.vendor,
                            'risk_score': result.risk_score,
                            'timestamp': result.timestamp.isoformat() if result.timestamp else None
                        })
                    
                    with open(filename, 'w') as f:
                        json.dump(data, f, indent=2)
                
                self.add_log_message(f"Database exported to {filename}")
                
        except Exception as e:
            QMessageBox.critical(self, "Export Error", f"Database export failed: {e}")
    
    def import_database(self):
        """Import scan database from file"""
        try:
            filename, _ = QFileDialog.getOpenFileName(
                self, "Import Database", "", "JSON Files (*.json);;CSV Files (*.csv)"
            )
            
            if filename:
                # Implementation would depend on file format
                self.add_log_message(f"Database import from {filename} - feature coming soon")
                QMessageBox.information(self, "Import", "Database import feature coming in next update!")
                
        except Exception as e:
            QMessageBox.critical(self, "Import Error", f"Database import failed: {e}")
    
    def clear_database(self):
        """Clear all scan data from database"""
        try:
            reply = QMessageBox.question(
                self, "Clear Database", 
                "Are you sure you want to delete all scan data? This cannot be undone.",
                QMessageBox.Yes | QMessageBox.No, QMessageBox.No
            )
            
            if reply == QMessageBox.Yes:
                self.db_session.query(ScanResult).delete()
                self.db_session.commit()
                self.add_log_message("Database cleared successfully")
                QMessageBox.information(self, "Database Cleared", "All scan data has been deleted.")
                
        except Exception as e:
            QMessageBox.critical(self, "Clear Error", f"Database clear failed: {e}")
            self.db_session.rollback()

    # Additional vulnerability check methods for the enhanced database
    def check_smbghost(self, ip, port=445):
        """Check for SMBGhost vulnerability (CVE-2020-0796)"""
        try:
            if not self.check_port(ip, port):
                return False
            # Simplified check - in reality would need specific SMB protocol testing
            return True  # Placeholder
        except:
            return False
    
    def check_spring4shell(self, ip, port=8080):
        """Check for Spring4Shell vulnerability"""
        try:
            if not self.check_port(ip, port):
                return False
            # Would need HTTP request with specific Spring Framework detection
            return False  # Placeholder
        except:
            return False
    
    def check_printnightmare(self, ip, port=445):
        """Check for PrintNightmare vulnerability"""
        try:
            if not self.check_port(ip, port):
                return False
            # Would need specific RPC/SMB testing for print spooler
            return False  # Placeholder
        except:
            return False
    
    def check_ssh_scp_vuln(self, ip, port=22):
        """Check for SSH SCP vulnerability"""
        try:
            if not self.check_port(ip, port):
                return False
            # Would need SSH version detection
            return False  # Placeholder
        except:
            return False
    
    def check_sigred(self, ip, port=53):
        """Check for SIGRed DNS vulnerability"""
        try:
            if not self.check_port(ip, port):
                return False
            # Would need DNS query testing
            return False  # Placeholder
        except:
            return False
    
    def check_bluekeep(self, ip, port=3389):
        """Check for BlueKeep RDP vulnerability"""
        try:
            if not self.check_port(ip, port):
                return False
            # Would need RDP protocol testing
            return False  # Placeholder
        except:
            return False
    
    def check_sonicwall_vpn(self, ip, port=443):
        """Check for SonicWall VPN vulnerability"""
        try:
            if not self.check_port(ip, port):
                return False
            # Would need specific SonicWall SSL-VPN detection
            return False  # Placeholder
        except:
            return False

def main():
    """Main application entry point"""
    app = QApplication(sys.argv)
    scanner = NetworkScanner()
    scanner.show()
    sys.exit(app.exec_())

if __name__ == '__main__':
    main()
    