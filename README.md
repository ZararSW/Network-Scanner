# Network Scanner

A Python-based network scanning tool with a Qt GUI interface. This tool provides comprehensive network scanning capabilities with an intuitive graphical interface.

## Features

- Network interface detection and management
- IP and port scanning
- Device discovery
- Service identification
- OS detection
- Vulnerability scanning
- Continuous network monitoring
- Export results in multiple formats (CSV, JSON, HTML)

## Requirements

- Python 3.x
- PyQt5
- Scapy (optional, for enhanced scanning capabilities)
- Requests

# Installation

## Clone the repository:
```sh
git clone https://github.com/ZararSW/Network-Scanner
cd Network-Scanner
```

## Install required dependencies:
```sh
pip install -r requirements.txt
```

## Run the application:
```sh
python3 network-scanner.py
```

# Usage

### Select Network Interface:
Choose the network interface to scan from the drop-down menu.

### Configure Scan Options:
Set thread count and enable/disable advanced features.

### Start Scan:
Click "Start Scan" to begin discovering devices on your network.

### View Results:
Examine discovered devices in the results table.

### Export Reports:
Generate HTML, CSV, or JSON reports with the "Export Results" button.

# Advanced Features

- **Vulnerability Scanning**: Enable to check for common security vulnerabilities.
- **OS Detection**: Identify operating systems of discovered devices.
- **Continuous Monitoring**: Track devices and detect status changes in real-time.
- **Parallel Scanning**: Configure thread count for faster scanning of large networks.

# Security Notice

This tool is designed for network administrators and security professionals to audit their own networks. Always:

- Only scan networks you have permission to scan.
- Be aware that port scanning may be considered hostile by some network administrators.
- Use the vulnerability scanning features responsibly.

# License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

# Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository.
2. Create your feature branch:
   ```sh
   git checkout -b feature/amazing-feature
   ```
3. Commit your changes:
   ```sh
   git commit -m 'Add some amazing feature'
   ```
4. Push to the branch:
   ```sh
   git push origin feature/amazing-feature
   ```
5. Open a Pull Request.
