# Network Packet Analyzer

A lightweight network packet analyzer built in C++ that reads PCAPNG capture files, parses packet headers, analyzes network traffic, and generates a network analysis report.

## Features

### PCAPNG File Processing

- Reads PCAPNG files in binary mode
- Processes packet blocks
- Handles packet padding
- Validates block lengths
- Handles invalid and incomplete packet data

### Ethernet Analysis

- Extracts source MAC addresses
- Extracts destination MAC addresses
- Identifies Ethernet types
- Detects ARP, IPv4, and IPv6 traffic

### IPv4 Analysis

- Extracts source IP addresses
- Extracts destination IP addresses
- Reads IPv4 header information
- Identifies transport protocols

### TCP Analysis

- Extracts source ports
- Extracts destination ports
- Detects TCP flags
- Counts SYN, ACK, FIN, RST, PSH, and URG flags
- Tracks TCP network flows

### UDP Analysis

- Extracts source ports
- Extracts destination ports
- Tracks UDP network flows

### ICMP Analysis

- Detects ICMP traffic

### Traffic Statistics

The analyzer calculates:

- Total packet count
- Total captured bytes
- Total original bytes
- Average packet size
- Smallest packet
- Largest packet
- Protocol statistics
- IP address statistics
- MAC address statistics
- Port usage statistics
- Traffic directions
- Network flows

### Service Detection

Common ports are mapped to their associated services, including:

- FTP
- SSH
- Telnet
- SMTP
- DNS
- DHCP
- HTTP
- POP3
- NTP
- IMAP
- HTTPS
- IMAPS
- POP3S

### Basic Anomaly Detection

The analyzer performs basic rule-based detection for:

- Possible port scanning
- High SYN activity

## Technologies

- C++
- C++17
- PCAPNG
- Binary file processing
- Standard Template Library
- Hash maps
- Sets
- Vectors
- Bitwise operations

## Project Structure

```text
netanalyzer/
|
|-- src/
|   |-- main.cpp
|
|-- samples/
|   |-- arp.pcapng
|
|-- README.md
|-- .gitignore
