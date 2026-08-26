# N3 — DNS Spoof

Redirect DNS queries via rogue responses.

## Overview

This project implements a DNS spoofing attack that:
- Intercepts DNS queries for a target domain
- Returns spoofed responses redirecting to attacker IP
- Supports A, AAAA, and MX records
- Logs all spoofed queries

## Features

- **Domain targeting**: Spoof specific domains
- **Real-time spoofing**: Intercept and respond to DNS queries
- **Multiple record types**: Support for various DNS records
- **Logging**: Record all spoofed queries

## Installation

```bash
pip install scapy
```

## Usage

```bash
# Spoof specific domain
sudo python3 dns_spoof.py --interface eth0 --domain example.com --ip 192.168.1.100

# Spoof multiple domains (run multiple instances)
sudo python3 dns_spoof.py --interface eth0 --domain facebook.com --ip 192.168.1.100
sudo python3 dns_spoof.py --interface eth0 --domain google.com --ip 192.168.1.100
```

## Example Output

```
=== N3 — DNS Spoof ===
Interface: eth0
Target: example.com
Redirect to: 192.168.1.100

[SPOOF] Query for www.example.com
  Redirected to 192.168.1.100
[SPOOF] Query for example.com
  Redirected to 192.168.1.100
```

## Legal Disclaimer

**IMPORTANT: Read before use.**

This project is provided for **educational and authorized security testing purposes only**. 

### Authorization Requirements
- You MUST have explicit written permission from the network owner before using this tool
- Unauthorized interception of network communications is illegal under federal and state laws
- This tool should ONLY be used on networks you own or have written authorization to test

### Legal Framework
- **Computer Fraud and Abuse Act (CFAA)**: Unauthorized access to computer systems is a federal crime
- **Wiretap Act (18 U.S.C. § 2511)**: Interception of electronic communications without consent is illegal
- **State Laws**: Many states have additional computer crime and wiretapping statutes
- **GDPR/CCPA**: Data collection may be subject to privacy regulations

### Acceptable Use
- Testing security of your own networks
- Authorized penetration testing with written scope
- Academic research in controlled lab environments
- Security education and training

### Prohibited Use
- Intercepting communications on networks you do not own
- Attacking infrastructure without authorization
- Any activity that violates applicable laws or regulations
- Commercial use without proper licensing

### No Warranty
This software is provided "AS IS" without warranty of any kind. The author is not responsible for any misuse or damage caused by this software.

### Responsible Disclosure
If you discover vulnerabilities using this tool, follow responsible disclosure practices:
1. Report to the vendor/owner privately
2. Allow reasonable time for remediation
3. Do not exploit beyond proof of concept

## License

MIT
