#!/usr/bin/env python3
"""Offline unit tests for the N3 DNS spoof decider/engine.

These exercise the real packet-construction and parse code paths with no
privileges and no network access.
"""
import os
import socket
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'firmware'))

from dns_spoof import (  # noqa: E402
    DNSMessage,
    DNSSpoofDecider,
    decode_name,
    encode_name,
)


class TestNameCodec(unittest.TestCase):
    def test_encode_simple_fqdn(self):
        self.assertEqual(encode_name('example-lab.test'),
                         b'\x0bexample-lab\x04test\x00')

    def test_encode_root(self):
        self.assertEqual(encode_name('.'), b'\x00')

    def test_decode_roundtrip(self):
        raw = encode_name('a.example-lab.test')
        name, end = decode_name(raw, 0)
        self.assertEqual(name, 'a.example-lab.test')
        self.assertEqual(end, len(raw))

    def test_decode_compression_pointer(self):
        # Pointer at offset 0 -> absolute offset 2 where 'lab' label lives
        data = bytes([0xC0, 0x02]) + encode_name('lab')
        name, end = decode_name(data, 0)
        self.assertEqual(name, 'lab')
        self.assertEqual(end, 2)


class TestDNSMessageBuild(unittest.TestCase):
    def test_build_query_header(self):
        q = DNSMessage.build_query('example-lab.test', qid=0x1234)
        self.assertEqual(q[:2], b'\x12\x34')
        flags = q[2:4]
        self.assertFalse(flags[0] & 0x80)  # QR=0 (query)
        self.assertEqual(q[4:6], b'\x00\x01')  # qdcount=1
        self.assertEqual(q[6:10], b'\x00\x00\x00\x00')

    def test_query_roundtrip_parse(self):
        q = DNSMessage.build_query('example-lab.test', qid=0x4242)
        p = DNSMessage.parse(q)
        self.assertEqual(p['id'], 0x4242)
        self.assertEqual(p['qr'], 0)
        self.assertEqual(p['questions'][0][0], 'example-lab.test')
        self.assertEqual(p['questions'][0][1], 1)  # A record

    def test_spoofed_reply_structure(self):
        r = DNSMessage.build_spoofed_reply(0x4242, 'example-lab.test',
                                           '192.0.2.200')
        self.assertEqual(r[:2], b'\x42\x42')
        self.assertEqual(r[2], 0x81)  # response + AA + RD/RA
        ancount = struct_unpack_ancount(r)
        self.assertEqual(ancount, 1)
        p = DNSMessage.parse(r)
        self.assertEqual(p['id'], 0x4242)
        self.assertEqual(p['qr'], 1)
        self.assertEqual(p['ancount'], 1)
        self.assertEqual(p['answers'][0][4], socket.inet_aton('192.0.2.200'))


class TestDNSSpoofDecider(unittest.TestCase):
    def setUp(self):
        self.decider = DNSSpoofDecider('example-lab.test', '192.0.2.200')

    def test_matching_id_accepted(self):
        qid = 0x1111
        q = DNSMessage.build_query('example-lab.test', qid=qid)
        r = DNSMessage.build_spoofed_reply(qid, 'example-lab.test',
                                           '192.0.2.200')
        self.decider.note_query(q)
        res = self.decider.verify_response(q, r)
        self.assertTrue(res['accepted'])
        self.assertEqual(res['reason'], 'qid_match')

    def test_mismatched_id_rejected(self):
        qid = 0x1111
        q = DNSMessage.build_query('example-lab.test', qid=qid)
        r = DNSMessage.build_spoofed_reply(qid, 'example-lab.test',
                                           '192.0.2.200',
                                           qid=(qid + 1) & 0xFFFF)
        res = self.decider.verify_response(q, r)
        self.assertFalse(res['accepted'])
        self.assertEqual(res['reason'], 'qid_mismatch')
        self.assertEqual(self.decider.stats['mismatch_rejected'], 1)

    def test_should_send_spoof_target_domain(self):
        q = DNSMessage.build_query('example-lab.test', qid=0x2222)
        reply = self.decider.should_send_spoof(q)
        self.assertIsNotNone(reply)
        p = DNSMessage.parse(reply)
        self.assertEqual(p['id'], 0x2222)
        self.assertEqual(self.decider.stats['spoofed'], 1)

    def test_should_send_spoof_other_domain(self):
        q = DNSMessage.build_query('other.example.test', qid=0x2222)
        self.assertIsNone(self.decider.should_send_spoof(q))
        self.assertEqual(self.decider.stats['spoofed'], 0)

    def test_summary_counts(self):
        qid = 0x3333
        q = DNSMessage.build_query('example-lab.test', qid=qid)
        r = DNSMessage.build_spoofed_reply(qid, 'example-lab.test',
                                           '192.0.2.200')
        self.decider.note_query(q)
        self.decider.verify_response(q, r)
        self.decider.verify_response(
            q, DNSMessage.build_spoofed_reply(qid, 'example-lab.test',
                                              '192.0.2.200',
                                              qid=(qid + 1) & 0xFFFF))
        s = self.decider.summary()
        self.assertEqual(s['queries'], 1)
        self.assertEqual(s['mismatch_rejected'], 1)


def struct_unpack_ancount(msg):
    # Minimal header read to avoid importing struct at module top of tests
    import struct
    return struct.unpack('!H', msg[6:8])[0]


if __name__ == '__main__':
    unittest.main()