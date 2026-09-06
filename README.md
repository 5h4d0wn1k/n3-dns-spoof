# N3 — DNS Spoof

Pure-stdlib DNS engine, spoof-decider, and cache-poison logic. All core logic
runs unprivileged and deterministically; live reply injection is gated behind
`--live`/`--iface`.

## Overview

This project implements a DNS spoofing engine that:
- Builds and parses genuine DNS wire-format messages by hand (stdlib `struct`)
- Spoofs responses only for a target domain, using the **matching query ID**
- Rejects mismatched-ID responses (cache-poison resistance, false-positive guard)
- Supports A and AAAA answers

## What Works

- **DNS message engine** (`DNSMessage.build_query` / `build_spoofed_reply` /
  `parse` / name codec with compression-pointer decode) — round-trips through
  the real parser, no privileges.
- **Spoof decider** (`DNSSpoofDecider`) — `verify_response` accepts only the
  exact query-ID match and answers the target domain; `should_send_spoof`
  generates a spoof reply for a fresh query.
- **Offline harness** (`--harness`) — deterministic PASS path: matching-ID
  reply accepted, spoof generated, mismatched-ID reply rejected.
- **Live sniff-and-spoof** (`--live/--iface`) — root + optional scapy; builds
  the spoof from the same engine used offline.

## Installation

No external dependencies for the core. Optional for live mode:

```bash
pip install scapy
```

## Usage

```bash
# Offline decider harness (no privileges, deterministic)
python3 dns_spoof.py --harness

# Custom target / spoof IP (documentation ranges only)
python3 dns_spoof.py --harness --domain lab-demo.test --ip 192.0.2.53

# Live sniff-and-spoof on a real interface (root + scapy)
sudo python3 dns_spoof.py --live --iface eth0 --domain example-lab.test --ip 192.0.2.200
```

## Tests

```bash
python3 -m unittest discover -s tests
```

## Live Lab Test Plan

> Authorized own-lab use only. Use documented placeholders (192.0.2.x, lab-* names).

1. **Prepare a controlled lab**: client host sends queries to a resolver you
   control; attacker host runs the tool.
2. Run `sudo python3 dns_spoof.py --live --iface <lab-iface> --domain lab-a.test --ip 192.0.2.200`.
3. From the client, resolve `lab-a.test` with `dig lab-a.test @<resolver>` and
   confirm the answer is `192.0.2.200`.
4. Confirm non-target domains (`other.test`) are untouched (engine checks the
   domain before sending a spoof).
5. Confirm the query-ID matching: a response whose ID does not match the
   client's query is rejected by the decider (cache-poison resistance).

## Metrics

Core offline harness is deterministic and unit-tested:

- DNS name codec round-trip incl. compression pointer: PASS (4 tests)
- Query/reply build + parse round-trip: PASS (3 tests)
- Matching query-ID response accepted: PASS
- Mismatched query-ID response rejected: PASS (cache-poison guard)
- Target-domain vs non-target-domain spoof decision: PASS (5 decider tests)
- Exit code: `0` on successful harness, `1` on failure

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