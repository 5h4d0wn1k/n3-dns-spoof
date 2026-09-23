> **⚠️ EDUCATIONAL USE ONLY — AUTHORIZED TESTING ONLY.**
> This project exists for education, research, and **defense of systems you own
> or hold explicit written authorization to assess**. Unauthorized use is
> prohibited and may be illegal. Read [ETHICS.md](ETHICS.md) and
> [SCOPE.md](SCOPE.md) before use. Use at your own risk; **AS IS**, no warranty.

# N3 — DNS Spoof

**DNS spoofing toolkit** by **5h4d0wn1k** for **educational cache-poisoning
and response-forgery study**: a pure-standard-library DNS wire-format engine
(query build, spoofed-reply build, name codec with compression-pointer
decode), a query-ID-strict spoof decider, deterministic offline harness and a
`--live` sniff-and-spoof mode gated behind root + scapy.

## Why study DNS spoofing

DNS is the trust root of the internet — and the classic demonstration of why
query IDs and 0x20 randomization exist. This engine builds and parses DNS
wire messages by hand (`struct`-level), proves that a matching query ID opens
the door to response forgery, and equally proves that **mismatched-ID
responses are rejected** — the same guard that makes modern cache poisoning
hard. That dual lesson is the point: students see both the attack and the
defense in the same code path. All core logic runs unprivileged and fully
deterministic; live reply injection requires `--live`/`--iface`, root
privileges and scapy, and must stay inside an authorized lab. See
[ETHICS.md](ETHICS.md) and [SCOPE.md](SCOPE.md).

## Features

- **DNS wire-format engine** — `build_query`, `build_spoofed_reply`, `parse`
  and a name codec with compression-pointer decode (`DNSMessage`).
- **Spoof decider** — `should_send_spoof` generates a reply for a fresh
  query; `verify_response` accepts only exact query-ID matches (`DNSSpoofDecider`).
- **Cache-poison resistance** — mismatched-ID responses are rejected, the
  false-positive guard taught in every defenses course.
- **A and AAAA answers** — spoof both address record types.
- **Deterministic offline harness** — `--harness` runs the full PASS path
  with no privileges and RFC 5737 documentation addresses.
- **Live sniff-and-spoof** — `--live --iface` uses the same engine for real
  interface injection (root + scapy, authorized-lab only).

## Quickstart

Prerequisites: the core needs only the Python standard library. Live mode
additionally needs `pip install scapy` and root on a lab interface.

```bash
# Offline decider harness (no privileges, deterministic, exit 0)
python3 firmware/dns_spoof.py --harness

# Custom target / spoof IP (documentation ranges only)
python3 firmware/dns_spoof.py --harness --domain lab-demo.test --ip 192.0.2.53

# Live sniff-and-spoof on a real interface (root + scapy, authorized lab only)
sudo python3 firmware/dns_spoof.py --live --iface eth0 --domain example-lab.test --ip 192.0.2.200

# Run the test suite (12 deterministic offline tests)
python3 -m unittest discover -s tests
```

## CLI

```
python3 firmware/dns_spoof.py [-h] [-d DOMAIN] [-i IFACE] [--ip IP]
                              [--harness] [--live] [--timeout SEC]
```

- `-d, --domain` — target domain to spoof (default `example-lab.test`).
- `-i, --iface` — network interface for live mode (default `eth0`).
- `--ip` — spoofed answer address (default `192.0.2.200`).
- `--harness` — run the deterministic offline decider harness.
- `--live` — live sniff-and-spoof (requires root + scapy + authorization).
- `--timeout` — sniff timeout for live mode.

Exit codes: `0` on successful harness, `1` on failure.

## Project structure

```
firmware/dns_spoof.py   # DNS message engine, decider, harness, live mode
tests/test_dns_spoof.py # unittest coverage: codec, round-trip, decider
```

## Documentation

- [ETHICS.md](ETHICS.md) — acceptable and prohibited use.
- [SCOPE.md](SCOPE.md) — authorized target scope.
- [SECURITY.md](SECURITY.md) — responsible disclosure.
- [CONTRIBUTING.md](CONTRIBUTING.md) — contribution guide.

## Contributing

New query-ID defenses, additional RR-types and harness cases are welcome. Open
an issue or PR against the default branch; keep contributions scoped to
educational and authorization-respecting tooling.

## License

MIT — full legal shield in [LICENSE](LICENSE). Educational, authorization-
required software for studying DNS hijacking on networks you own or are
explicitly permitted to test.