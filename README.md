# 🌐 DNSHawk

> DNS recon & zone hygiene auditor — AXFR leaks, dangling CNAME takeovers, wildcard traps, SPF/DMARC holes and tunneling fingerprints, straight off the wire. Zero dependencies, pure Python stdlib.

[![Python](https://img.shields.io/badge/Python-3.9%2B-0D1117?style=for-the-badge&logo=python&logoColor=3776AB)](https://python.org)
[![Dependencies](https://img.shields.io/badge/Dependencies-0-00E676?style=for-the-badge&labelColor=0D1117)]()
[![License: MIT](https://img.shields.io/badge/License-MIT-0D1117?style=for-the-badge&labelColor=00E676)](LICENSE)
[![Author](https://img.shields.io/badge/Author-mustafaak0-0D1117?style=for-the-badge&logo=github&logoColor=00E676)](https://github.com/mustafaak0)

No `dnspython`, no `dig` shell-outs — DNSHawk builds DNS packets byte by byte,
chases compression pointers by hand and speaks UDP/TCP directly to the
resolver. The wire-format parser *is* the product.

## 🎯 Detections

| Finding | Logic | FP defense |
|---------|-------|------------|
| 🔓 **AXFR open** | zone transfer attempted over TCP against every NS | transfer must *complete* with records on the wire |
| 🪝 **CNAME takeover** | 35-service fingerprint list (heroku, github-pages, azure, cloudfront…) | dangling only if target NXDOMAINs; live targets downgraded to advisory |
| 📡 **DNS tunneling?** | TXT ≥80 chars, base64 charset, Shannon entropy ≥3.2 · hex labels ≥20 chars | `vendor-verification=token` records excluded — base64 padding never trails a key |
| 🌫️ **wildcard catch-all** | random-token probe *before* enumeration | wordlist hits that echo the probe answer are suppressed, not reported |
| 📧 **SPF / DMARC** | `+all` is critical, `p=none` monitor-only, missing policy flagged | strict `-all` + `p=reject` pass clean |
| 🏠 **internal leak** | RFC1918 / CGNAT / loopback IPs in public zone data | documentation ranges (192.0.2.x, 203.0.113.x…) don't count |
| 🔏 **no DNSSEC** | DO-bit EDNS query → AD flag / RRSIG presence | verified against live signed zones (isc.org, cloudflare.com) |

## 🚀 Usage

```bash
# offline demo: 3 synthetic zones, 8 planted findings, self-checking
python dnshawk.py --demo

# live audit (default resolver 1.1.1.1)
python dnshawk.py example.com

# custom resolver, zone-transfer attempts, own wordlist, JSON report
python dnshawk.py example.com --resolver 8.8.8.8 --axfr \
                        --wordlist subs.txt --json report.json
```

```
╭─ DNSHawk ───────────────────────────────────────────────────
│ zone     : vuln-demo.local
│ resolver : mock://demo (offline)
│ ns       : ns1.vuln-demo.local · ns2.vuln-demo.local
│ intel    : A 203.0.113.10 · MX mail · TXT 1 · DNSSEC ✘ · SPF +all!
│
│ ● [AXFR OPEN] ns2.vuln-demo.local  →  100/100
│   full zone transfer succeeded: 21 records dumped, 4 internal (cctv…
│ ● [SPF +all] anyone may send  →  90/100
│ ● [TAKEOVER] old.vuln-demo.local → vuln-app.herokuapp.com  →  85/100
│ ● [DNS TUNNELING?] covert channel fingerprints  →  70/100
│ ○ [INTERNAL LEAK] private IPs in public zone  →  35/100
╰──────────────────────────────────────────────────────────────
```

## 🧪 Verified on Synthetic Zones *and* the Real Internet

`--demo` plants 8 findings across three zones — a leaky one, a tidy one, and
a wildcard trap — then self-checks: **8/8 caught, 0 false positives**, and
the wildcard zone proves its 153 echo answers get suppressed instead of
reported as "subdomains found".

The demo runs the *exact* production code path: the mock resolver serves
real wire-format bytes, so every query built and every response parsed is
the same code that talks to 1.1.1.1. Field notes from live testing:

- `example.com` → clean bill (DNSSEC ✔, SPF `-all`, DMARC `p=reject`)
- `github.com` → 16 subdomains mapped, only true positives — its 24 TXT
  records include long base64 verification tokens that the `=`-heuristic
  correctly refuses to call tunneling

## 🧠 How the Wire Works (no dnspython!)

```
query    : header(ID · flags · counts) + QNAME labels + QTYPE/QCLASS
           [+ EDNS(0) OPT RR carrying the DO bit]
response : compressed names — 0xC0 pointer chase, loop-guarded
           → typed RDATA: A · AAAA · NS · CNAME · SOA · PTR · MX · TXT ·
             SRV · CAA (character-string chains decoded, not dumped as hex)
AXFR     : same question over TCP, 2-byte length prefixes, SOA…records…SOA
EDNS/DO  : OPT TTL = ext-rcode(1B) + version(1B) + flags(2B, DO = 0x8000)
```

UDP first, TCP re-ask on truncation (`TC` bit), retries with fresh IDs,
IDN/punycode labels, null-MX (`0 .`) handled.

## 🔭 Roadmap

- [ ] NSEC3 walking on signed zones
- [ ] cache snooping (RD=0 probes)
- [ ] CNAME chain rendering with depth limit
- [ ] IoC export as CSV for your SIEM

## ⚖️ Disclaimer

For zones **you are authorized to assess**.
Recon responsibly.

---

<div align="center">

*The quietest exfiltration channel is the one the firewall must leave open.*

</div>
