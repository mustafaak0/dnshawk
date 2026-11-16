#!/usr/bin/env python3
"""
DNSHawk — DNS recon & zone hygiene auditor. Zero dependencies, pure stdlib.

Speaks raw DNS wire format by hand (no dnspython): builds query packets,
chases compression pointers, and audits a zone like a pentester on recon:

  - subdomain enumeration   (built-in wordlist, wildcard-aware)
  - AXFR zone transfer      (the classic misconfiguration)
  - dangling CNAME takeover (heroku / github-pages / azure / … fingerprints)
  - SPF & DMARC hygiene     (+all spf, missing/p=none DMARC)
  - DNSSEC presence         (DO bit + AD flag / RRSIG)
  - DNS tunneling heuristics (long base64 TXT payloads, hex labels)
  - internal address leaks   (RFC1918 hosts exposed in public zone data)

For zones you are authorized to assess. Recon responsibly.
"""

from __future__ import annotations

import argparse
import base64
import ipaddress
import json
import math
import re
import secrets
import socket
import struct
import sys
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

__version__ = "1.0.0"

# --------------------------------------------------------------------------
# constants / knowledge bases
# --------------------------------------------------------------------------

TYPE_A, TYPE_NS, TYPE_CNAME, TYPE_SOA = 1, 2, 5, 6
TYPE_PTR, TYPE_MX, TYPE_TXT, TYPE_AAAA = 12, 15, 16, 28
TYPE_SRV, TYPE_OPT, TYPE_RRSIG, TYPE_AXFR = 33, 41, 46, 252
TYPE_CAA = 257

TYPE_NAMES = {
    TYPE_A: "A", TYPE_NS: "NS", TYPE_CNAME: "CNAME", TYPE_SOA: "SOA",
    TYPE_PTR: "PTR", TYPE_MX: "MX", TYPE_TXT: "TXT", TYPE_AAAA: "AAAA",
    TYPE_SRV: "SRV", TYPE_CAA: "CAA", TYPE_RRSIG: "RRSIG", TYPE_AXFR: "AXFR",
}

RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN",
          4: "NOTIMP", 5: "REFUSED"}

UDP_RETRIES = 2          # per-query retries before giving up
TXT_TUNNEL_LEN = 80      # TXT payload this long + base64ish = tunneling fuel
LABEL_HEX_LEN = 20       # single label this long + hex = covert-channel fuel
ENTROPY_MIN = 3.2        # shannon bits/char for "encoded, not human" verdict

# subdomain bruteforce wordlist (kept short & high-yield; bring your own too)
WORDS = (
    "www www2 mail mail2 smtp pop imap webmail owa exchange autodiscover "
    "autoconfig vpn vpn2 remote portal gateway gw proxy ns1 ns2 dns "
    "api api2 app apps dev dev1 dev2 test staging stage uat qa sandbox "
    "demo beta admin administrator panel cpanel whm plesk dashboard manage "
    "monitor grafana kibana prometheus nagios zabbix jenkins ci cd git "
    "gitlab svn bamboo artifactory docker registry k8s kube rancher jira "
    "confluence wiki docs help support kb status health backup db data sql "
    "mysql postgres mongodb redis memcached kafka queue cache cdn static "
    "assets img images media files download downloads upload share cloud "
    "storage drive office mobile ios android shop store cart pay payment "
    "billing crm erp hr intranet internal corp lan old legacy archive "
    "temp tmp security soc siem firewall fw router switch printer print "
    "scan cctv cam voip sip pbx meet video chat xmpp shop2 teams relay "
    "mx mx2 imap2 pop3 smtp2 bastion jump host logger syslog snmp salt "
).split()

# CNAME takeover fingerprints: target suffix -> service
TAKEOVER_FP = {
    "github.io": "GitHub Pages", "herokuapp.com": "Heroku",
    "herokudns.com": "Heroku", "azurewebsites.net": "Azure App Service",
    "cloudapp.net": "Azure Cloud Service", "trafficmanager.net": "Azure Traffic Manager",
    "azureedge.net": "Azure CDN", "blob.core.windows.net": "Azure Blob",
    "cloudfront.net": "AWS CloudFront", "elb.amazonaws.com": "AWS ELB",
    "elasticloadbalancing.com": "AWS ELB", "netlify.app": "Netlify",
    "vercel.app": "Vercel", "now.sh": "Vercel", "gitbook.io": "GitBook",
    "readthedocs.io": "ReadTheDocs", "fastly.net": "Fastly",
    "pantheon.io": "Pantheon", "tumblr.com": "Tumblr",
    "wordpress.com": "WordPress.com", "shopify.com": "Shopify",
    "zendesk.com": "Zendesk", "freshdesk.com": "Freshdesk",
    "helpscoutdocs.com": "HelpScout", "intercom.help": "Intercom",
    "unbouncepages.com": "Unbounce", "webflow.io": "Webflow",
    "surge.sh": "Surge.sh", "firebaseio.com": "Firebase",
    "web.app": "Firebase Hosting", "firebaseapp.com": "Firebase",
    "cloudfunctions.net": "GCP Cloud Functions", "apigee.net": "Apigee",
}

# ranges that should never appear in a public zone
INTERNAL_NETS = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8",
    "169.254.0.0/16", "100.64.0.0/10", "fe80::/10", "fc00::/7",
)]


# --------------------------------------------------------------------------
# data types
# --------------------------------------------------------------------------

@dataclass
class Record:
    name: str
    rtype: int
    ttl: int
    data: str                     # humanized value


@dataclass
class Message:
    qid: int
    rcode: int
    aa: bool
    tc: bool
    ra: bool
    ad: bool
    question: tuple
    answers: list = field(default_factory=list)
    authority: list = field(default_factory=list)
    additional: list = field(default_factory=list)

    def all_records(self):
        return self.answers + self.authority + self.additional


@dataclass
class Finding:
    tag: str
    title: str
    detail: str
    score: int                    # 0-100, house-style confidence


@dataclass
class Report:
    domain: str
    resolver: str
    ns: list = field(default_factory=list)
    apex: list = field(default_factory=list)      # "A 1.2.3.4" strings
    mx: list = field(default_factory=list)
    txt_count: int = 0
    dnssec: bool = False
    spf: str = ""
    dmarc: str = ""
    subdomains: list = field(default_factory=list)  # (name, "A/CNAME", value)
    suppressed: int = 0                             # wildcard-echo probes
    axfr: str = ""
    findings: list = field(default_factory=list)
    errors: list = field(default_factory=list)


class DnsError(Exception):
    pass


# --------------------------------------------------------------------------
# wire format — encode
# --------------------------------------------------------------------------

def _enc_label(label: str) -> bytes:
    if label.isascii():
        return label.encode()
    try:                                    # IDN -> punycode where possible
        return label.encode("idna")
    except (UnicodeError, ValueError):
        return label.encode("utf-8")        # raw label; some servers accept


def encode_name(name: str) -> bytes:
    out = b""
    name = name.strip().rstrip(".")
    if name:
        for label in name.split("."):
            b = _enc_label(label)
            if not 0 < len(b) < 64:
                raise DnsError(f"bad label {label!r} in {name!r}")
            out += bytes([len(b)]) + b
    return out + b"\x00"


def build_query(qid: int, name: str, qtype: int, rd: bool = True,
                dnssec: bool = False) -> bytes:
    """One question, optional EDNS(0) OPT RR carrying the DO bit."""
    flags = 0x0100 if rd else 0                 # RD set for recursive asks
    header = struct.pack("!HHHHHH", qid & 0xFFFF, flags, 1, 0, 0,
                         1 if dnssec else 0)
    body = encode_name(name) + struct.pack("!HH", qtype, 1)
    opt = b""
    if dnssec:
        # OPT: root name, type 41, class = payload size, TTL = ext-rcode(1B)
        # + version(1B) + flags(2B) with DO = 0x8000, rdlen 0
        opt = b"\x00" + struct.pack("!HHIH", TYPE_OPT, 1232, 0x00008000, 0)
    return header + body + opt


# --------------------------------------------------------------------------
# wire format — decode
# --------------------------------------------------------------------------

def decode_name(msg: bytes, off: int) -> tuple:
    """Follow 0xC0 compression pointers; return (name, next-unread-offset)."""
    labels, jumped, jumps, end = [], False, 0, off
    while True:
        if off >= len(msg):
            raise DnsError("name runs off packet")
        ln = msg[off]
        if ln == 0:
            if not jumped:
                end = off + 1
            break
        if ln & 0xC0 == 0xC0:                       # compression pointer
            if off + 1 >= len(msg):
                raise DnsError("truncated pointer")
            ptr = ((ln & 0x3F) << 8) | msg[off + 1]
            if not jumped:
                end = off + 2
            jumped = True
            jumps += 1
            if jumps > 32:
                raise DnsError("compression pointer loop")
            off = ptr
            continue
        if ln & 0xC0:
            raise DnsError(f"reserved label type {ln:#04x}")
        labels.append(msg[off + 1:off + 1 + ln]
                      .decode("utf-8", "replace"))
        off += 1 + ln
    return ".".join(labels), end


def _parse_rdata(rtype: int, raw: bytes, msg: bytes, off: int) -> str:
    """Humanize one RDATA blob (offsets are into the full message for names)."""
    if rtype == TYPE_A and len(raw) == 4:
        return socket.inet_ntoa(raw)
    if rtype == TYPE_AAAA and len(raw) == 16:
        return socket.inet_ntop(socket.AF_INET6, raw)
    if rtype in (TYPE_NS, TYPE_CNAME, TYPE_PTR):
        return decode_name(msg, off)[0]
    if rtype == TYPE_SOA:
        mname, off2 = decode_name(msg, off)
        rname, off2 = decode_name(msg, off2)
        ser, ref, ret, exp, mini = struct.unpack("!IIIII", raw[-20:])
        return f"{mname} {rname} (serial {ser})"
    if rtype == TYPE_MX:
        pref = struct.unpack("!H", raw[:2])[0]
        return f"{pref} {decode_name(msg, off + 2)[0]}"
    if rtype == TYPE_TXT:
        parts, i = [], 0                         # character-string chain
        while i < len(raw):
            n = raw[i]
            parts.append(raw[i + 1:i + 1 + n].decode("utf-8", "replace"))
            i += 1 + n
        return "".join(parts)
    if rtype == TYPE_SRV:
        pri, wt, port = struct.unpack("!HHH", raw[:6])
        return f"{pri} {wt} {port} {decode_name(msg, off + 6)[0]}"
    if rtype == TYPE_CAA:
        flag, tlen = raw[0], raw[1]
        return f"{flag} {raw[2:2 + tlen].decode()} {raw[2 + tlen:].decode()}"
    hexs = raw.hex()
    return hexs[:32] + ("…" if len(hexs) > 32 else "")


def parse_message(data: bytes) -> Message:
    if len(data) < 12:
        raise DnsError("response shorter than header")
    qid, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", data[:12])
    msg = Message(
        qid=qid,
        rcode=flags & 0xF,
        aa=bool(flags & 0x0400), tc=bool(flags & 0x0200),
        ra=bool(flags & 0x0080), ad=bool(flags & 0x0020),
        question=("", 0),
    )
    off = 12
    if qd:
        qname, off = decode_name(data, off)
        qtype, _qclass = struct.unpack("!HH", data[off:off + 4])
        msg.question = (qname.lower().rstrip("."), qtype)
        off += 4
    for count, target in ((an, "a"), (ns, "n"), (ar, "d")):
        for _ in range(count):
            if off + 10 > len(data):
                return msg                        # tolerate truncated tails
            name, off = decode_name(data, off)
            rtype, rclass, ttl, rdlen = struct.unpack("!HHIH", data[off:off + 10])
            off += 10
            if off + rdlen > len(data):
                return msg
            try:
                human = _parse_rdata(rtype, data[off:off + rdlen], data, off)
            except Exception:
                human = data[off:off + rdlen].hex()[:24]
            rec = Record(name.lower().rstrip("."), rtype, ttl, human)
            if target == "a":
                msg.answers.append(rec)
            elif target == "n":
                msg.authority.append(rec)
            else:
                msg.additional.append(rec)
            off += rdlen
    return msg


# --------------------------------------------------------------------------
# transports — live (UDP/TCP) and mock (offline demo)
# --------------------------------------------------------------------------

class UdpDnsClient:
    """Real resolver talk: UDP first, TCP on truncation, AXFR over TCP."""

    label = ""

    def __init__(self, resolver: str, timeout: float):
        self.server = resolver
        self.timeout = timeout
        self.label = resolver

    # -- single UDP/TCP round trip -------------------------------------
    def _exchange(self, wire: bytes, tcp: bool = False) -> bytes:
        if tcp:
            with socket.create_connection((self.server, 53), self.timeout) as s:
                s.settimeout(self.timeout)
                s.sendall(struct.pack("!H", len(wire)) + wire)
                ln = s.recv(2)
                if len(ln) < 2:
                    raise DnsError("short TCP length prefix")
                need = struct.unpack("!H", ln)[0]
                buf = b""
                while len(buf) < need:
                    chunk = s.recv(need - len(buf))
                    if not chunk:
                        break
                    buf += chunk
            return buf
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(self.timeout)
            s.sendto(wire, (self.server, 53))
            data, _ = s.recvfrom(65535)
        return data

    def query(self, name: str, qtype: int, dnssec: bool = False) -> Message:
        wire = build_query(secrets.randbits(16), name, qtype, True, dnssec)
        data, last = None, None
        for _ in range(UDP_RETRIES + 1):
            try:
                data = self._exchange(wire)
                break
            except OSError as exc:
                last = exc
        if data is None:
            raise DnsError(f"query {name} timed out ({last})")
        msg = parse_message(data)
        if msg.tc:                                 # truncated -> redo on TCP
            tcp_wire = build_query(msg.qid, name, qtype, True, dnssec)
            msg = parse_message(self._exchange(tcp_wire, tcp=True))
        return msg

    def axfr(self, domain: str, ns_host: str):
        """Try a zone transfer; returns (records, None) or (None, reason)."""
        try:
            addr = next(r.data for r in self.query(ns_host, TYPE_A).answers
                        if r.rtype == TYPE_A)
        except (StopIteration, DnsError):
            return None, f"no A record for {ns_host}"
        wire = build_query(secrets.randbits(16), domain, TYPE_AXFR, False)
        recs, soas = [], 0
        try:
            with socket.create_connection((addr, 53), self.timeout) as s:
                s.settimeout(self.timeout)
                s.sendall(struct.pack("!H", len(wire)) + wire)
                while soas < 2:
                    ln = s.recv(2)
                    if len(ln) < 2:
                        break
                    need = struct.unpack("!H", ln)[0]
                    buf = b""
                    while len(buf) < need:
                        chunk = s.recv(need - len(buf))
                        if not chunk:
                            return recs, None    # server hung up mid-stream
                        buf += chunk
                    m = parse_message(buf)
                    if m.rcode != 0:
                        return None, RCODES.get(m.rcode, m.rcode)
                    if not m.answers:
                        break
                    for r in m.answers:
                        if r.rtype == TYPE_SOA:
                            soas += 1
                            if soas == 2:
                                break
                        recs.append(r)
        except OSError as exc:
            return None, type(exc).__name__.lower()
        return (recs, None) if recs else (None, "empty")


class MockZone:
    """A synthetic zone the MockTransport serves from wire-format bytes."""

    def __init__(self, domain, dnssec=False, axfr_ips=()):
        self.domain = domain
        self.records = {}                        # name -> [(rtype, value)]
        self.dnssec = dnssec
        self.axfr_ips = set(axfr_ips)
        self.wildcard = None                     # e.g. "192.0.2.1"

    def add(self, name, rtype, value):
        # keys are always fully-qualified — lookups arrive as FQDNs
        if name != self.domain and not name.endswith("." + self.domain):
            name = f"{name}.{self.domain}"
        self.records.setdefault(name, []).append((rtype, value))

    def match(self, qname):
        if qname in self.records:
            return self.records[qname]
        if self.wildcard and "." in qname:
            parent = qname.split(".", 1)[1]
            if parent == self.domain or parent.endswith("." + self.domain):
                return [(TYPE_A, self.wildcard)]
        return None


def _encode_rdata(rtype: int, value: str) -> bytes:
    if rtype == TYPE_A:
        return socket.inet_aton(value)
    if rtype == TYPE_AAAA:
        return socket.inet_pton(socket.AF_INET6, value)
    if rtype in (TYPE_NS, TYPE_CNAME, TYPE_PTR):
        return encode_name(value)
    if rtype == TYPE_SOA:
        mname, rname, ser = value.split()[:3]
        nums = value.split()[3:]
        return (encode_name(mname) + encode_name(rname)
                + struct.pack("!IIIII", int(ser), *[int(n) for n in nums]))
    if rtype == TYPE_MX:
        pref, host = value.split()
        return struct.pack("!H", int(pref)) + encode_name(host)
    if rtype == TYPE_TXT:
        out = b""
        for i in range(0, len(value), 255):      # character-string chunks
            chunk = value[i:i + 255].encode()
            out += bytes([len(chunk)]) + chunk
        return out
    if rtype == TYPE_CAA:
        flag, tag, val = value.split(" ", 2)
        return (bytes([int(flag), len(tag)]) + tag.encode() + val.encode())
    return bytes.fromhex(value)                  # RRSIG & friends: raw blob


class MockTransport:
    """Serves MockZones by building real wire responses (parser gets a workout)."""

    def __init__(self):
        self.zones = {}

    def _zone_for(self, qname):
        best = None
        for z in self.zones.values():
            if qname == z.domain or qname.endswith("." + z.domain):
                if best is None or len(z.domain) > len(best.domain):
                    best = z
        return best

    def response(self, wire: bytes, qid: int, qname: str, qtype: int,
                 rcode: int, rrsets, dnssec: bool) -> bytes:
        flags = 0x8000 | 0x0100 | 0x0080 | 0x0400        # QR RD RA AA
        if dnssec:
            flags |= 0x0020                              # AD
        head = struct.pack("!HHHHHH", qid, flags | rcode, 1, len(rrsets), 0, 0)
        out = head + encode_name(qname) + struct.pack("!HH", qtype, 1)
        for name, rtype, ttl, value in rrsets:
            rdata = _encode_rdata(rtype, value)
            out += (encode_name(name) + struct.pack("!HHIH", rtype, 1, ttl,
                                                    len(rdata)) + rdata)
        return out

    def exchange(self, wire: bytes) -> bytes:
        qid, _fl, qd = struct.unpack("!HHH", wire[:6])
        if not qd:
            raise DnsError("mock: no question")
        qname, off = decode_name(wire, 12)
        qtype, _c = struct.unpack("!HH", wire[off:off + 4])
        qname = qname.lower().rstrip(".")
        zone = self._zone_for(qname)
        if zone is None:
            return self.response(wire, qid, qname, qtype, 3, [], False)
        hits = zone.match(qname)
        if hits is None:
            return self.response(wire, qid, qname, qtype, 3, [], False)
        rrsets = [(qname, t, 3600, v) for t, v in hits
                  if t == qtype or qtype == 255
                  or (t == TYPE_CNAME and qtype in (TYPE_A, TYPE_AAAA))]
        # CNAME chase inside the zone (enum should see the alias + target)
        for t, v in hits:
            if t == TYPE_CNAME and qtype in (TYPE_A, TYPE_AAAA):
                tgt = v.lower().rstrip(".")
                if self._zone_for(tgt) is not None:
                    for t2, v2 in (self._zone_for(tgt).match(tgt) or []):
                        if t2 == TYPE_A:
                            rrsets.append((tgt, TYPE_A, 3600, v2))
        wants_dnssec = b"\x00" + struct.pack("!HHIH", TYPE_OPT, 1232, 0x00008000, 0) in wire
        if wants_dnssec and zone.dnssec:
            # a synthetic RRSIG-shaped blob: presence is all the auditor needs
            rrsets.append((qname, TYPE_RRSIG, 3600,
                           "0006380d2026111604171000142030" + "ab" * 8))
        return self.response(wire, qid, qname, qtype, 0, rrsets, zone.dnssec)

    def axfr(self, domain, ns_ip):
        zone = self.zones.get(domain)
        if zone is None:
            return None, "REFUSED"
        if ns_ip not in zone.axfr_ips:
            return None, "REFUSED"
        rrsets = []
        for name, items in zone.records.items():
            for t, v in items:
                rrsets.append((name, t, 3600, v))
        rrsets.sort(key=lambda r: (r[0], r[1]))
        soa = next(r for r in rrsets if r[1] == TYPE_SOA)  # SOA first & last
        rrsets = [soa] + [r for r in rrsets if r[1] != TYPE_SOA]
        msgs = []
        for i in range(0, len(rrsets), 10):
            chunk = rrsets[i:i + 10]
            if i + 10 >= len(rrsets):
                chunk = chunk + [soa]                    # closing SOA
            qid = secrets.randbits(16)
            body = self.response(b"", qid, domain, TYPE_AXFR, 0, chunk, True)
            msgs.append(body)
        recs = []
        for m in msgs:
            recs.extend(parse_message(m).answers)
        return recs, None


class MockDnsClient:
    """Same interface as UdpDnsClient, backed by MockTransport."""

    def __init__(self, transport: MockTransport):
        self.t = transport
        self.label = "mock://demo (offline)"

    def query(self, name: str, qtype: int, dnssec: bool = False) -> Message:
        wire = build_query(secrets.randbits(16), name, qtype, True, dnssec)
        return parse_message(self.t.exchange(wire))

    def axfr(self, domain: str, ns_host: str):
        zone = self.t.zones.get(domain)
        if zone is None:
            return None, "REFUSED"
        try:
            ns_ip = next(v for t, v in zone.records.get(ns_host, [])
                         if t == TYPE_A)
        except StopIteration:
            return None, f"no A record for {ns_host}"
        return self.t.axfr(domain, ns_ip)


# --------------------------------------------------------------------------
# heuristics
# --------------------------------------------------------------------------

def shannon(s: str) -> float:
    if not s:
        return 0.0
    freq = {c: s.count(c) for c in set(s)}
    n = len(s)
    return -sum((k / n) * math.log2(k / n) for k in freq.values())


B64_RE = re.compile(r"^[A-Za-z0-9+/=_-]+$")
HEX_RE = re.compile(r"^[0-9a-fA-F]+$")


def looks_encoded(s: str) -> bool:
    # "vendor-verification=<token>" records have '=' mid-string; base64
    # padding only ever trails — so key=value shapes are legit, not tunnels
    if "=" in s.rstrip("="):
        return False
    return (len(s) >= TXT_TUNNEL_LEN and bool(B64_RE.match(s))
            and shannon(s) >= ENTROPY_MIN)


def label_is_hex(label: str) -> bool:
    return len(label) >= LABEL_HEX_LEN and bool(HEX_RE.match(label))


def is_internal(addr: str) -> bool:
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False
    return any(ip in net for net in INTERNAL_NETS)


def takeover_service(cname_target: str):
    t = cname_target.lower().rstrip(".")
    for suffix, service in TAKEOVER_FP.items():
        if t == suffix or t.endswith("." + suffix):
            return service
    return None


def spf_verdict(txts: list) -> tuple:
    """Return (spf_record, finding_or_None) — +all is the headline act."""
    for t in txts:
        if t.startswith("v=spf1"):
            tail = t[len("v=spf1"):].split()
            if "+all" in tail or "all" in tail:
                return t, Finding(
                    "SPF-PERMISSIVE", "[SPF +all] anyone may send",
                    "v=spf1 … +all — every host on the internet is an "
                    "authorized sender for this domain", 90)
            if "?all" in tail:
                return t, Finding(
                    "SPF-NEUTRAL", "[SPF ?all] neutral policy",
                    "neutral result — receivers fall back to guessing", 45)
            return t, None
    return "", None


# --------------------------------------------------------------------------
# the audit itself
# --------------------------------------------------------------------------

def audit(domain, client, words=WORDS, do_axfr=False, workers=12) -> Report:
    rep = Report(domain=domain.rstrip("."),
                 resolver=client.label)

    soa = client.query(domain, TYPE_SOA, dnssec=True)
    if soa.rcode == 3:
        raise DnsError(f"NXDOMAIN — {domain} does not exist")
    rep.dnssec = soa.ad or any(r.rtype == TYPE_RRSIG for r in soa.all_records())

    ns_msg = client.query(domain, TYPE_NS)
    rep.ns = sorted({r.data for r in ns_msg.answers if r.rtype == TYPE_NS})

    for r in client.query(domain, TYPE_A).answers:
        if r.rtype == TYPE_A:
            rep.apex.append(f"A {r.data}")
        if r.rtype == TYPE_CNAME:
            rep.apex.append(f"CNAME {r.data}")
    for r in client.query(domain, TYPE_AAAA).answers:
        if r.rtype == TYPE_AAAA:
            rep.apex.append(f"AAAA {r.data}")
    mx_msg = client.query(domain, TYPE_MX)
    rep.mx = sorted({r.data for r in mx_msg.answers if r.rtype == TYPE_MX}) \
        if mx_msg.rcode == 0 and mx_msg.answers else []
    txts = [r.data for r in client.query(domain, TYPE_TXT).answers
            if r.rtype == TYPE_TXT]
    rep.txt_count = len(txts)

    # -- email hygiene ---------------------------------------------------
    rep.spf, f = spf_verdict(txts)
    if f:
        rep.findings.append(f)
    dmarc = [r.data for r in client.query(f"_dmarc.{domain}", TYPE_TXT).answers
             if r.rtype == TYPE_TXT and r.data.startswith("v=DMARC1")]
    if dmarc:
        m = re.search(r"p\s*=\s*(\w+)", dmarc[0])
        rep.dmarc = m.group(1) if m else "?"
        if rep.dmarc == "none":
            rep.findings.append(Finding(
                "DMARC-NONE", "[DMARC p=none] monitor-only policy",
                "DMARC is deployed but takes no action — phishing continues "
                "undelivered-but-unblocked", 40))
    else:
        rep.dmarc = ""
        rep.findings.append(Finding(
            "DMARC-MISSING", "[DMARC missing] no policy at all",
            f"no TXT record on _dmarc.{domain} — receivers have no guidance "
            "on spoofed mail", 55))

    # -- wildcard detection (before enum, or 150 'findings' laugh at you) --
    wildcard_hit = None
    probe = f"{secrets.token_hex(6)}.{domain}"
    try:
        pm = client.query(probe, TYPE_A)
        wildcard_hit = next((r for r in pm.answers
                             if r.rtype in (TYPE_A, TYPE_CNAME)), None)
    except DnsError:
        pass
    wildcard_on = wildcard_hit is not None

    # -- subdomain enumeration -------------------------------------------
    def hunt(word):
        try:
            m = client.query(f"{word}.{domain}", TYPE_A)
        except DnsError:
            return word, None
        if m.rcode != 0:
            return word, None
        a = next((r for r in m.answers if r.rtype == TYPE_A), None)
        cn = next((r for r in m.answers if r.rtype == TYPE_CNAME), None)
        if a is None and cn is None:
            return word, None
        return word, (cn.data if cn else a.data, bool(cn))

    with ThreadPoolExecutor(max_workers=max(1, workers)) as ex:
        results = dict(ex.map(hunt, words))

    cn_targets = {}
    for word, hit in sorted(results.items()):
        if hit is None:
            continue
        value, is_cname = hit
        fq = f"{word}.{domain}"
        if wildcard_on and wildcard_hit is not None:
            wv = (wildcard_hit.data if wildcard_hit.rtype == TYPE_CNAME
                  else wildcard_hit.data)
            if value == wv:
                rep.suppressed += 1
                continue
        rep.subdomains.append((fq, "CNAME" if is_cname else "A", value))
        if is_cname:
            cn_targets[fq] = value
    if wildcard_on:
        rep.findings.append(Finding(
            "WILDCARD", "[WILDCARD] catch-all DNS",
            f"*.{domain} answers everything ({TYPE_NAMES.get(wildcard_hit.rtype, '?')} "
            f"{wildcard_hit.data}) — enum results filtered, brute-force "
            "yield is zero", 20))

    # -- dangling CNAME takeover -----------------------------------------
    for fq, target in cn_targets.items():
        service = takeover_service(target)
        if not service:
            continue
        try:
            alive = client.query(target, TYPE_A).rcode == 0
        except DnsError:
            alive = False
        if alive:
            rep.findings.append(Finding(
                "TAKEOVER-SVC", f"[TAKEOVER SVC] {fq} → {target}",
                f"CNAME to {service} (target resolves — verify ownership, "
                "it is one expiry away from takeover)", 35))
        else:
            rep.findings.append(Finding(
                "TAKEOVER", f"[TAKEOVER] {fq} → {target}",
                f"dangling CNAME to {service} — target does not resolve; "
                "claim it and you own the name", 85))

    # -- DNS tunneling heuristics -----------------------------------------
    tun_hits = [f"TXT@{domain} ({len(t)} chars)" for t in txts
                if looks_encoded(t)]
    for fq, kind, value in rep.subdomains:
        if kind != "CNAME":
            try:
                for r in client.query(fq, TYPE_TXT).answers:
                    if r.rtype == TYPE_TXT and looks_encoded(r.data):
                        tun_hits.append(f"TXT@{fq} ({len(r.data)} chars)")
            except DnsError:
                pass
        for label in fq.split(".")[:-2]:
            if label_is_hex(label):
                tun_hits.append(f"hex label '{label}' in {fq}")
    if tun_hits:
        rep.findings.append(Finding(
            "DNS-TUNNEL", "[DNS TUNNELING?] covert channel fingerprints",
            "; ".join(tun_hits[:3]) + (" …" if len(tun_hits) > 3 else "")
            + " — long encoded TXT payloads / hex labels are iodine & "
            "dnscat2 territory", 70))

    # -- internal address leaks -------------------------------------------
    leaks = [f"{fq} → {v}" for fq, k, v in rep.subdomains
             if k == "A" and is_internal(v)]
    leaks += [f"{domain} → {v[2:]}" for v in rep.apex
              if v.startswith("A ") and is_internal(v[2:])]
    if leaks:
        rep.findings.append(Finding(
            "INTERNAL-LEAK", "[INTERNAL LEAK] private IPs in public zone",
            "; ".join(leaks[:4]) + (" …" if len(leaks) > 4 else "")
            + " — internal topology served to the whole internet", 35))

    if not rep.dnssec:
        rep.findings.append(Finding(
            "NO-DNSSEC", "[NO DNSSEC] unsigned zone",
            "responses are spoofable — no RRSIG/AD in sight (recon note; "
            "not an outage)", 25))

    # -- AXFR ---------------------------------------------------------------
    if do_axfr and rep.ns:
        for ns in rep.ns:
            try:
                recs, err = client.axfr(domain, ns)
            except DnsError as exc:
                recs, err = None, str(exc)
            if err:
                rep.errors.append(f"AXFR {ns}: {err}")
                continue
            internal = [r for r in recs if r.rtype == TYPE_A
                        and is_internal(r.data)]
            rep.axfr = f"{ns} leaked {len(recs)} records"
            rep.findings.append(Finding(
                "AXFR", f"[AXFR OPEN] {ns}",
                f"full zone transfer succeeded: {len(recs)} records dumped"
                + (f", {len(internal)} internal ({internal[0].name} → "
                   f"{internal[0].data}…)" if internal else "")
                + " — the entire attack surface, gift-wrapped", 100))
            break

    rep.findings.sort(key=lambda f: -f.score)
    return rep


# --------------------------------------------------------------------------
# rendering
# --------------------------------------------------------------------------

def render(rep: Report, out=print):
    out(f"╭─ DNSHawk ─{'─' * 50}")
    out(f"│ zone     : {rep.domain}")
    out(f"│ resolver : {rep.resolver}")
    if rep.ns:
        out(f"│ ns       : {' · '.join(rep.ns)}")
    intel = []
    if rep.apex:
        intel.append(" · ".join(rep.apex[:3]))
    if rep.mx:
        parts = rep.mx[0].split()             # "10 host" — or null-MX "0 ."
        intel.append("MX " + (parts[1] if len(parts) > 1 else parts[0]))
    intel.append(f"TXT {rep.txt_count}")
    intel.append("DNSSEC ✔" if rep.dnssec else "DNSSEC ✘")
    if rep.spf:
        intel.append("SPF " + ("strict" if "-all" in rep.spf
                               else ("+all!" if "+all" in rep.spf else "soft")))
    if rep.dmarc:
        intel.append(f"DMARC p={rep.dmarc}")
    out(f"│ intel    : {' · '.join(intel)}")
    out("│")
    if not rep.findings:
        out("│ ✔ no findings — zone looks tidy")
    for f in rep.findings:
        bullet = "●" if f.score >= 40 else "○"
        out(f"│ {bullet} {f.title}  →  {f.score}/100")
        out(f"│   {f.detail}")
    if rep.subdomains:
        out("│")
        subs = [f"{n} ({k} {v})" for n, k, v in rep.subdomains[:6]]
        more = len(rep.subdomains) - 6
        out(f"│ ⊕ subdomains: {', '.join(subs)}"
            + (f" +{more} more" if more > 0 else ""))
    if rep.suppressed:
        out(f"│ ⊕ wildcard suppressed {rep.suppressed} wordlist probes")
    out(f"╰{'─' * 60}")


def report_json(rep: Report) -> dict:
    return {
        "tool": "dnshawk", "version": __version__,
        "domain": rep.domain, "resolver": rep.resolver,
        "nameservers": rep.ns, "apex": rep.apex, "mx": rep.mx,
        "txt_count": rep.txt_count, "dnssec": rep.dnssec,
        "spf": rep.spf, "dmarc": rep.dmarc, "axfr": rep.axfr,
        "subdomains": [{"name": n, "kind": k, "value": v}
                       for n, k, v in rep.subdomains],
        "wildcard_suppressed": rep.suppressed,
        "findings": [{"tag": f.tag, "title": f.title, "detail": f.detail,
                      "score": f.score} for f in rep.findings],
        "errors": rep.errors,
    }


# --------------------------------------------------------------------------
# offline demo — three synthetic zones, planted findings, self-check
# --------------------------------------------------------------------------

def build_demo_zones() -> MockTransport:
    t = MockTransport()

    vuln = MockZone("vuln-demo.local",
                    axfr_ips={"203.0.113.54"})          # ns2 is the leaky one
    vuln.add("vuln-demo.local", TYPE_SOA,
             "ns1.vuln-demo.local hostmaster.vuln-demo.local 2026111601 "
             "7200 900 1209600 300")
    vuln.add("vuln-demo.local", TYPE_NS, "ns1.vuln-demo.local")
    vuln.add("vuln-demo.local", TYPE_NS, "ns2.vuln-demo.local")
    vuln.add("vuln-demo.local", TYPE_A, "203.0.113.10")
    vuln.add("vuln-demo.local", TYPE_MX, "10 mail")
    vuln.add("vuln-demo.local", TYPE_TXT, "v=spf1 +all")     # planted #2
    vuln.add("www", TYPE_A, "203.0.113.10")
    vuln.add("mail", TYPE_A, "203.0.113.25")
    vuln.add("ns1", TYPE_A, "203.0.113.53")
    vuln.add("ns2", TYPE_A, "203.0.113.54")
    vuln.add("staging", TYPE_A, "203.0.113.60")
    vuln.add("vpn", TYPE_A, "10.0.0.7")                      # planted #6
    vuln.add("intranet", TYPE_A, "10.0.0.8")
    vuln.add("git", TYPE_A, "10.0.0.15")
    vuln.add("cctv", TYPE_A, "10.0.0.30")
    vuln.add("old", TYPE_CNAME, "vuln-app.herokuapp.com")    # planted #4
    vuln.add("data", TYPE_A, "203.0.113.61")                 # reachable, so the
    for i in range(3):                                       # planted #5 TXTs
        blob = base64.b64encode(             # underneath get inspected
            f"exfil-chunk-{i:02d}-".encode()
            + secrets.token_bytes(64)).decode()
        vuln.add("data", TYPE_TXT, blob)
    t.zones["vuln-demo.local"] = vuln                        # planted #1 AXFR,
    # planted #3 = no _dmarc record (absence), #7 = no DNSSEC

    clean = MockZone("clean-demo.local", dnssec=True)
    clean.add("clean-demo.local", TYPE_SOA,
              "ns1.clean-demo.local hostmaster.clean-demo.local 2026111601 "
              "7200 900 1209600 300")
    clean.add("clean-demo.local", TYPE_NS, "ns1.clean-demo.local")
    clean.add("clean-demo.local", TYPE_NS, "ns2.clean-demo.local")
    clean.add("clean-demo.local", TYPE_A, "198.51.100.10")
    clean.add("clean-demo.local", TYPE_MX, "10 mail")
    clean.add("clean-demo.local", TYPE_TXT, "v=spf1 -all")
    clean.add("clean-demo.local", TYPE_TXT, "google-site-verification=1a2b3c")
    clean.add("_dmarc", TYPE_TXT,
              "v=DMARC1; p=reject; rua=mailto:dmarc@clean-demo.local")
    clean.add("www", TYPE_A, "198.51.100.10")
    clean.add("mail", TYPE_A, "198.51.100.25")
    clean.add("ns1", TYPE_A, "198.51.100.53")
    clean.add("ns2", TYPE_A, "198.51.100.54")
    clean.add("api", TYPE_CNAME, "www")                      # chases, resolves
    t.zones["clean-demo.local"] = clean

    parked = MockZone("parked-demo.local", dnssec=True)
    parked.add("parked-demo.local", TYPE_SOA,
               "ns1.parked-demo.local hostmaster.parked-demo.local 2026111601 "
               "7200 900 1209600 300")
    parked.add("parked-demo.local", TYPE_NS, "ns1.parked-demo.local")
    parked.add("parked-demo.local", TYPE_NS, "ns2.parked-demo.local")
    parked.add("parked-demo.local", TYPE_A, "192.0.2.10")
    parked.add("parked-demo.local", TYPE_TXT, "v=spf1 -all")
    parked.add("_dmarc", TYPE_TXT,
               "v=DMARC1; p=reject; rua=mailto:dmarc@parked-demo.local")
    parked.add("ns1", TYPE_A, "192.0.2.53")
    parked.add("ns2", TYPE_A, "192.0.2.54")
    parked.wildcard = "192.0.2.1"                            # planted: catch-all
    t.zones["parked-demo.local"] = parked
    return t


EXPECTED = {
    "vuln-demo.local": {"AXFR", "SPF-PERMISSIVE", "DMARC-MISSING",
                        "TAKEOVER", "DNS-TUNNEL", "INTERNAL-LEAK",
                        "NO-DNSSEC"},
    "clean-demo.local": set(),
    "parked-demo.local": {"WILDCARD"},
}


def run_demo(json_out=None) -> int:
    client = MockDnsClient(build_demo_zones())
    print(f"DNSHawk {__version__} — offline demo (synthetic zones, "
          "same wire-format code path as live mode)\n")
    planted, caught, fps = 0, 0, 0
    ok_all = True
    for domain, expected in EXPECTED.items():
        rep = audit(domain, client, do_axfr=True, workers=8)
        render(rep)
        print()
        tags = {f.tag for f in rep.findings}
        missing, extra = expected - tags, tags - expected
        if not missing and not extra:
            supp = f" · {rep.suppressed} wildcard probes suppressed" \
                if rep.suppressed else ""
            print(f"✔ {domain}: {len(expected)}/{len(expected)} expected "
                  f"findings{supp}\n")
        else:
            ok_all = False
            print(f"✘ {domain}: missing={sorted(missing)} "
                  f"unexpected={sorted(extra)}\n")
        planted += len(expected)
        caught += len(expected) - len(missing)
        fps += len(extra)
    verdict = "demo verified" if ok_all else "DEMO FAILED"
    print(f"{'✔' if ok_all else '✘'} {verdict}: {caught}/{planted} planted "
          f"findings · {fps} false positives")
    if json_out:
        Path_write(json_out, {"demo": [
            report_json(audit(d, MockDnsClient(build_demo_zones()),
                              do_axfr=True)) for d in EXPECTED]})
    return 0 if ok_all else 1


def Path_write(path, obj):
    from pathlib import Path as _P
    _P(path).write_text(json.dumps(obj, indent=2, ensure_ascii=False),
                        encoding="utf-8")


# --------------------------------------------------------------------------
# cli
# --------------------------------------------------------------------------

def main(argv=None) -> int:
    p = argparse.ArgumentParser(
        prog="dnshawk",
        description="DNS recon & zone hygiene auditor — raw wire format, "
                    "zero dependencies")
    p.add_argument("domain", nargs="?", help="domain to audit (or --demo)")
    p.add_argument("--resolver", default="1.1.1.1",
                   help="DNS server to query (default 1.1.1.1)")
    p.add_argument("--axfr", action="store_true",
                   help="attempt zone transfers against every NS")
    p.add_argument("--wordlist", metavar="FILE",
                   help="extra subdomain words (one per line)")
    p.add_argument("--workers", type=int, default=12,
                   help="parallel enum queries (default 12)")
    p.add_argument("--timeout", type=float, default=2.0,
                   help="per-query timeout seconds (default 2)")
    p.add_argument("--json", metavar="FILE", help="write JSON report")
    p.add_argument("--demo", action="store_true",
                   help="offline demo: synthetic zones, planted findings")
    p.add_argument("--version", action="version",
                   version=f"DNSHawk {__version__}")
    args = p.parse_args(argv)

    if args.demo:
        return run_demo(args.json)
    if not args.domain:
        p.error("a domain is required (or run --demo)")

    words = list(WORDS)
    if args.wordlist:
        from pathlib import Path
        extra = [w.strip() for w in
                 Path(args.wordlist).read_text(encoding="utf-8").splitlines()
                 if w.strip() and not w.startswith("#")]
        words += [w for w in extra if w not in words]

    client = UdpDnsClient(args.resolver, args.timeout)
    try:
        rep = audit(args.domain, client, words=words,
                    do_axfr=args.axfr, workers=args.workers)
    except DnsError as exc:
        print(f"[!] {exc}", file=sys.stderr)
        return 2
    render(rep)
    for e in rep.errors:
        print(f"[i] {e}", file=sys.stderr)
    if args.json:
        Path_write(args.json, report_json(rep))
        print(f"[+] json → {args.json}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n[!] interrupted", file=sys.stderr)
        sys.exit(130)
