#!/usr/bin/env python3
"""
dns_precheck.py - DNS pre-migration audit for onboarding a domain to
Cloudflare (L7 Application Security: WAF, Bot Management, DDoS, API Shield).

Given a domain it reports:
  * Registrar / registration data (RDAP, falls back to WHOIS port 43)
  * Parent (TLD) delegation: NS set, glue, parent NS TTL, DS (DNSSEC)
  * Authoritative name servers: reachability, AA flag, SOA serial sync
  * Record inventory by type with TTLs (apex + common hostnames)
  * Propagation of the NS set (or any record type) across public
    resolvers worldwide (1.1.1.1, 8.8.8.8, 9.9.9.9, OpenDNS, ...)
  * Cloudflare readiness findings (DNSSEC, CAA, TTLs, mail, origin
    exposure, registry locks, lame delegation, ...)
  * An HTML report with an interactive propagation map, JSON output and
    an optional BIND zone file ready for Cloudflare's DNS import.

Only dependency: dnspython (pip install dnspython).

Examples:
  python3 dns_precheck.py example.com
  python3 dns_precheck.py example.com --html report.html --json report.json
  python3 dns_precheck.py example.com --expect-ns ada.ns.cloudflare.com,bob.ns.cloudflare.com \
      --watch 120 --html live.html
  python3 dns_precheck.py example.com --record A --expect 104.21.1.1,172.67.1.1
"""

from __future__ import annotations

import argparse
import concurrent.futures as cf
import datetime as dt
import html
import ipaddress
import json
import os
import random
import re
import socket
import string
import sys
import time
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass, field

try:
    import dns.exception
    import dns.flags
    import dns.message
    import dns.name
    import dns.query
    import dns.rcode
    import dns.rdatatype
except ImportError:  # pragma: no cover
    sys.exit("dnspython is required:  pip install dnspython")

VERSION = "1.0.0"

# --------------------------------------------------------------------------
# Reference data
# --------------------------------------------------------------------------

# Public resolvers used for the propagation check. Most are anycast: the
# coordinates are the operator's home location, used to place the marker on
# the map; the answer you get comes from the PoP closest to *you*. Add your
# own (ISP, corporate, regional) resolvers with --resolver.
PUBLIC_RESOLVERS = [
    # name, ip (None = DoH only), city, country, lat, lon, doh url
    ("Cloudflare", "1.1.1.1", "San Francisco", "US", 37.77, -122.42, "https://cloudflare-dns.com/dns-query"),
    ("Cloudflare (2nd)", "1.0.0.1", "San Francisco", "US", 37.70, -122.30, "https://cloudflare-dns.com/dns-query"),
    ("Google", "8.8.8.8", "Mountain View", "US", 37.42, -122.08, "https://dns.google/dns-query"),
    ("Google (2nd)", "8.8.4.4", "Mountain View", "US", 37.35, -121.95, "https://dns.google/dns-query"),
    ("Quad9", "9.9.9.9", "Zurich", "CH", 47.37, 8.54, "https://dns.quad9.net/dns-query"),
    ("OpenDNS (Cisco)", "208.67.222.222", "San Jose", "US", 37.34, -121.89, "https://doh.opendns.com/dns-query"),
    ("Level3 / Lumen", "4.2.2.2", "Denver", "US", 39.74, -104.99, None),
    ("Comodo Secure DNS", "8.26.56.26", "Clifton NJ", "US", 40.86, -74.16, None),
    ("UltraDNS (Vercara)", "64.6.64.6", "Reston VA", "US", 38.96, -77.36, None),
    ("Hurricane Electric", "74.82.42.42", "Fremont", "US", 37.55, -121.99, None),
    ("Control D", "76.76.2.0", "Toronto", "CA", 43.65, -79.38, "https://freedns.controld.com/p0"),
    ("CIRA Canadian Shield", "149.112.121.10", "Ottawa", "CA", 45.42, -75.70, "https://private.canadianshield.cira.ca/dns-query"),
    ("AdGuard DNS", "94.140.14.140", "Limassol", "CY", 34.68, 33.04, "https://unfiltered.adguard-dns.com/dns-query"),
    ("DNS4EU (unfiltered)", "86.54.11.100", "Brno", "CZ", 49.19, 16.61, "https://unfiltered.joindns4.eu/dns-query"),
    ("FDN", "80.67.169.12", "Paris", "FR", 48.86, 2.35, None),
    ("DNS.WATCH", "84.200.69.80", "Frankfurt", "DE", 50.11, 8.68, None),
    ("Gcore", "95.85.95.85", "Luxembourg", "LU", 49.61, 6.13, None),
    ("Mullvad", None, "Stockholm", "SE", 59.33, 18.07, "https://dns.mullvad.net/dns-query"),
    ("Yandex", "77.88.8.8", "Moscow", "RU", 55.75, 37.62, None),
    ("Alibaba AliDNS", "223.5.5.5", "Hangzhou", "CN", 30.27, 120.15, "https://dns.alidns.com/dns-query"),
    ("114DNS", "114.114.114.114", "Nanjing", "CN", 32.06, 118.80, None),
    ("DNSPod (Tencent)", "119.29.29.29", "Shenzhen", "CN", 22.54, 114.06, "https://doh.pub/dns-query"),
    ("Quad101 (TWNIC)", "101.101.101.101", "Taipei", "TW", 25.03, 121.56, "https://dns.twnic.tw/dns-query"),
    ("KT", "168.126.63.1", "Seoul", "KR", 37.57, 126.98, None),
    ("IIJ Public DNS", None, "Tokyo", "JP", 35.68, 139.69, "https://public.dns.iij.jp/dns-query"),
]

# Resolvers used for internal recursive lookups (resolving NS host names etc.)
BOOTSTRAP = [("Cloudflare", "1.1.1.1", "https://cloudflare-dns.com/dns-query"),
             ("Google", "8.8.8.8", "https://dns.google/dns-query"),
             ("Quad9", "9.9.9.9", "https://dns.quad9.net/dns-query")]

APEX_TYPES = ["SOA", "NS", "A", "AAAA", "CNAME", "MX", "TXT", "CAA",
              "HTTPS", "SVCB", "DNSKEY", "DS"]

COMMON_HOSTS = [
    "www", "api", "app", "admin", "portal", "login", "auth", "sso", "m",
    "mail", "webmail", "smtp", "imap", "pop", "mx", "autodiscover",
    "autoconfig", "ftp", "sftp", "vpn", "remote", "cdn", "static",
    "assets", "media", "img", "blog", "shop", "store", "dev", "staging",
    "test", "uat", "beta", "origin", "direct", "cpanel", "whm", "ns1", "ns2",
]
# (name, rdtype) pairs for service/verification records
SPECIAL_RECORDS = [
    ("_dmarc", "TXT"), ("_mta-sts", "TXT"), ("_smtp._tls", "TXT"),
    ("_bimi", "TXT"), ("default._bimi", "TXT"),
    ("google._domainkey", "TXT"), ("selector1._domainkey", "CNAME"),
    ("selector2._domainkey", "CNAME"), ("default._domainkey", "TXT"),
    ("k1._domainkey", "TXT"), ("s1._domainkey", "CNAME"), ("s2._domainkey", "CNAME"),
    ("_autodiscover._tcp", "SRV"), ("_sip._tls", "SRV"),
    ("_sipfederationtls._tcp", "SRV"), ("_xmpp-client._tcp", "SRV"),
    ("_caldavs._tcp", "SRV"), ("_carddavs._tcp", "SRV"),
    ("_acme-challenge", "TXT"), ("_cf-custom-hostname", "TXT"),
]

NS_PROVIDERS = [
    ("ns.cloudflare.com", "Cloudflare"), ("awsdns", "AWS Route 53"),
    ("azure-dns", "Azure DNS"), ("googledomains.com", "Google Cloud DNS"),
    ("google.com", "Google"), ("domaincontrol.com", "GoDaddy"),
    ("registrar-servers.com", "Namecheap"), ("ovh.net", "OVHcloud"),
    ("akam.net", "Akamai Edge DNS"), ("ultradns", "UltraDNS / Vercara"),
    ("nsone.net", "NS1 (IBM)"), ("dynect.net", "Oracle Dyn"),
    ("dnsimple", "DNSimple"), ("gandi.net", "Gandi"), ("name.com", "Name.com"),
    ("hetzner", "Hetzner"), ("digitalocean.com", "DigitalOcean"),
    ("linode.com", "Akamai/Linode"), ("vercel-dns.com", "Vercel"),
    ("nsone", "NS1"), ("wixdns.net", "Wix"), ("squarespacedns", "Squarespace"),
    ("hostinger", "Hostinger"), ("ionos", "IONOS"), ("ui-dns", "IONOS"),
    ("bluehost", "Bluehost"), ("hostgator", "HostGator"), ("easydns", "easyDNS"),
    ("dnsmadeeasy", "DNS Made Easy"), ("he.net", "Hurricane Electric"),
    ("netlify", "Netlify"), ("oraclecloud", "Oracle Cloud"),
    ("alidns", "Alibaba Cloud"), ("dnspod", "DNSPod"), ("genious.net", "Genious"),
]

# https://www.cloudflare.com/ips/ (fetched at runtime when reachable)
CF_IPV4 = ["173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22",
           "103.31.4.0/22", "141.101.64.0/18", "108.162.192.0/18",
           "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22",
           "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
           "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22"]
CF_IPV6 = ["2400:cb00::/32", "2606:4700::/32", "2803:f800::/32",
           "2405:b500::/32", "2405:8100::/32", "2a06:98c0::/29",
           "2c0f:f248::/32"]

# CAs Cloudflare uses for Universal / Advanced certificates
CF_CAS = {"letsencrypt.org", "pki.goog", "ssl.com", "digicert.com",
          "sectigo.com", "comodoca.com"}

# EPP statuses that block a name-server change at the registry
BLOCKING_STATUS = {"serverupdateprohibited", "clientupdateprohibited",
                   "pendingdelete", "redemptionperiod", "serverhold", "clienthold"}

# --------------------------------------------------------------------------
# Terminal helpers
# --------------------------------------------------------------------------

USE_COLOR = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None
ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")
COLORS = {"red": "31", "green": "32", "yellow": "33", "blue": "34",
          "magenta": "35", "cyan": "36", "grey": "90", "bold": "1"}


def c(text, color):
    if not USE_COLOR:
        return str(text)
    return f"\x1b[{COLORS[color]}m{text}\x1b[0m"


def vlen(s):
    return len(ANSI_RE.sub("", str(s)))


def table(headers, rows, max_col=60):
    rows = [[str(x) for x in r] for r in rows]

    def clip(s):
        plain = ANSI_RE.sub("", s)
        if len(plain) <= max_col:
            return s
        return plain[: max_col - 1] + "…"

    rows = [[clip(x) for x in r] for r in rows]
    widths = [vlen(h) for h in headers]
    for r in rows:
        for i, x in enumerate(r):
            widths[i] = max(widths[i], vlen(x))
    sep = "  "
    out = [sep.join(c(h.ljust(widths[i]), "bold") for i, h in enumerate(headers)),
           sep.join("─" * w for w in widths)]
    for r in rows:
        out.append(sep.join(x + " " * (widths[i] - vlen(x)) for i, x in enumerate(r)))
    return "\n".join(out)


def section(title):
    bar = "═" * max(10, 78 - len(title) - 4)
    print("\n" + c(f"══ {title} {bar}", "cyan"))


def human_ttl(sec):
    if sec is None:
        return "-"
    sec = int(sec)
    for unit, n in (("d", 86400), ("h", 3600), ("m", 60)):
        if sec >= n and sec % n == 0:
            return f"{sec // n}{unit}"
    if sec >= 3600:
        return f"{sec / 3600:.1f}h"
    if sec >= 60:
        return f"{sec // 60}m{sec % 60}s"
    return f"{sec}s"


# --------------------------------------------------------------------------
# DNS transport
# --------------------------------------------------------------------------

@dataclass
class DNSResult:
    server: str
    qname: str
    rdtype: str
    rcode: str = "TIMEOUT"
    ok: bool = False
    aa: bool = False
    ad: bool = False
    rtt_ms: float | None = None
    transport: str = ""
    answer: list = field(default_factory=list)       # [(name, type, ttl, value)]
    authority: list = field(default_factory=list)
    additional: list = field(default_factory=list)
    error: str = ""


def _rrsets(section):
    out = []
    for rrset in section:
        for rd in rrset:
            out.append((rrset.name.to_text().lower(),
                        dns.rdatatype.to_text(rrset.rdtype), rrset.ttl, rd.to_text()))
    return out


def _build_query(qname, rdtype, recursive, dnssec, cd):
    q = dns.message.make_query(qname, rdtype, want_dnssec=dnssec, use_edns=0, payload=1232)
    if not recursive:
        q.flags &= ~dns.flags.RD
    if cd:
        q.flags |= dns.flags.CD
    return q


def _doh(q, url, timeout):
    req = urllib.request.Request(url, data=q.to_wire(), method="POST", headers={
        "Content-Type": "application/dns-message",
        "Accept": "application/dns-message",
        "User-Agent": f"dns-precheck/{VERSION}"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return dns.message.from_wire(resp.read())


def query(server, qname, rdtype, *, recursive=True, dnssec=False, cd=False,
          timeout=3.0, doh=None, transport="auto"):
    """Send one DNS query. server = IPv4/IPv6 or None (DoH only)."""
    res = DNSResult(server=server or doh or "", qname=qname, rdtype=rdtype)
    q = _build_query(qname, rdtype, recursive, dnssec, cd)
    attempts = []
    if transport in ("auto", "udp") and server:
        attempts.append("udp")
    if transport in ("auto", "doh") and doh:
        attempts.append("doh")
    if not attempts:
        res.rcode, res.error = "N/A", "no usable transport"
        return res
    for how in attempts:
        t0 = time.perf_counter()
        try:
            if how == "udp":
                r, tcp = dns.query.udp_with_fallback(q, server, timeout=timeout)
                res.transport = "tcp" if tcp else "udp"
            else:
                r = _doh(q, doh, timeout)
                res.transport = "doh"
            res.rtt_ms = round((time.perf_counter() - t0) * 1000, 1)
            res.rcode = dns.rcode.to_text(r.rcode())
            res.ok = r.rcode() in (dns.rcode.NOERROR, dns.rcode.NXDOMAIN)
            res.aa = bool(r.flags & dns.flags.AA)
            res.ad = bool(r.flags & dns.flags.AD)
            res.answer = _rrsets(r.answer)
            res.authority = _rrsets(r.authority)
            res.additional = _rrsets(r.additional)
            res.error = ""
            return res
        except (dns.exception.Timeout, socket.timeout, TimeoutError):
            res.rcode, res.error = "TIMEOUT", f"{how}: timeout"
        except Exception as e:  # any transport failure (bad DoH reply, proxy, reset) is just a failed probe
            res.rcode, res.error = "ERROR", f"{how}: {type(e).__name__} {e}".strip()
    return res


class Recursor:
    """Small helper that asks bootstrap resolvers (with fallback) and caches."""

    def __init__(self, timeout, transport):
        self.timeout, self.transport, self.cache = timeout, transport, {}

    def lookup(self, qname, rdtype, cd=False, dnssec=False):
        key = (qname.lower(), rdtype, cd, dnssec)
        if key in self.cache:
            return self.cache[key]
        last = None
        for _, ip, doh in BOOTSTRAP:
            r = query(ip, qname, rdtype, timeout=self.timeout, doh=doh,
                      transport=self.transport, cd=cd, dnssec=dnssec)
            last = r
            if r.ok or r.rcode == "SERVFAIL":  # SERVFAIL is a real answer (e.g. DNSSEC)
                break
        self.cache[key] = last
        return last

    def values(self, qname, rdtype):
        r = self.lookup(qname, rdtype)
        want = qname.lower().rstrip(".") + "."
        return [v for n, t, _, v in r.answer if t == rdtype and n == want]

    def addresses(self, host):
        return self.values(host, "A"), self.values(host, "AAAA")


def norm(name):
    return name.lower().rstrip(".") + "."


# --------------------------------------------------------------------------
# Registrar: RDAP with WHOIS fallback
# --------------------------------------------------------------------------

def http_json(url, timeout):
    req = urllib.request.Request(url, headers={
        "Accept": "application/rdap+json, application/json",
        "User-Agent": f"dns-precheck/{VERSION}"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8", "replace"))


def rdap_lookup(domain, timeout):
    tld = domain.rsplit(".", 1)[-1]
    urls = []
    try:
        boot = http_json("https://data.iana.org/rdap/dns.json", timeout)
        for tlds, bases in boot.get("services", []):
            if tld in tlds:
                urls += [b.rstrip("/") + "/domain/" + domain for b in bases]
    except Exception:
        pass
    urls.append("https://rdap.org/domain/" + domain)
    for url in urls:
        try:
            data = http_json(url, timeout)
        except Exception:
            continue
        # follow the registrar's RDAP server (thin registries like .com)
        for link in data.get("links", []):
            if link.get("rel") == "related" and "rdap" in link.get("type", "") + link.get("href", ""):
                try:
                    data = {**data, "_registrar_rdap": http_json(link["href"], timeout)}
                except Exception:
                    pass
                break
        return parse_rdap(data, url)
    return None


def _vcard_fn(entity):
    for item in (entity.get("vcardArray") or [None, []])[1]:
        if item and item[0] == "fn":
            return item[3]
    return None


def parse_rdap(d, src):
    info = {"source": "RDAP " + src, "registrar": None, "iana_id": None,
            "abuse_email": None, "created": None, "expires": None,
            "updated": None, "status": d.get("status", []),
            "nameservers": [n.get("ldhName", "").lower() for n in d.get("nameservers", [])],
            "dnssec": None, "ds": []}

    def walk(entities):
        for e in entities or []:
            roles = e.get("roles", [])
            if "registrar" in roles:
                info["registrar"] = info["registrar"] or _vcard_fn(e)
                for pid in e.get("publicIds", []):
                    if "IANA" in pid.get("type", ""):
                        info["iana_id"] = pid.get("identifier")
            if "abuse" in roles:
                for item in (e.get("vcardArray") or [None, []])[1]:
                    if item and item[0] == "email":
                        info["abuse_email"] = item[3]
            walk(e.get("entities"))

    walk(d.get("entities"))
    for ev in d.get("events", []):
        a, when = ev.get("eventAction"), ev.get("eventDate")
        if a == "registration":
            info["created"] = when
        elif a == "expiration":
            info["expires"] = when
        elif a == "last changed":
            info["updated"] = when
    sec = d.get("secureDNS") or {}
    info["dnssec"] = sec.get("delegationSigned")
    for ds in sec.get("dsData", []):
        info["ds"].append(f'{ds.get("keyTag")} {ds.get("algorithm")} {ds.get("digestType")} {ds.get("digest")}')
    reg = d.get("_registrar_rdap")
    if reg and not info["expires"]:
        for ev in reg.get("events", []):
            if ev.get("eventAction") == "expiration":
                info["expires"] = ev.get("eventDate")
    return info


# Used when whois.iana.org cannot be reached
WHOIS_SERVERS = {
    "com": "whois.verisign-grs.com", "net": "whois.verisign-grs.com", "org": "whois.publicinterestregistry.org",
    "info": "whois.nic.info", "biz": "whois.nic.biz", "io": "whois.nic.io", "co": "whois.nic.co",
    "me": "whois.nic.me", "ai": "whois.nic.ai", "xyz": "whois.nic.xyz", "app": "whois.nic.google",
    "dev": "whois.nic.google", "ma": "whois.registre.ma", "fr": "whois.nic.fr", "be": "whois.dns.be",
    "de": "whois.denic.de", "uk": "whois.nic.uk", "eu": "whois.eu", "nl": "whois.domain-registry.nl",
    "es": "whois.nic.es", "it": "whois.nic.it", "ch": "whois.nic.ch", "ca": "whois.cira.ca",
    "us": "whois.nic.us", "tn": "whois.ati.tn", "dz": "whois.nic.dz", "ae": "whois.aeda.net.ae",
    "sa": "whois.nic.net.sa", "qa": "whois.registry.qa", "za": "whois.registry.net.za",
}
# Servers that need a special query syntax
WHOIS_QUERY = {"whois.verisign-grs.com": "domain {d}", "whois.denic.de": "-T dn,ace {d}", "whois.jprs.jp": "{d}/e"}

# canonical field -> accepted WHOIS labels (normalized: lowercase, alnum + single spaces)
WHOIS_FIELDS = {
    "domain": ["domain name", "domain", "nom de domaine"],
    "registry_domain_id": ["registry domain id", "roid", "domain id"],
    "registrar": ["registrar", "sponsoring registrar", "registrar name", "registrar organization",
                  "registrar organisation", "sponsoring registrar organization", "registrar organization name"],
    "registrar_iana_id": ["registrar iana id", "sponsoring registrar iana id"],
    "registrar_whois_server": ["registrar whois server", "whois server", "registrar whois"],
    "registrar_url": ["registrar url", "referral url", "registrar website", "registrar web"],
    "abuse_email": ["registrar abuse contact email", "abuse contact email", "abuse email", "abuse mailbox"],
    "abuse_phone": ["registrar abuse contact phone", "abuse contact phone"],
    "created": ["creation date", "created", "created date", "created on", "registered on", "registration date",
                "registration time", "domain registration date", "registered", "date de creation"],
    "updated": ["updated date", "last updated", "last update", "changed", "last modified", "updated",
                "modified", "last updated date", "date de modification"],
    "expires": ["registry expiry date", "registrar registration expiration date", "expiration date", "expiry date",
                "expires", "expire", "expires on", "paid till", "renewal date", "expiration time",
                "date d expiration"],
    "status": ["domain status", "status", "state", "statut"],
    "nameservers": ["name server", "name servers", "nameserver", "nameservers", "nserver", "dns", "host name"],
    "dnssec": ["dnssec", "signed delegation"],
    "registrant_name": ["registrant name", "registrant contact name"],
    "registrant_org": ["registrant organization", "registrant organisation", "registrant", "holder",
                       "registrant contact organisation", "titulaire"],
    "registrant_country": ["registrant country", "registrant country code", "registrant contact country"],
    "registrant_email": ["registrant email", "registrant contact email"],
    "admin_name": ["admin name", "administrative contact name", "admin contact name"],
    "admin_email": ["admin email", "administrative contact email", "admin contact email"],
    "tech_name": ["tech name", "technical contact name", "tech contact name"],
    "tech_email": ["tech email", "technical contact email", "tech contact email"],
}
WHOIS_MULTI = {"status", "nameservers"}
WHOIS_NOT_FOUND = re.compile(r"no match|not found|no entries found|no data found|domain not found|"
                             r"status:\s*(free|available)|is available for registration", re.I)
WHOIS_RATE_LIMIT = re.compile(r"limit exceeded|too many (requests|queries)|try again later|quota", re.I)


def whois_raw(server, q, timeout):
    q = WHOIS_QUERY.get(server.lower(), "{d}").format(d=q)
    with socket.create_connection((server, 43), timeout=timeout) as s:
        s.settimeout(timeout)
        s.sendall((q + "\r\n").encode("utf-8"))
        chunks = []
        while True:
            b = s.recv(8192)
            if not b:
                break
            chunks.append(b)
    raw = b"".join(chunks)
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("latin-1")


def _wkey(k):
    return re.sub(r"\s+", " ", re.sub(r"[^a-z0-9]+", " ", k.lower())).strip()


def parse_whois(text):
    """Generic WHOIS parser: 'Key: value', 'Key....: value' and indented
    multi-line blocks ('Name servers:' followed by indented values)."""
    pairs, last_key = [], None
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith(("%", "#", ">>>", "NOTICE", "TERMS OF USE")):
            last_key = None if not line.strip() else last_key
            continue
        m = re.match(r"^\s*([^:\[\]]{1,60}?)\s*\.*\s*:\s*(.*)$", line)
        if m and not re.match(r"^\s*https?$", m.group(1), re.I):
            key, val = _wkey(m.group(1)), m.group(2).strip()
            if val:
                pairs.append((key, val))
                last_key = None
            else:
                last_key = key
        elif last_key and line.startswith((" ", "\t")):
            pairs.append((last_key, line.strip()))
    fields = {}
    for canon, labels in WHOIS_FIELDS.items():
        for label in labels:
            vals = [v for k, v in pairs if k == label]
            if vals:
                fields[canon] = vals if canon in WHOIS_MULTI else vals[0]
                break
    if "nameservers" in fields:
        fields["nameservers"] = sorted({v.split()[0].lower().rstrip(".") for v in fields["nameservers"]})
    if "status" in fields:
        fields["status"] = list(dict.fromkeys(v.split()[0] for v in fields["status"]))
    return fields, pairs


def whois_lookup(domain, timeout, server=None):
    tld = domain.rsplit(".", 1)[-1]
    out = {"servers": [], "raw": {}, "fields": {}, "all_fields": [], "error": None, "not_found": False}
    if not server:
        try:
            m = re.search(r"^(?:refer|whois):\s*(\S+)", whois_raw("whois.iana.org", tld, timeout), re.M | re.I)
            server = m.group(1) if m else None
        except Exception:
            server = None
        server = server or WHOIS_SERVERS.get(tld)
    texts = []
    seen = set()
    hop = server
    while hop and hop.lower() not in seen and len(seen) < 3:
        seen.add(hop.lower())
        try:
            text = whois_raw(hop, domain, timeout)
        except Exception as e:
            out["error"] = f"{hop}: {type(e).__name__} {e}"
            break
        out["servers"].append(hop)
        out["raw"][hop] = text
        texts.append(text)
        m = re.search(r"^\s*(?:Registrar WHOIS Server|ReferralServer|Whois Server)\s*:\s*(?:whois://|rwhois://)?([\w.-]+)",
                      text, re.M | re.I)
        hop = m.group(1) if m and "." in m.group(1) else None
    if not texts:  # port 43 blocked or no server: try the system whois client
        import shutil
        import subprocess
        if shutil.which("whois"):
            try:
                text = subprocess.run(["whois", domain], capture_output=True, text=True,
                                      timeout=timeout * 6).stdout
                if text.strip():
                    out["servers"].append("system whois")
                    out["raw"]["system whois"] = text
                    texts.append(text)
                    out["error"] = None
            except Exception as e:
                out["error"] = f"system whois: {e}"
    if not texts:
        out["error"] = out["error"] or "no WHOIS server found"
        return out
    merged, allp = {}, []
    for t in texts:  # registry first, registrar answers fill the gaps
        f, p = parse_whois(t)
        allp += p
        for k, v in f.items():
            merged.setdefault(k, v)
    out["fields"], out["all_fields"] = merged, allp
    head = texts[0][:2000]
    out["not_found"] = bool(WHOIS_NOT_FOUND.search(head)) and not merged.get("registrar")
    if WHOIS_RATE_LIMIT.search(head) and not merged:
        out["error"] = "rate limited by WHOIS server, retry later"
    return out


def parse_date(v):
    v = (v or "").strip()
    v = re.sub(r"\s*\(.*\)$", "", v)
    try:
        when = dt.datetime.fromisoformat(v.replace("Z", "+00:00").replace(" UTC", "+00:00")[:25])
    except ValueError:
        when = None
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d", "%d/%m/%Y", "%d-%m-%Y", "%d.%m.%Y", "%Y.%m.%d",
                    "%d-%b-%Y", "%d %b %Y", "%Y/%m/%d", "%a %b %d %H:%M:%S %Z %Y", "%B %d %Y"):
            try:
                when = dt.datetime.strptime(v.split(" (")[0].strip(), fmt)
                break
            except ValueError:
                continue
    if when and when.tzinfo is None:
        when = when.replace(tzinfo=dt.timezone.utc)
    return when


def whois_to_info(w):
    """Map WHOIS fields onto the registrar summary used by the rest of the report."""
    f = w.get("fields", {})
    sec = f.get("dnssec")
    return {"source": "WHOIS " + ", ".join(w.get("servers", [])), "registrar": f.get("registrar"),
            "iana_id": f.get("registrar_iana_id"), "abuse_email": f.get("abuse_email"),
            "created": f.get("created"), "expires": f.get("expires"), "updated": f.get("updated"),
            "status": f.get("status", []), "nameservers": f.get("nameservers", []),
            "dnssec": None if not sec else bool(re.match(r"(signed|yes|true|active)", sec, re.I)), "ds": []}


# --------------------------------------------------------------------------
# Audit
# --------------------------------------------------------------------------

def provider_of(ns_host):
    h = ns_host.lower()
    for needle, name in NS_PROVIDERS:
        if needle in h:
            return name
    parts = h.rstrip(".").split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else h


def in_cloudflare(ip, nets):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(a in n for n in nets)


def load_cf_ranges(timeout):
    nets = []
    for url, fallback in (("https://www.cloudflare.com/ips-v4", CF_IPV4),
                          ("https://www.cloudflare.com/ips-v6", CF_IPV6)):
        lines = fallback
        try:
            with urllib.request.urlopen(url, timeout=timeout) as r:
                got = [l.strip() for l in r.read().decode().splitlines() if l.strip()]
                if got:
                    lines = got
        except Exception:
            pass
        nets += [ipaddress.ip_network(x) for x in lines]
    return nets


class Audit:
    def __init__(self, domain, args):
        self.domain = norm(domain)
        self.d = self.domain.rstrip(".")
        self.args = args
        self.rec = Recursor(args.timeout, args.transport)
        self.report = {"domain": self.d, "generated": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
                       "tool": f"dns_precheck {VERSION}"}
        self.findings = []
        self.auth_ips = []          # [(host, ip)]
        self.cf_nets = []

    # -- helpers ---------------------------------------------------------
    def find(self, level, title, detail):
        self.findings.append({"level": level, "title": title, "detail": detail})

    def auth_query(self, qname, rdtype, dnssec=False):
        """Query the first responsive authoritative server (non-recursive)."""
        for _, ip in self.auth_ips:
            r = query(ip, qname, rdtype, recursive=False, dnssec=dnssec,
                      timeout=self.args.timeout, transport="udp")
            if r.ok:
                return r
        # fall back to a recursive answer (e.g. port 53 blocked)
        return self.rec.lookup(qname, rdtype)

    # -- 1. registrar ----------------------------------------------------
    def registrar(self):
        t = self.args.timeout + 5
        with cf.ThreadPoolExecutor(2) as ex:
            f_rdap = ex.submit(rdap_lookup, self.d, t)
            f_who = ex.submit(whois_lookup, self.d, t, self.args.whois_server) if not self.args.no_whois else None
            rdap = f_rdap.result()
            who = f_who.result() if f_who else None
        self.report["whois"] = who
        info = rdap
        if who and who.get("fields"):
            winfo = whois_to_info(who)
            if info:  # RDAP is structured; WHOIS fills whatever RDAP lacks
                for k, v in winfo.items():
                    if k != "source" and not info.get(k) and v:
                        info[k] = v
                info["source"] += " + " + winfo["source"]
                key = lambda x: x.replace(" ", "").lower()
                have = {key(x) for x in info.get("status") or []}
                info["status"] = list(info.get("status") or []) + [x for x in winfo["status"] if key(x) not in have]
                info["nameservers"] = sorted(set(info.get("nameservers") or []) | set(winfo["nameservers"]))
            else:
                info = winfo
            wf = who["fields"]
            for k in ("registrar_whois_server", "registrar_url", "registrant_org", "registrant_country"):
                if wf.get(k):
                    info[k] = wf[k]
        self.report["registrar"] = info
        if who and who.get("not_found"):
            self.find("CRIT", "WHOIS: domain not found",
                      f"{', '.join(who['servers'])} reports no registration for {self.d}.")
        elif who and who.get("error") and not who.get("fields"):
            self.find("INFO", "WHOIS unavailable", f"{who['error']} (outbound TCP/43 may be blocked).")
        if not info:
            self.find("WARN", "Registration data unavailable",
                      "Neither RDAP nor WHOIS answered; check the registrar portal manually.")
            return
        st = {s.replace(" ", "").lower() for s in info.get("status") or []}
        blocking = st & BLOCKING_STATUS
        if blocking - {"clientupdateprohibited"}:
            self.find("CRIT", "Registry status blocks NS change",
                      f"Status {', '.join(sorted(blocking))} prevents updating name servers. "
                      "Ask the registrar/registry to remove the lock before cut-over.")
        elif blocking:
            self.find("WARN", "Registrar update lock (clientUpdateProhibited)",
                      "Name servers cannot be changed until you (or the registrar) disable the "
                      "domain lock in the registrar panel. Unlock it just before cut-over.")
        if "clienttransferprohibited" in st:
            self.find("INFO", "Transfer lock present",
                      "clientTransferProhibited is fine: NS changes do not need a transfer. "
                      "Only remove it if you also move the registration to Cloudflare Registrar.")
        exp = info.get("expires")
        if exp:
            when = parse_date(exp)
            if when:
                days = (when - dt.datetime.now(dt.timezone.utc)).days
                info["days_to_expiry"] = days
                if days < 30:
                    self.find("CRIT" if days < 7 else "WARN", "Domain expires soon",
                              f"Registration expires in {days} days ({exp}). Renew before migrating.")

    # -- 2. delegation ---------------------------------------------------
    def parent_zone(self):
        labels = self.d.split(".")
        for i in range(1, len(labels)):
            cand = ".".join(labels[i:]) + "."
            if self.rec.values(cand, "NS"):
                return cand
        return labels[-1] + "."

    def delegation(self):
        parent = self.parent_zone()
        pns = self.rec.values(parent, "NS")
        deleg = {"parent_zone": parent, "parent_servers": pns, "ns": [], "ns_ttl": None,
                 "glue": [], "ds": [], "ds_ttl": None, "queried": None}
        for host in sorted(pns):
            ips, _ = self.rec.addresses(host)
            for ip in ips[:1]:
                r = query(ip, self.domain, "NS", recursive=False, timeout=self.args.timeout, transport="udp")
                if not r.ok:
                    continue
                recs = [x for x in r.authority + r.answer if x[1] == "NS" and x[0] == self.domain]
                if not recs:
                    continue
                deleg["queried"] = f"{host.rstrip('.')} ({ip})"
                deleg["ns"] = sorted({norm(x[3]) for x in recs})
                deleg["ns_ttl"] = recs[0][2]
                deleg["glue"] = [(n, t, ttl, v) for n, t, ttl, v in r.additional if t in ("A", "AAAA")]
                ds = query(ip, self.domain, "DS", recursive=False, timeout=self.args.timeout, transport="udp")
                dsr = [x for x in ds.answer if x[1] == "DS"]
                deleg["ds"] = [x[3] for x in dsr]
                deleg["ds_ttl"] = dsr[0][2] if dsr else None
                break
            if deleg["ns"]:
                break
        if not deleg["ns"]:  # UDP/53 to TLD servers blocked -> recursive view
            deleg["queried"] = "recursive resolver (TLD servers unreachable)"
            r = self.rec.lookup(self.domain, "NS")
            recs = [x for x in r.answer if x[1] == "NS"]
            deleg["ns"] = sorted({norm(x[3]) for x in recs})
            deleg["ns_ttl"] = recs[0][2] if recs else None
            deleg["ds"] = self.rec.values(self.domain, "DS")
        if not deleg["ns"]:
            self.find("CRIT", "No delegation found",
                      f"The parent zone {parent} returns no NS for {self.d}. Is the domain registered?")
        self.report["delegation"] = deleg
        return deleg

    # -- 3. authoritative servers ---------------------------------------
    def authoritative(self, deleg):
        rows = []
        serials = set()
        for host in deleg["ns"]:
            v4, v6 = self.rec.addresses(host)
            glue4 = [v for n, t, _, v in deleg["glue"] if n == host and t == "A"]
            v4 = v4 or glue4
            row = {"host": host, "provider": provider_of(host), "ipv4": v4, "ipv6": v6,
                   "aa": None, "serial": None, "rtt_ms": None, "status": "unresolvable",
                   "child_ns": []}
            for ip in v4[:1]:
                self.auth_ips.append((host, ip))
                r = query(ip, self.domain, "SOA", recursive=False, timeout=self.args.timeout, transport="udp")
                row["rtt_ms"], row["aa"] = r.rtt_ms, r.aa
                soa = [x for x in r.answer if x[1] == "SOA"]
                if r.ok and r.aa and soa:
                    row["serial"] = int(soa[0][3].split()[2])
                    serials.add(row["serial"])
                    row["status"] = "OK"
                    nsr = query(ip, self.domain, "NS", recursive=False, timeout=self.args.timeout, transport="udp")
                    row["child_ns"] = sorted({norm(x[3]) for x in nsr.answer if x[1] == "NS"})
                elif r.ok:
                    row["status"] = "LAME (not authoritative)"
                else:
                    row["status"] = r.rcode
            rows.append(row)
        self.report["authoritative"] = rows

        lame = [r["host"] for r in rows if r["status"].startswith("LAME") or r["status"] == "REFUSED"]
        dead = [r["host"] for r in rows if r["status"] in ("TIMEOUT", "ERROR", "unresolvable")]
        if lame:
            self.find("WARN", "Lame delegation", f"{', '.join(lame)} listed at the parent but not authoritative.")
        if dead and len(dead) < len(rows):
            self.find("WARN", "Unreachable name servers", f"No answer from {', '.join(dead)}.")
        if len(serials) > 1:
            self.find("WARN", "SOA serial mismatch",
                      f"Authoritative servers disagree ({', '.join(map(str, sorted(serials)))}); "
                      "zone transfers between them are lagging. Export records from the primary.")
        child = {tuple(r["child_ns"]) for r in rows if r["child_ns"]}
        if child and any(set(cn) != set(deleg["ns"]) for cn in child):
            self.find("WARN", "Parent/child NS mismatch",
                      "NS at the registry differ from NS inside the zone: "
                      f"parent={', '.join(deleg['ns'])} child={', '.join(next(iter(child)))}")
        providers = sorted({r["provider"] for r in rows})
        self.report["dns_providers"] = providers
        if providers == ["Cloudflare"]:
            self.find("INFO", "Already delegated to Cloudflare",
                      "All NS are *.ns.cloudflare.com; the zone is already on Cloudflare.")
        if not any(r["status"] == "OK" for r in rows):
            self.find("WARN", "Authoritative servers not queried directly",
                      "Port 53 to the name servers seems blocked; the inventory below uses a "
                      "recursive resolver, so TTLs are remaining cache times, not configured values.")

    # -- 4. record inventory ---------------------------------------------
    def inventory(self):
        names = [(self.domain, t) for t in APEX_TYPES]
        hosts = list(COMMON_HOSTS) + list(self.args.subdomain or [])
        if self.args.subdomains_file:
            with open(self.args.subdomains_file) as fh:
                hosts += [l.strip() for l in fh if l.strip() and not l.startswith("#")]
        for h in dict.fromkeys(hosts):
            fq = norm(f"{h}.{self.d}")
            names += [(fq, "A"), (fq, "AAAA")]
        names += [(norm(f"{h}.{self.d}"), t) for h, t in SPECIAL_RECORDS]
        wildcard_label = "wc-" + "".join(random.choices(string.ascii_lowercase + string.digits, k=12))
        names.append((norm(f"{wildcard_label}.{self.d}"), "A"))

        def run(item):
            q, t = item
            if t == "DS":
                return item, self.rec.lookup(q, t)
            return item, self.auth_query(q, t, dnssec=(t == "DNSKEY"))

        records = {}
        with cf.ThreadPoolExecutor(self.args.workers) as ex:
            for (q, t), r in ex.map(run, names):
                for n, rt, ttl, v in r.answer:
                    if rt not in ("RRSIG", "NSEC", "NSEC3"):
                        records.setdefault((n, rt, v), ttl)
        wc_name = norm(f"{wildcard_label}.{self.d}")
        wildcard = [v for (n, t, v) in records if n == wc_name]
        records = {k: v for k, v in records.items() if k[0] != wc_name}
        inv = [{"name": n, "type": t, "ttl": ttl, "value": v}
               for (n, t, v), ttl in sorted(records.items(), key=lambda kv: (kv[0][0] != self.domain, kv[0][0], kv[0][1]))]
        # drop CNAME-chain targets that live outside the zone
        inv = [r for r in inv if r["name"] == self.domain or r["name"].endswith("." + self.domain)]
        self.report["records"] = inv
        self.report["wildcard"] = wildcard
        if self.args.axfr:
            self.report["axfr"] = self.try_axfr()
        return inv

    def try_axfr(self):
        import dns.zone
        for host, ip in self.auth_ips:
            try:
                z = dns.zone.from_xfr(dns.query.xfr(ip, self.d, timeout=self.args.timeout + 5, lifetime=30))
                lines = z.to_text(relativize=False)
                if isinstance(lines, bytes):
                    lines = lines.decode()
                self.find("WARN", "Zone transfer (AXFR) allowed",
                          f"{host.rstrip('.')} allows AXFR from the internet. Full zone captured for "
                          "migration, but restrict AXFR afterwards (information disclosure).")
                return {"server": host, "zone": lines}
            except Exception:
                continue
        return None

    # -- 5. propagation --------------------------------------------------
    def resolvers(self):
        lst = [dict(name=n, ip=ip, city=city, country=cc, lat=lat, lon=lon, doh=doh)
               for n, ip, city, cc, lat, lon, doh in PUBLIC_RESOLVERS]
        for spec in self.args.resolver or []:
            p = [x.strip() for x in spec.split(",")]
            try:
                lst.append(dict(name=p[0], ip=p[1], city=p[2] if len(p) > 2 else "custom",
                                country=p[3] if len(p) > 3 else "", lat=float(p[4]) if len(p) > 4 else 0.0,
                                lon=float(p[5]) if len(p) > 5 else 0.0, doh=None))
            except (IndexError, ValueError):
                sys.exit(f"bad --resolver '{spec}', expected Name,IP[,City,CC,lat,lon]")
        if self.args.only_resolvers:
            keep = [s.lower() for s in self.args.only_resolvers.split(",")]
            lst = [r for r in lst if any(k in r["name"].lower() or k == r["ip"] for k in keep)]
        return lst

    def reference(self, rtype):
        if self.args.expect:
            vals = [x.strip() for x in self.args.expect.split(",") if x.strip()]
            return {norm(v) if rtype in ("NS", "CNAME", "MX") else v.lower() for v in vals}, "expected (--expect)"
        if rtype == "NS":
            return set(self.report["delegation"]["ns"]), "registry delegation"
        r = self.auth_query(self.domain if not self.args.name else norm(self.args.name), rtype)
        return {self._canon(rtype, x[3]) for x in r.answer if x[1] == rtype}, "authoritative answer"

    @staticmethod
    def _canon(rtype, v):
        v = v.lower()
        if rtype in ("NS", "CNAME", "PTR"):
            return norm(v)
        if rtype == "MX":
            pref, host = v.split(None, 1)
            return f"{pref} {norm(host)}"
        return v

    def propagation(self):
        rtype = self.args.record.upper()
        qname = norm(self.args.name) if self.args.name else self.domain
        ref, ref_src = self.reference(rtype)
        resolvers = self.resolvers()

        def probe(rv):
            r = query(rv["ip"], qname, rtype, dnssec=True, timeout=self.args.timeout,
                      doh=rv["doh"], transport=self.args.transport)
            soa = query(rv["ip"], self.domain, "SOA", timeout=self.args.timeout,
                        doh=rv["doh"], transport=self.args.transport)
            vals = {self._canon(rtype, x[3]) for x in r.answer if x[1] == rtype}
            ttl = min((x[2] for x in r.answer if x[1] == rtype), default=None)
            serial = mname = None
            for x in soa.answer:
                if x[1] == "SOA":
                    parts = x[3].split()
                    mname, serial = parts[0], int(parts[2])
            if not r.ok and r.rcode != "NXDOMAIN":
                status = r.rcode
            elif r.rcode == "NXDOMAIN":
                status = "NXDOMAIN"
            elif not vals:
                status = "NO DATA"
            elif vals == ref:
                status = "MATCH"
            elif vals & ref:
                status = "PARTIAL"
            else:
                status = "STALE" if self.args.expect else "MISMATCH"
            return {**rv, "status": status, "values": sorted(vals), "ttl": ttl, "ad": r.ad,
                    "rtt_ms": r.rtt_ms, "transport": r.transport, "soa_serial": serial,
                    "soa_mname": mname, "error": r.error}

        with cf.ThreadPoolExecutor(self.args.workers) as ex:
            results = list(ex.map(probe, resolvers))
        answered = [r for r in results if r["status"] not in ("TIMEOUT", "ERROR", "N/A")]
        matched = [r for r in results if r["status"] == "MATCH"]
        pct = round(100 * len(matched) / len(answered), 1) if answered else 0.0
        eta = max((r["ttl"] or 0 for r in answered if r["status"] != "MATCH"), default=0)
        prop = {"qname": qname, "type": rtype, "reference": sorted(ref), "reference_source": ref_src,
                "results": results, "answered": len(answered), "matched": len(matched),
                "percent": pct, "max_stale_ttl": eta,
                "checked_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")}
        if self.args.expect and rtype == "NS":
            prop["registry_updated"] = set(self.report["delegation"]["ns"]) == ref
        self.report["propagation"] = prop
        return prop

    # -- 6. Cloudflare readiness ----------------------------------------
    def readiness(self):
        recs = self.report.get("records", [])
        deleg = self.report.get("delegation", {})
        by = lambda n, t: [r for r in recs if r["name"] == n and r["type"] == t]
        apex = self.domain

        # DNSSEC
        if deleg.get("ds"):
            self.find("CRIT", "DNSSEC is active (DS at registry)",
                      "Disable DNSSEC / remove the DS record at the registrar and wait for the DS TTL "
                      f"({human_ttl(deleg.get('ds_ttl'))}) BEFORE changing NS, or the domain will fail "
                      "validation (SERVFAIL on 1.1.1.1/8.8.8.8/9.9.9.9). Re-enable DNSSEC in Cloudflare "
                      "after activation and publish Cloudflare's DS. (Alternative: multi-signer DNSSEC.)")
            v = self.rec.lookup(apex, "SOA", dnssec=True)
            if v.rcode == "SERVFAIL" and self.rec.lookup(apex, "SOA", cd=True).ok:
                self.find("CRIT", "DNSSEC validation currently broken",
                          "Validating resolvers return SERVFAIL but answer with CD=1: DS/DNSKEY mismatch.")
        # NS TTL
        if deleg.get("ns_ttl"):
            self.find("INFO", "Parent NS TTL",
                      f"Registry NS TTL is {human_ttl(deleg['ns_ttl'])}: resolvers may keep the old "
                      "name servers that long after you switch. Keep the old DNS provider serving an "
                      "identical zone for at least this long (ideally 48-72h).")
        # Record TTLs
        high = [r for r in recs if r["type"] in ("A", "AAAA", "CNAME", "MX", "TXT") and r["ttl"] and r["ttl"] > 3600]
        if high:
            ex = ", ".join(sorted({f"{r['name'].rstrip('.')} {r['type']} {human_ttl(r['ttl'])}" for r in high})[:6])
            self.find("WARN", "High TTLs on records",
                      f"{len(high)} record(s) above 1h ({ex}...). Lower to 300s at the current provider "
                      "at least one old-TTL period before cut-over so rollback is fast.")
        # Apex CNAME
        if by(apex, "CNAME"):
            self.find("WARN", "CNAME at zone apex",
                      "Apex CNAME is non-standard; Cloudflare will apply CNAME flattening. Verify target.")
        # CAA
        caa = by(apex, "CAA")
        if caa:
            issuers = {re.sub(r'^\d+\s+issue(wild)?\s+"?([^";]*).*$', r"\2", r["value"]).strip().lower()
                       for r in caa if " issue" in r["value"]}
            missing = sorted(CF_CAS - issuers - {"comodoca.com", "sectigo.com"})
            self.find("WARN" if missing else "INFO", "CAA records present",
                      f"Current CAs: {', '.join(sorted(issuers)) or '-'}. Cloudflare auto-adds CAA for its "
                      "Universal SSL CAs when Universal SSL is on; if you use Advanced/Custom certs make sure "
                      f"the chosen CA is authorized ({', '.join(missing)} not listed today).")
        # Email
        mx = by(apex, "MX")
        txt = [r["value"] for r in by(apex, "TXT")]
        mail_hosts = set()
        if mx:
            mail_hosts = {norm(r["value"].split()[-1]) for r in mx}
            inzone = sorted(h.rstrip(".") for h in mail_hosts if h.endswith("." + apex) or h == apex)
            self.find("INFO", "Mail records found",
                      f"{len(mx)} MX record(s). Copy MX/SPF/DKIM/DMARC exactly and keep "
                      + (f"{', '.join(inzone)} as DNS-only (grey cloud): " if inzone else "mail hosts ")
                      + "Cloudflare does not proxy SMTP/IMAP.")
            if not any(t.strip('"').lower().startswith("v=spf1") for t in txt):
                self.find("WARN", "No SPF record", "MX exists but no v=spf1 TXT at the apex.")
            if not by(norm("_dmarc." + self.d), "TXT"):
                self.find("WARN", "No DMARC record", "No _dmarc TXT record found.")
        # Origin exposure
        web = {r["value"] for r in recs if r["name"] in (apex, norm("www." + self.d)) and r["type"] in ("A", "AAAA")}
        non_http = ("mail", "smtp", "imap", "pop", "mx", "ftp", "sftp", "cpanel", "whm", "direct", "origin",
                    "webmail", "vpn", "remote", "ns1", "ns2")
        leaks = sorted({r["name"].rstrip(".") for r in recs if r["type"] in ("A", "AAAA") and r["value"] in web
                        and r["name"].split(".")[0] in non_http})
        leaks = sorted(set(leaks) | {r["name"].rstrip(".") for r in recs if r["type"] in ("A", "AAAA")
                                     and r["name"] in mail_hosts and r["value"] in web})
        if leaks:
            self.find("WARN", "Origin IP exposed by non-proxiable hostnames",
                      f"{', '.join(leaks)} resolve to the same IP as the web origin. Once the site is "
                      "proxied these still reveal the origin and allow WAF bypass. Move them to a different IP.")
        cf_hits = sorted({r["value"] for r in recs if r["type"] in ("A", "AAAA") and in_cloudflare(r["value"], self.cf_nets)})
        if web and not (web & set(cf_hits)):
            self.find("INFO", "Origin hardening after cut-over",
                      f"Web origin ({', '.join(sorted(web))}) is public today and stays in DNS history. "
                      "After proxying: allow-list only Cloudflare IP ranges on the origin firewall, enable "
                      "Authenticated Origin Pulls (mTLS) or use Cloudflare Tunnel, and consider rotating the origin IP.")
        if cf_hits:
            self.find("INFO", "Records already on Cloudflare IPs", ", ".join(cf_hits))
        if self.report.get("wildcard"):
            self.find("INFO", "Wildcard DNS detected",
                      f"Random labels resolve ({', '.join(self.report['wildcard'])}). Recreate the wildcard in "
                      "Cloudflare; it can be proxied. Enumeration of subdomains is unreliable with wildcards.")
        verif = [t for t in txt if re.match(r'"?(google-site-verification|ms=|facebook-domain|atlassian|'
                                            r'apple-domain|docusign|globalsign|_?[a-z0-9-]*verification)', t, re.I)]
        if verif:
            self.find("INFO", "Verification TXT records", f"{len(verif)} SaaS verification record(s) must be copied.")
        if self.d.count(".") > 1 and not re.search(r"\.(co|com|org|net|gov|ac|edu)\.[a-z]{2}$", self.d):
            self.find("INFO", "Subdomain input",
                      "Cloudflare full setup works on the registrable domain; a subdomain zone requires "
                      "Enterprise (subdomain setup) or a CNAME/partial setup.")
        self.find("INFO", "Pre-cut-over checklist",
                  "1) Lower TTLs  2) Disable DNSSEC at registrar  3) Import zone in Cloudflare & compare "
                  "(this report's --export-bind)  4) Set proxy status per record (grey for mail/FTP/SSH)  "
                  "5) SSL/TLS mode Full (strict) with a valid origin cert  6) WAF/Managed Rules in log mode first  "
                  "7) Switch NS at registrar  8) Watch propagation (--expect-ns ... --watch 120)  "
                  "9) Re-enable DNSSEC in Cloudflare  10) Lock origin to Cloudflare IPs.")
        order = {"CRIT": 0, "WARN": 1, "INFO": 2}
        self.findings.sort(key=lambda f: order[f["level"]])
        self.report["findings"] = self.findings

    # -- driver ----------------------------------------------------------
    def run(self):
        self.cf_nets = load_cf_ranges(self.args.timeout)
        print(c(f"Auditing {self.d} …", "grey"), file=sys.stderr)
        self.registrar()
        deleg = self.delegation()
        self.authoritative(deleg)
        self.inventory()
        self.propagation()
        self.readiness()
        return self.report


# --------------------------------------------------------------------------
# Rendering: terminal
# --------------------------------------------------------------------------

STATUS_COLOR = {"MATCH": "green", "PARTIAL": "yellow", "STALE": "red", "MISMATCH": "red",
                "NXDOMAIN": "red", "NO DATA": "yellow", "SERVFAIL": "red", "REFUSED": "red",
                "TIMEOUT": "grey", "ERROR": "grey", "N/A": "grey"}
LEVEL_COLOR = {"CRIT": "red", "WARN": "yellow", "INFO": "blue"}


def print_report(rep, show_records=True, raw_whois=False):
    reg = rep.get("registrar")
    section("Registrar / Registration")
    if reg:
        rows = [("Registrar", f"{reg.get('registrar') or '-'}" + (f"  (IANA {reg['iana_id']})" if reg.get("iana_id") else "")),
                ("Abuse contact", reg.get("abuse_email") or "-"),
                ("Created", reg.get("created") or "-"), ("Updated", reg.get("updated") or "-"),
                ("Expires", f"{reg.get('expires') or '-'}"
                 + (f"  ({reg['days_to_expiry']} days)" if reg.get("days_to_expiry") is not None else "")),
                ("Status", ", ".join(reg.get("status") or []) or "-"),
                ("NS (registrar)", ", ".join(reg.get("nameservers") or []) or "-"),
                ("DNSSEC signed", {True: c("yes", "yellow"), False: "no", None: "-"}[reg.get("dnssec")]),
                ("Registrar WHOIS", reg.get("registrar_whois_server") or "-"),
                ("Registrar URL", reg.get("registrar_url") or "-"),
                ("Source", reg.get("source"))]
        print("  " + table(["Field", "Value"], rows, max_col=110).replace("\n", "\n  "))
    else:
        print(c("  registration data unavailable", "yellow"))
    print_whois(rep.get("whois"), raw=raw_whois)

    d = rep.get("delegation", {})
    section(f"Delegation at parent zone {d.get('parent_zone', '')}")
    print(f"  Queried : {d.get('queried')}")
    print(f"  NS TTL  : {human_ttl(d.get('ns_ttl'))}   ({d.get('ns_ttl')}s)")
    print(f"  DS      : " + (c(f"{len(d['ds'])} record(s), TTL {human_ttl(d.get('ds_ttl'))}", "yellow")
                             if d.get("ds") else "none (DNSSEC not enabled at registry)"))
    for ds in d.get("ds", []):
        print(c(f"            {ds}", "grey"))
    if d.get("glue"):
        print("  Glue    : " + ", ".join(f"{n.rstrip('.')}={v}" for n, _, _, v in d["glue"]))

    section("Authoritative name servers")
    rows = []
    for a in rep.get("authoritative", []):
        st = a["status"]
        rows.append([a["host"].rstrip("."), a["provider"], ", ".join(a["ipv4"]) or "-",
                     ", ".join(a["ipv6"]) or "-", c(st, "green" if st == "OK" else "red"),
                     a["serial"] or "-", f"{a['rtt_ms']} ms" if a["rtt_ms"] else "-"])
    print("  " + table(["Name server", "Provider", "IPv4", "IPv6", "Status", "SOA serial", "RTT"], rows).replace("\n", "\n  "))
    print(f"  Provider(s): {', '.join(rep.get('dns_providers', []))}")

    if show_records:
        recs = rep.get("records", [])
        section(f"Records by type ({len(recs)} found)")
        by_type = {}
        for r in recs:
            by_type.setdefault(r["type"], []).append(r)
        summary = ", ".join(f"{t}:{len(v)}" for t, v in sorted(by_type.items()))
        print("  " + summary + "\n")
        for t in sorted(by_type, key=lambda t: (APEX_TYPES.index(t) if t in APEX_TYPES else 99, t)):
            print(c(f"  [{t}]", "magenta"))
            rows = [[r["name"].rstrip("."), human_ttl(r["ttl"]), r["ttl"], r["value"]] for r in by_type[t]]
            print("  " + table(["Name", "TTL", "sec", "Value"], rows, max_col=90).replace("\n", "\n  "))
        if rep.get("wildcard"):
            print(c(f"\n  Wildcard: random labels resolve to {', '.join(rep['wildcard'])}", "yellow"))
        if rep.get("axfr"):
            print(c(f"\n  AXFR succeeded from {rep['axfr']['server']} (full zone in JSON/BIND export)", "yellow"))

    print_propagation(rep["propagation"])

    section("Cloudflare readiness findings")
    for f in rep.get("findings", []):
        print(f"  {c(f['level'].ljust(4), LEVEL_COLOR[f['level']])}  {c(f['title'], 'bold')}")
        print(c(f"        {f['detail']}", "grey"))


WHOIS_LABELS = [("domain", "Domain"), ("registry_domain_id", "Registry domain ID"), ("registrar", "Registrar"),
                ("registrar_iana_id", "Registrar IANA ID"), ("registrar_whois_server", "Registrar WHOIS server"),
                ("registrar_url", "Registrar URL"), ("abuse_email", "Abuse email"), ("abuse_phone", "Abuse phone"),
                ("created", "Created"), ("updated", "Updated"), ("expires", "Expires"), ("status", "Status"),
                ("nameservers", "Name servers"), ("dnssec", "DNSSEC"), ("registrant_name", "Registrant"),
                ("registrant_org", "Registrant org"), ("registrant_country", "Registrant country"),
                ("registrant_email", "Registrant email"), ("admin_name", "Admin contact"),
                ("admin_email", "Admin email"), ("tech_name", "Tech contact"), ("tech_email", "Tech email")]


def print_whois(w, raw=False):
    section("WHOIS")
    if not w:
        print(c("  skipped (--no-whois)", "grey"))
        return
    print(f"  Servers queried: {' -> '.join(w['servers']) or '-'}")
    if w.get("error"):
        print(c(f"  {w['error']}", "yellow"))
    f = w.get("fields", {})
    rows = [(label, ", ".join(f[k]) if isinstance(f[k], list) else f[k]) for k, label in WHOIS_LABELS if f.get(k)]
    if rows:
        print("  " + table(["Field", "Value"], rows, max_col=110).replace("\n", "\n  "))
    elif not w.get("error"):
        print(c("  WHOIS answered but no known fields were recognised; use --whois-raw to see the text.", "yellow"))
    if raw:
        for server, text in w.get("raw", {}).items():
            print(c(f"\n  ── raw WHOIS from {server} ──", "magenta"))
            print("  " + text.strip().replace("\n", "\n  "))
    elif w.get("raw"):
        print(c("  (full raw WHOIS text: --whois-raw, or in the HTML/JSON report)", "grey"))


def print_propagation(p):
    section(f"Propagation of {p['type']} {p['qname']}")
    print(f"  Reference ({p['reference_source']}): {', '.join(v.rstrip('.') for v in p['reference']) or '-'}")
    if "registry_updated" in p:
        print("  Registry already shows expected NS: " +
              (c("yes", "green") if p["registry_updated"] else c("NO - change not yet applied at registrar/registry", "red")))
    rows = []
    for r in sorted(p["results"], key=lambda r: (r["status"] != "MATCH", r["country"], r["name"])):
        vals = ", ".join(v.rstrip(".") for v in r["values"]) or r.get("error") or "-"
        rows.append([r["name"], f"{r['city']}, {r['country']}", r["ip"] or "DoH",
                     c(r["status"], STATUS_COLOR.get(r["status"], "grey")), vals,
                     human_ttl(r["ttl"]), r["soa_serial"] or "-", "✓" if r["ad"] else "",
                     f"{r['rtt_ms']:.0f}" if r["rtt_ms"] else "-", r["transport"] or "-"])
    print("  " + table(["Resolver", "Location", "IP", "Status", "Answer", "TTL left", "SOA serial", "AD",
                        "ms", "via"], rows, max_col=64).replace("\n", "\n  "))
    pct = p["percent"]
    width = 40
    fill = int(width * pct / 100)
    col = "green" if pct == 100 else "yellow" if pct >= 50 else "red"
    print(f"\n  Propagation  [{c('█' * fill, col)}{'░' * (width - fill)}]  {c(f'{pct}%', col)}  "
          f"({p['matched']}/{p['answered']} responding resolvers match)")
    if pct < 100 and p["max_stale_ttl"]:
        eta = dt.datetime.now() + dt.timedelta(seconds=p["max_stale_ttl"])
        print(f"  Worst-case cache expiry among non-matching resolvers: {human_ttl(p['max_stale_ttl'])} "
              f"(≈ {eta:%Y-%m-%d %H:%M} local)")
    print_ascii_map(p["results"])


def print_ascii_map(results):
    """Coarse equirectangular plot of resolver locations, one glyph per resolver."""
    W, H = 72, 18
    grid = [[" "] * W for _ in range(H)]
    # faint continents: rough boxes (lon1, lat1, lon2, lat2)
    land = [(-168, 15, -52, 72), (-82, -56, -34, 13), (-18, 35, 40, 71), (-18, -35, 52, 35),
            (40, 5, 145, 75), (95, -10, 155, 20), (112, -44, 154, -10)]
    for lon1, lat1, lon2, lat2 in land:
        for y in range(H):
            lat = 80 - y * 140 / (H - 1)
            for x in range(W):
                lon = -180 + x * 360 / (W - 1)
                if lon1 <= lon <= lon2 and lat1 <= lat <= lat2:
                    grid[y][x] = c("·", "grey")
    glyph = {"MATCH": ("●", "green"), "PARTIAL": ("◐", "yellow"), "NO DATA": ("◐", "yellow")}
    for r in results:
        x = round((r["lon"] + 180) * (W - 1) / 360)
        y = round((80 - r["lat"]) * (H - 1) / 140)
        if 0 <= x < W and 0 <= y < H:
            g, col = glyph.get(r["status"], ("○", "grey") if r["status"] in ("TIMEOUT", "ERROR", "N/A") else ("✖", "red"))
            grid[y][x] = c(g, col)
    print("\n  " + c("Propagation map", "bold") + "  (" + c("●", "green") + " match  " + c("◐", "yellow")
          + " partial  " + c("✖", "red") + " stale/mismatch  " + c("○", "grey") + " no answer)  — open --html for the interactive map")
    print("  ┌" + "─" * W + "┐")
    for row in grid:
        print("  │" + "".join(row) + "│")
    print("  └" + "─" * W + "┘")


# --------------------------------------------------------------------------
# Rendering: HTML (Leaflet map) and BIND export
# --------------------------------------------------------------------------

HTML_TEMPLATE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
__REFRESH__
<title>DNS Precheck __DOMAIN__</title>
<link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css">
<style>
:root{--bg:#f7f8fa;--card:#fff;--fg:#1d2330;--muted:#5b6475;--line:#e3e6ec;--ok:#1a9b55;--warn:#d38b00;--bad:#d23c3c;--off:#8a93a3;--info:#2f6fd6;--accent:#f38020}
@media (prefers-color-scheme:dark){:root{--bg:#11141a;--card:#1a1e26;--fg:#e6e9ef;--muted:#9aa3b2;--line:#2a303b}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.45 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
header{padding:20px 16px;border-bottom:3px solid var(--accent);background:var(--card)}
header h1{margin:0;font-size:20px}header p{margin:4px 0 0;color:var(--muted)}
main{max-width:1200px;margin:0 auto;padding:16px}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:16px;margin-bottom:16px;overflow-x:auto}
h2{font-size:16px;margin:0 0 12px}
table{border-collapse:collapse;width:100%;font-size:13px}
th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--muted);font-weight:600}td.v{font-family:ui-monospace,Menlo,Consolas,monospace;word-break:break-all}
.pill{display:inline-block;padding:1px 8px;border-radius:99px;font-size:12px;font-weight:600;color:#fff}
.MATCH{background:var(--ok)}.PARTIAL,.NODATA{background:var(--warn)}.STALE,.MISMATCH,.NXDOMAIN,.SERVFAIL,.REFUSED{background:var(--bad)}.TIMEOUT,.ERROR,.NA{background:var(--off)}
.CRIT{background:var(--bad)}.WARN{background:var(--warn)}.INFO{background:var(--info)}
#map{height:460px;border-radius:8px}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px}
.kpi{border:1px solid var(--line);border-radius:8px;padding:10px}.kpi b{display:block;font-size:22px}.kpi span{color:var(--muted);font-size:12px}
.bar{height:10px;background:var(--line);border-radius:99px;overflow:hidden}.bar i{display:block;height:100%;background:var(--ok)}
.legend span{margin-right:12px}.dot{display:inline-block;width:10px;height:10px;border-radius:50%;margin-right:4px;vertical-align:middle}
details summary{cursor:pointer;color:var(--muted)}pre{white-space:pre-wrap;font-size:12px}
</style></head><body>
<header><h1>DNS pre-migration report: __DOMAIN__</h1>
<p>Generated __GENERATED__ by __TOOL__ — target platform: Cloudflare (L7 Application Security)</p></header>
<main>
<section class="card"><h2>Summary</h2><div class="kpis" id="kpis"></div></section>
<section class="card"><h2 id="ptitle">Propagation map</h2>
<p class="legend"><span><i class="dot" style="background:var(--ok)"></i>match</span><span><i class="dot" style="background:var(--warn)"></i>partial / no data</span><span><i class="dot" style="background:var(--bad)"></i>stale / mismatch</span><span><i class="dot" style="background:var(--off)"></i>no answer</span></p>
<div class="bar"><i id="pbar"></i></div><p id="pinfo"></p>
<div id="map"></div>
<p style="color:var(--muted);font-size:12px">Most public resolvers are anycast; markers sit at the operator's home location while answers come from the PoP nearest the machine that ran this check.</p>
<table id="ptable"></table></section>
<section class="card"><h2>Cloudflare readiness findings</h2><table id="findings"></table></section>
<section class="card"><h2>Registrar</h2><table id="registrar"></table></section>
<section class="card"><h2>WHOIS</h2><p id="whoisinfo"></p><table id="whois"></table>
<details><summary>All WHOIS fields</summary><table id="whoisall"></table></details>
<details><summary>Raw WHOIS text</summary><div id="whoisraw"></div></details></section>
<section class="card"><h2>Delegation &amp; authoritative name servers</h2><table id="deleg"></table><br><table id="auth"></table></section>
<section class="card"><h2>Records by type</h2><div id="records"></div></section>
<section class="card"><details><summary>Raw JSON</summary><pre id="raw"></pre></details></section>
</main>
<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
<script>
const R = __DATA__;
const esc = s => String(s ?? '-').replace(/[&<>"]/g, ch => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[ch]));
const pill = (s, cls) => `<span class="pill ${cls || String(s).replace(/[^A-Z]/g,'')}">${esc(s)}</span>`;
const ttl = s => { if (s==null) return '-'; s=+s; if (s>=86400&&s%86400==0) return s/86400+'d'; if (s>=3600&&s%3600==0) return s/3600+'h'; if (s>=60&&s%60==0) return s/60+'m'; return s+'s'; };
const rows = (el, head, data) => { document.getElementById(el).innerHTML = '<tr>'+head.map(h=>`<th>${h}</th>`).join('')+'</tr>' + data.map(r=>'<tr>'+r.map((x,i)=>`<td${i==r.length-1?' class="v"':''}>${x}</td>`).join('')+'</tr>').join(''); };
const P = R.propagation, F = R.findings || [], D = R.delegation || {}, G = R.registrar || {};
const crit = F.filter(f=>f.level=='CRIT').length, warn = F.filter(f=>f.level=='WARN').length;
document.getElementById('kpis').innerHTML = [
  [P.percent+'%', `${P.type} propagation (${P.matched}/${P.answered})`],
  [(R.dns_providers||[]).join(', ')||'-', 'Current DNS provider'],
  [esc(G.registrar), 'Registrar'],
  [ttl(D.ns_ttl), 'Parent NS TTL'],
  [D.ds && D.ds.length ? 'ON' : 'off', 'DNSSEC (DS at registry)'],
  [(R.records||[]).length, 'Records found'],
  [crit+' / '+warn, 'Critical / warnings']].map(k=>`<div class="kpi"><b>${k[0]}</b><span>${k[1]}</span></div>`).join('');
document.getElementById('ptitle').textContent = `Propagation map — ${P.type} ${P.qname}`;
document.getElementById('pbar').style.width = P.percent+'%';
document.getElementById('pinfo').innerHTML = `Reference (${esc(P.reference_source)}): <code>${P.reference.map(esc).join(', ')}</code> — checked ${esc(P.checked_at)}` +
  (P.registry_updated===undefined ? '' : ` — registry shows expected NS: <b>${P.registry_updated?'yes':'NO'}</b>`);
const color = s => ({MATCH:'#1a9b55',PARTIAL:'#d38b00','NO DATA':'#d38b00',TIMEOUT:'#8a93a3',ERROR:'#8a93a3','N/A':'#8a93a3'})[s] || '#d23c3c';
if (window.L) {
  const map = L.map('map', {worldCopyJump:true}).setView([30, 10], 2);
  L.tileLayer('https://{s}.basemaps.cartocdn.com/rastertiles/voyager/{z}/{x}/{y}{r}.png', {maxZoom: 8, attribution: '&copy; OpenStreetMap &copy; CARTO'}).addTo(map);
  P.results.forEach(r => L.circleMarker([r.lat, r.lon], {radius: 9, color: '#fff', weight: 2, fillColor: color(r.status), fillOpacity: .95})
    .addTo(map).bindPopup(`<b>${esc(r.name)}</b> ${esc(r.ip||'DoH')}<br>${esc(r.city)}, ${esc(r.country)}<br>${pill(r.status)}<br><code>${(r.values.length?r.values:[r.error||'-']).map(esc).join('<br>')}</code><br>TTL left ${ttl(r.ttl)} · SOA ${esc(r.soa_serial)} · ${esc(r.rtt_ms)} ms ${r.ad?'· DNSSEC AD':''}`)
    .bindTooltip(`${r.name}: ${r.status}`));
} else {
  // offline fallback: equirectangular SVG plot with a lat/lon graticule
  const W = 1000, H = 460, px = lon => (lon + 180) / 360 * W, py = lat => (85 - lat) / 145 * H;
  let g = '';
  for (let lon = -180; lon <= 180; lon += 30) g += `<line x1="${px(lon)}" y1="0" x2="${px(lon)}" y2="${H}" stroke="currentColor" stroke-opacity=".12"/>`;
  for (let lat = -60; lat <= 80; lat += 20) g += `<line x1="0" y1="${py(lat)}" x2="${W}" y2="${py(lat)}" stroke="currentColor" stroke-opacity=".12"/><text x="4" y="${py(lat) - 3}" font-size="10" fill="currentColor" opacity=".5">${lat}°</text>`;
  const regions = [['North America', -100, 50], ['South America', -60, -15], ['Europe', 15, 58], ['Africa', 20, 5], ['Asia', 95, 50], ['Oceania', 135, -25]];
  regions.forEach(([n, lon, lat]) => g += `<text x="${px(lon)}" y="${py(lat)}" font-size="13" text-anchor="middle" fill="currentColor" opacity=".3">${n}</text>`);
  P.results.forEach(r => g += `<circle cx="${px(r.lon)}" cy="${py(r.lat)}" r="7" fill="${color(r.status)}" stroke="#fff" stroke-width="2"><title>${esc(r.name)} (${esc(r.city)}, ${esc(r.country)}): ${esc(r.status)} ${esc(r.values.join(', '))}</title></circle>`);
  document.getElementById('map').innerHTML = `<svg viewBox="0 0 ${W} ${H}" width="100%" height="100%" style="color:var(--fg);background:var(--bg);border-radius:8px">${g}</svg>`;
}
rows('ptable', ['Resolver','Location','IP','Status','TTL left','SOA serial','AD','ms','via','Answer'],
  [...P.results].sort((a,b)=>(a.status=='MATCH')-(b.status=='MATCH')||a.country.localeCompare(b.country)).map(r=>[esc(r.name), esc(r.city+', '+r.country), esc(r.ip||'DoH'), pill(r.status), esc(r.ttl==null?'':ttl(r.ttl)), esc(r.soa_serial), r.ad?'✓':'', esc(r.rtt_ms), esc(r.transport), (r.values.length?r.values:[r.error||'-']).map(esc).join('<br>')]));
rows('findings', ['Level','Finding','Detail'], F.map(f=>[pill(f.level), '<b>'+esc(f.title)+'</b>', esc(f.detail)]));
rows('registrar', ['Field','Value'], [['Registrar', esc(G.registrar)+(G.iana_id?` (IANA ${esc(G.iana_id)})`:'')], ['Abuse', esc(G.abuse_email)], ['Created', esc(G.created)], ['Updated', esc(G.updated)], ['Expires', esc(G.expires)+(G.days_to_expiry!=null?` (${G.days_to_expiry} days)`:'')], ['Status', esc((G.status||[]).join(', '))], ['NS at registrar', esc((G.nameservers||[]).join(', '))], ['Registrar WHOIS server', esc(G.registrar_whois_server)], ['Registrar URL', esc(G.registrar_url)], ['Registrant', esc([G.registrant_org, G.registrant_country].filter(Boolean).join(', ') || null)], ['Source', esc(G.source)]]);
const W = R.whois || {}, WF = W.fields || {};
const WL = [['domain','Domain'],['registry_domain_id','Registry domain ID'],['registrar','Registrar'],['registrar_iana_id','Registrar IANA ID'],['registrar_whois_server','Registrar WHOIS server'],['registrar_url','Registrar URL'],['abuse_email','Abuse email'],['abuse_phone','Abuse phone'],['created','Created'],['updated','Updated'],['expires','Expires'],['status','Status'],['nameservers','Name servers'],['dnssec','DNSSEC'],['registrant_name','Registrant'],['registrant_org','Registrant org'],['registrant_country','Registrant country'],['registrant_email','Registrant email'],['admin_name','Admin contact'],['admin_email','Admin email'],['tech_name','Tech contact'],['tech_email','Tech email']];
document.getElementById('whoisinfo').innerHTML = R.whois ? `Servers queried: <code>${(W.servers||[]).map(esc).join(' → ') || '-'}</code>` + (W.error ? ` — <b>${esc(W.error)}</b>` : '') : 'WHOIS skipped (--no-whois)';
rows('whois', ['Field','Value'], WL.filter(([k]) => WF[k]).map(([k, l]) => [l, Array.isArray(WF[k]) ? WF[k].map(esc).join('<br>') : esc(WF[k])]));
rows('whoisall', ['Key','Value'], (W.all_fields||[]).map(([k, v]) => [esc(k), esc(v)]));
document.getElementById('whoisraw').innerHTML = Object.entries(W.raw||{}).map(([srv, t]) => `<h3>${esc(srv)}</h3><pre>${esc(t)}</pre>`).join('') || '<p>-</p>';
rows('deleg', ['Parent zone','Queried','NS TTL','DS','NS'], [[esc(D.parent_zone), esc(D.queried), ttl(D.ns_ttl), D.ds&&D.ds.length? D.ds.map(esc).join('<br>') : 'none', (D.ns||[]).map(esc).join('<br>')]]);
rows('auth', ['Provider','IPv4','IPv6','Status','SOA serial','RTT ms','Name server'], (R.authoritative||[]).map(a=>[esc(a.provider), esc(a.ipv4.join(', ')), esc(a.ipv6.join(', ')), pill(a.status, a.status=='OK'?'MATCH':'MISMATCH'), esc(a.serial), esc(a.rtt_ms), esc(a.host)]));
const byType = {}; (R.records||[]).forEach(r => (byType[r.type] = byType[r.type] || []).push(r));
document.getElementById('records').innerHTML = Object.keys(byType).sort().map(t => `<h3>${esc(t)} <small>(${byType[t].length})</small></h3><table><tr><th>Name</th><th>TTL</th><th>Value</th></tr>` +
  byType[t].map(r=>`<tr><td>${esc(r.name)}</td><td>${ttl(r.ttl)}</td><td class="v">${esc(r.value)}</td></tr>`).join('') + '</table>').join('') || '<p>No records.</p>';
document.getElementById('raw').textContent = JSON.stringify(R, null, 2);
</script></body></html>
"""


def write_html(rep, path, refresh=None):
    data = json.dumps(rep, default=str).replace("</", "<\\/")
    out = (HTML_TEMPLATE.replace("__DATA__", data)
           .replace("__DOMAIN__", html.escape(rep["domain"]))
           .replace("__GENERATED__", html.escape(rep["generated"]))
           .replace("__TOOL__", html.escape(rep["tool"]))
           .replace("__REFRESH__", f'<meta http-equiv="refresh" content="{int(refresh)}">' if refresh else ""))
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(out)


def write_bind(rep, path):
    """BIND zone file suitable for Cloudflare 'Import DNS records'."""
    if rep.get("axfr"):
        body = rep["axfr"]["zone"]
    else:
        lines = []
        for r in rep.get("records", []):
            if r["type"] in ("SOA", "NS", "DNSKEY", "DS", "RRSIG"):
                continue  # Cloudflare manages these itself
            lines.append(f"{r['name']}\t{r['ttl']}\tIN\t{r['type']}\t{r['value']}")
        body = "\n".join(lines)
    with open(path, "w") as fh:
        fh.write(f"; {rep['domain']} exported {rep['generated']} by {rep['tool']}\n"
                 f"; Review before importing into Cloudflare (DNS > Records > Import).\n"
                 f"; Records found by probing common names only unless AXFR succeeded:\n"
                 f"; add any hostnames that are missing.\n$ORIGIN {rep['domain']}.\n{body}\n")


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def parse_args(argv=None):
    p = argparse.ArgumentParser(description="DNS pre-migration audit for Cloudflare onboarding.",
                                formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__.split("Examples:")[1])
    p.add_argument("domain", help="registrable domain, e.g. example.com")
    p.add_argument("--record", default="NS", help="record type to track for propagation (default NS)")
    p.add_argument("--name", help="host name to track for propagation (default: the domain apex)")
    p.add_argument("--expect", help="comma-separated expected values for --record (e.g. new NS or IPs)")
    p.add_argument("--expect-ns", help="shortcut for --record NS --expect ...")
    p.add_argument("--resolver", action="append", metavar="Name,IP[,City,CC,lat,lon]",
                   help="add a resolver to the propagation check (repeatable)")
    p.add_argument("--only-resolvers", help="comma-separated names/IPs to restrict the resolver list")
    p.add_argument("--subdomain", action="append", help="extra host label to inventory (repeatable)")
    p.add_argument("--subdomains-file", help="file with one host label per line to inventory")
    p.add_argument("--no-whois", action="store_true", help="skip the WHOIS lookup (RDAP only)")
    p.add_argument("--whois-server", help="query this WHOIS server instead of the one IANA refers to")
    p.add_argument("--whois-raw", action="store_true", help="print the full raw WHOIS text")
    p.add_argument("--axfr", action="store_true", help="attempt a zone transfer from the authoritative servers")
    p.add_argument("--transport", choices=["auto", "udp", "doh"], default="auto",
                   help="auto = UDP/TCP 53 then DoH fallback (default)")
    p.add_argument("--timeout", type=float, default=3.0, help="per-query timeout in seconds")
    p.add_argument("--workers", type=int, default=24, help="parallel queries")
    p.add_argument("--html", help="write HTML report with interactive propagation map")
    p.add_argument("--json", help="write full JSON report")
    p.add_argument("--export-bind", help="write discovered records as a BIND zone file for Cloudflare import")
    p.add_argument("--watch", type=int, metavar="SECONDS", help="re-check propagation every N seconds until 100%%")
    p.add_argument("--max-rounds", type=int, default=0, help="stop watch mode after N rounds (0 = until 100%%)")
    p.add_argument("--no-records", action="store_true", help="do not print the record inventory")
    p.add_argument("--no-color", action="store_true")
    p.add_argument("--version", action="version", version=VERSION)
    a = p.parse_args(argv)
    if a.expect_ns:
        a.record, a.expect = "NS", a.expect_ns
    try:
        a.domain = a.domain.strip().rstrip(".").lower().encode("idna").decode()
    except UnicodeError:
        p.error("invalid domain name")
    a.domain = re.sub(r"^https?://", "", a.domain).split("/")[0]
    if "." not in a.domain:
        p.error("domain must contain a dot")
    return a


def save(rep, args, refresh=None):
    if args.json:
        with open(args.json, "w") as fh:
            json.dump(rep, fh, indent=2, default=str)
    if args.html:
        write_html(rep, args.html, refresh)
    if args.export_bind:
        write_bind(rep, args.export_bind)


def main(argv=None):
    global USE_COLOR
    args = parse_args(argv)
    if args.no_color:
        USE_COLOR = False
    audit = Audit(args.domain, args)
    rep = audit.run()
    print_report(rep, show_records=not args.no_records, raw_whois=args.whois_raw)
    save(rep, args, refresh=args.watch)
    for label, path in (("HTML", args.html), ("JSON", args.json), ("BIND", args.export_bind)):
        if path:
            print(c(f"\n  {label} written: {os.path.abspath(path)}", "green"))

    rnd = 1
    while args.watch and rep["propagation"]["percent"] < 100 and (not args.max_rounds or rnd < args.max_rounds):
        print(c(f"\n  watching: next check in {args.watch}s (Ctrl+C to stop)", "grey"))
        try:
            time.sleep(args.watch)
        except KeyboardInterrupt:
            break
        rnd += 1
        if args.record.upper() == "NS":
            audit.delegation()  # refresh registry view
        audit.propagation()
        rep["generated"] = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
        print_propagation(rep["propagation"])
        save(rep, args, refresh=args.watch)

    return 2 if any(f["level"] == "CRIT" for f in rep["findings"]) else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
