# Cloudflare DNS pre-migration check

`dns_precheck.py` audits a domain before you move it (and its application) behind
Cloudflare L7 Application Security (WAF, Bot Management, DDoS, API Shield). It
collects the DNS facts you need for the migration and tracks name-server
propagation across public resolvers worldwide, with a map.

## Install & run

```bash
pip install -r requirements.txt        # only dependency: dnspython
python3 dns_precheck.py example.com --html report.html --json report.json --export-bind zone.txt
```

Exit code is `2` when a critical finding exists (DNSSEC still on, registry update lock,
no delegation, ...), `0` otherwise, so it can gate a CI/CD or change pipeline.

## What it reports

| Section | Details |
|---|---|
| Registrar / WHOIS | RDAP and WHOIS (registry, then the registrar's WHOIS server) are always queried and merged into one table: registrar + IANA ID, registrar WHOIS server, registrar URL, status, created/updated/expiry (days left), NS at registrar, DNSSEC, registry domain ID, registrant org/country, abuse contact. Works for gTLDs and ccTLDs such as .ma; uses the system `whois` command if TCP/43 is blocked. |
| Delegation | Parent (TLD) zone queried directly: NS set, parent NS TTL, glue, DS records + TTL. |
| Authoritative NS | Per server: provider (GoDaddy, Route 53, Azure, ...), IPv4/IPv6, AA flag (lame delegation), SOA serial sync, RTT, parent vs child NS mismatch. |
| Records by type | SOA, NS, A, AAAA, CNAME, MX, TXT, CAA, HTTPS, SVCB, DNSKEY, DS at the apex; ~40 common hosts (www, api, mail, autodiscover, ...); DMARC/DKIM/MTA-STS/BIMI/SRV records; wildcard detection. TTLs come from the authoritative servers (the configured values, not cached ones). Optional `--axfr`. |
| Propagation | 25 public resolvers (1.1.1.1, 1.0.0.1, 8.8.8.8, 8.8.4.4, 9.9.9.9, OpenDNS, Level3, Comodo, UltraDNS, Hurricane Electric, Control D, CIRA, AdGuard, DNS4EU, FDN, DNS.WATCH, Gcore, Mullvad, Yandex, AliDNS, 114DNS, DNSPod, Quad101, KT, IIJ) + your own. Per resolver: status, answer, remaining cache TTL, SOA serial, DNSSEC AD bit, latency, transport. Shows %, ETA for stale caches, a terminal map and an interactive HTML map. |
| Cloudflare readiness | DNSSEC/DS handling, registry locks, expiry, parent NS TTL, high record TTLs, apex CNAME, CAA vs Cloudflare CAs, MX/SPF/DMARC and grey-cloud hosts, origin-IP exposure via mail/ftp/cpanel hosts, verification TXT records, wildcard, AXFR exposure, cut-over checklist. |

## Migration-day workflow

```bash
# 1. Baseline before any change (keep the outputs as evidence)
python3 dns_precheck.py example.com --html before.html --json before.json --export-bind example.com.zone

# 2. Import example.com.zone in Cloudflare (DNS > Records > Import), review proxy status,
#    disable DNSSEC at the registrar if the report says so, then change NS at the registrar.

# 3. Watch the new Cloudflare name servers propagate (HTML auto-refreshes)
python3 dns_precheck.py example.com \
  --expect-ns ada.ns.cloudflare.com,bob.ns.cloudflare.com \
  --watch 120 --html live.html --no-records

# 4. Track any record, e.g. www now answering with Cloudflare anycast IPs
python3 dns_precheck.py example.com --name www.example.com --record A --expect 104.21.10.10,172.67.20.20
```

Status per resolver: `MATCH` (identical to the reference), `PARTIAL` (overlap),
`STALE` (still the old value while `--expect` is set), `MISMATCH`, `NXDOMAIN`,
`NO DATA`, `SERVFAIL`, `TIMEOUT`. Without `--expect` the reference is the delegation
at the registry (for NS) or the authoritative answer (other types).

## Useful options

| Option | Purpose |
|---|---|
| `--resolver "ISP,196.200.0.1,Casablanca,MA,33.57,-7.59"` | add a resolver (repeatable): your ISP, corporate or regional resolvers |
| `--only-resolvers cloudflare,google,quad9` | restrict the resolver list |
| `--subdomain portal --subdomains-file hosts.txt` | inventory extra host names (the zone cannot be listed without AXFR) |
| `--transport doh` | use DNS-over-HTTPS when UDP/53 is filtered (`auto` = UDP/TCP then DoH) |
| `--axfr` | try a zone transfer to capture the full zone (only on domains you own) |
| `--timeout 3 --workers 24` | tuning |

## Notes and limits

* Most public resolvers are anycast: the map places each at the operator's home
  location, but the answer comes from the PoP nearest the machine running the
  script. To see other regions, run it from hosts in those regions or add regional
  resolvers with `--resolver`.
* Without AXFR, the inventory only contains names the script probes. Compare it with the
  export from your current DNS provider before you import into Cloudflare.
* The HTML map uses Leaflet + CARTO tiles from the internet; offline it falls back to a
  built-in SVG map.
* Run it only against domains you own or are authorized to assess.
