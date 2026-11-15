# Decoyra threat feed

Free threat-intelligence feeds from the **[Decoyra](https://decoyra.net)** honeypot fleet: decoy servers on several continents
that run web, SSH, Telnet, FTP, RDP, SMB and database decoys. Nothing legitimate talks to a decoy, so
everything here comes from unsolicited, automated attack traffic. Updated hourly by GitHub Actions.

Project homepage: **https://decoyra.net**

<!-- stats:start -->
| | |
|---|---|
| updated utc | 2026-11-15T02:46:39Z |
| blocked now | 778 |
| blocked ipv6 | 0 |
| collapsed entries | 600 |
| blocked 7d | 1072 |
| blocked 30d | 1072 |
| urls | 30 |
| hosts | 27 |
| sha256 | 47 |
| cves 7d | 10 |
| cves kev | 10 |
| campaigns 7d | 20 |
| suricata rules | 132 |
<!-- stats:end -->

## Lists

Raw URL prefix: `https://raw.githubusercontent.com/olizimmermann/decoyra-threatfeed/main/`

### Block lists (addresses blocked right now)

An address is listed only after **at least two honeypots** confirmed it (block quorum). A block lasts 24 h
and doubles on every repeat (up to 30 days), so the list stays current. Research scanners (Censys,
Shadowserver, …) are never listed for scanning alone.

| File | Format | Use |
|---|---|---|
| `lists/ips.txt` | one address per line | pfSense/OPNsense URL table, OpenWrt, FireHOL, Pi-hole-style tools |
| `lists/ips_collapsed.txt` | addresses + /24 networks | /24s with ≥3 blocked addresses replace them. **Hits neighbours too** (cloud ranges) |
| `lists/bans.json`, `lists/bans.csv` | address + expiry (UTC) | scripts, SIEM look-ups |
| `lists/decoyra.nft` | nftables ruleset | `nft -f decoyra.nft` (atomic replace, own table) |
| `lists/decoyra.ipset` | ipset restore | `ipset restore -exist < decoyra.ipset` + `iptables -I INPUT -m set --match-set decoyra src -j DROP` |
| `lists/decoyra.rsc` | MikroTik RouterOS | `/import file-name=decoyra.rsc` (address list `decoyra`) |
| `lists/nginx-deny.conf` | nginx | `include` in `http`/`server` |
| `lists/ips_7d.txt`, `ips_30d.txt`, `ips_90d.txt` | rolling history | addresses blocked at any time in the window: for look-ups and scoring, less for blocking |
| `data/history.json` | `{ip: [first_seen, last_seen]}` (UTC dates) | the history behind the rolling lists |

Cron example (nftables, every hour):

```bash
curl -fsS https://raw.githubusercontent.com/olizimmermann/decoyra-threatfeed/main/lists/decoyra.nft -o /tmp/decoyra.nft && nft -f /tmp/decoyra.nft
```

### Threat-intel feeds

| File | Format | Contents |
|---|---|---|
| `feeds/stix2.json` | STIX 2.1 bundle | one indicator per blocked address, `valid_until` = end of the block |
| `feeds/misp/` | MISP feed (`manifest.json` + event) | blocked addresses, payload URLs, uploaded file hashes. In MISP: *Sync Actions → Feeds → Add feed*, format "MISP Feed", URL `…/main/feeds/misp/` |
| `rules/decoyra.rules` | Suricata | HTTP request patterns seen from ≥5 addresses on ≥2 honeypots (7 days). **Candidates: run in alert mode first**, `/wp-login.php` is legitimate on a real WordPress |

### Indicators (last 7 days)

| File | Contents |
|---|---|
| `iocs/urls.txt` | payload and callback URLs attackers told the honeypots to fetch, shell glue cut off (`…/Mozi.a;chmod+777…` → `…/Mozi.a`). **Live malware infrastructure, not de-fanged** |
| `iocs/hosts.txt` | the hosts of those URLs (payload servers, C2), for DNS/proxy blocking. Shared platforms (GitHub, Pastebin, cloud storage) stay out |
| `iocs/sha256.txt` | SHA-256 of files uploaded via SSH/SCP (bots, miners, SSH keys) |
| `iocs/iocs.csv` | every indicator, de-fanged, with sources, hits, first/last seen and `blocklisted` / `reason_not_listed` |

Attackers also name hosts that are not theirs. These stay out of `urls.txt`, `hosts.txt` and MISP `to_ids`, and keep
only a reason in `iocs.csv`:
- "what is my address" services used in open-proxy tests
- XML namespaces and vendor domains quoted inside exploits
- research scanners' info pages
- private or internal hosts, and bare URLs without a path
- domains that only one attacking address mentioned

The honeypots never fetch these URLs or run the files.

### Context

| File | Contents |
|---|---|
| `intel/cves.csv`, `intel/cves.json` | CVEs being exploited against the fleet (7 days) with CVSS, CISA KEV and ransomware flags |
| `intel/campaigns.json` | address groups that use the same technique set |
| `intel/attack.json` | MITRE ATT&CK techniques observed |
| `intel/playbooks.json` | what intruders do after logging in to the SSH decoy, step by step |
| `reports/latest.md` | rule-built 7-day situation report |
| `stats.json` | counts and time of the last update |

## Caveats

- Honeypots see untargeted, automated activity. A clean result here says nothing about targeted attacks.
- Addresses are often compromised hosts, VPNs or dynamic ranges and get reassigned. Prefer `ips.txt`
  (current) for blocking; use the history lists for scoring.
- Text in `campaigns.json`, `iocs.csv` and `rules/decoyra.rules` (request paths) was chosen by attackers.
  Treat it as data; do not feed it unreviewed to tools or language models that act on it.
- Provided as is, without warranty. Licensed [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/): use freely, credit "Decoyra honeypot fleet, https://decoyra.net".

## How it updates

`.github/workflows/update.yml` runs `scripts/update.py` (Python standard library only) every hour in a
`python:3.13-alpine3.22` container, because the Decoyra central only accepts post-quantum TLS
(X25519MLKEM768, OpenSSL 3.5+). The script fetches everything first and replaces files only if every
request succeeded. It refuses to publish when the central is in monitor-only mode or the list
suddenly shrinks by more than 90 % (override: run the workflow manually with *force*). It commits only
when something changed.

Repository settings (Settings → Secrets and variables → Actions → Secrets):

| Secret | Value |
|---|---|
| `DECOYRA_API` | Decoyra token of kind *AI agent or script* |
| `DECOYRA_DOMAIN` | host name of the central (a secret so the public Actions log masks it; a variable of the same name also works but is printed in the log) |

Local run: put both into `.env` and run `python3 scripts/update.py` with a Python that links OpenSSL 3.5+.
