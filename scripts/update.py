#!/usr/bin/env python3
"""Fetch the Decoyra honeypot fleet's intelligence and write the public lists in this repository.

Standard library only. Environment:
  DECOYRA_API     intelligence token ("AI agent or script")
  DECOYRA_DOMAIN  host name of the central, e.g. hub.example.org (never printed)
  FORCE=1         publish even if the ban list shrank suspiciously

The central requires post-quantum TLS (X25519MLKEM768), so Python must link OpenSSL 3.5 or newer.
Everything is fetched and validated first; files are only replaced when every request worked.
"""
from __future__ import annotations

import csv
import hashlib
import io
import ipaddress
import json
import os
import re
import ssl
import sys
import time
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parent.parent
NS = uuid.UUID("6f1f0a8e-3a52-5b7e-9d6c-6b0c1e9d2a41")          # namespace for stable MISP uuids
ORG = {"name": "Decoyra honeypot fleet", "uuid": str(uuid.uuid5(NS, "org"))}
HISTORY_DAYS = 90
SHRINK_GUARD = (100, 0.10)    # refuse if the list had >=100 entries and falls below 10 % of that


def die(msg: str) -> None:
    print("error: " + msg, file=sys.stderr)
    sys.exit(1)


def env(name: str) -> str:
    v = os.environ.get(name, "").strip()
    if not v and (ROOT / ".env").exists():             # local runs
        for line in (ROOT / ".env").read_text().splitlines():
            k, _, val = line.partition("=")
            if k.strip() == name:
                v = val.strip().strip('"').strip("'")
    return v


TOKEN, DOMAIN = env("DECOYRA_API"), env("DECOYRA_DOMAIN")
if not TOKEN or not DOMAIN:
    die("DECOYRA_API and DECOYRA_DOMAIN must be set")
DOMAIN = re.sub(r"^https?://", "", DOMAIN).strip("/")
CTX = ssl.create_default_context()


def get(path: str) -> bytes:
    """GET one endpoint. Errors name the path only, never the host or the token."""
    req = urllib.request.Request(f"https://{DOMAIN}/api/v1/{path}",
                                 headers={"Authorization": "Bearer " + TOKEN, "User-Agent": "decoyra-blocklist/1"})
    for attempt in range(3):
        try:
            with urllib.request.urlopen(req, timeout=60, context=CTX) as r:
                return r.read()
        except urllib.error.HTTPError as e:
            if e.code < 500 or attempt == 2:
                die(f"{path.split('?')[0]}: HTTP {e.code}")
        except Exception as e:  # noqa: BLE001 - TLS, DNS, timeouts
            if attempt == 2:
                die(f"{path.split('?')[0]}: {type(e).__name__}")
        time.sleep(5 * (attempt + 1))
    raise AssertionError


def get_json(path: str):
    try:
        return json.loads(get(path))
    except ValueError:
        die(f"{path.split('?')[0]}: not JSON")


def iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def public_net(value: str, max_prefix_v4: int = 24, max_prefix_v6: int = 48):
    """A public address or a network no broader than /24 (v4) or /48 (v6); else None."""
    try:
        n = ipaddress.ip_network(value.strip(), strict=True)
    except ValueError:
        return None
    if not n.is_global or n.prefixlen < (max_prefix_v4 if n.version == 4 else max_prefix_v6):
        return None
    return n


def net_str(n) -> str:
    return str(n.network_address) if n.prefixlen == n.max_prefixlen else str(n)


def sort_key(s: str):
    n = ipaddress.ip_network(s)
    return (n.version, int(n.network_address), n.prefixlen)


def clean_bans(rows: list, label: str) -> list[dict]:
    out, dropped = {}, 0
    for r in rows:
        n = public_net(str(r.get("ip", "")))
        if not n or not isinstance(r.get("expires"), (int, float)):
            dropped += 1
            continue
        out[net_str(n)] = {"ip": net_str(n), "expires": float(r["expires"])}
    if dropped:
        print(f"{label}: dropped {dropped} invalid, private or too broad entries")
    return sorted(out.values(), key=lambda r: sort_key(r["ip"]))


def strip_generated(text: str) -> str:
    """Remove the volatile generated= timestamp from export headers so unchanged content stays unchanged."""
    return re.sub(r",? ?generated=\S+", "", text)


# ----------------------------------------------------------------- fetch

print("TLS library:", ssl.OPENSSL_VERSION)

feed = get_json("feed/bans")
if not isinstance(feed, dict) or not feed.get("enforce"):
    die("the central is in monitor-only mode (enforce=false); not publishing an empty block list")
bans = clean_bans(feed.get("bans", []), "bans")
collapsed = clean_bans(get_json("feed/bans?collapse=3").get("bans", []), "bans collapse=3")

prev = ROOT / "lists" / "ips.txt"
if prev.exists() and os.environ.get("FORCE") != "1":
    before = sum(1 for line in prev.read_text().splitlines() if line and not line.startswith("#"))
    if before >= SHRINK_GUARD[0] and len(bans) < before * SHRINK_GUARD[1]:
        die(f"ban list shrank from {before} to {len(bans)}; set FORCE=1 to publish anyway")

misp_src = get_json("intel/rules?format=misp&hours=168")
stix = get_json("intel/rules?format=stix")
iocs = get_json("intel/iocs?hours=168")
exploits = get_json("intel/exploits?hours=168")
campaigns = get_json("intel/campaigns?hours=168")
attack = get_json("intel/attack?hours=168")
playbooks = get_json("intel/playbooks?hours=168")
suricata = get(f"intel/rules?format=suricata&hours=168&min_sources=5&min_agents=2").decode()
report_md = get("intel/report?hours=168&format=md").decode()
targets = get_json("intel/targets?hours=168")      # read only to scrub agent locations; never written

for name, val, typ in (("misp", misp_src, dict), ("stix", stix, dict), ("iocs", iocs, list), ("exploits", exploits, list),
                       ("campaigns", campaigns, list), ("attack", attack, (list, dict)), ("playbooks", playbooks, (list, dict)),
                       ("targets", targets, list)):
    if not isinstance(val, typ):
        die(f"{name}: unexpected shape")
if not suricata.startswith("#"):
    die("suricata: unexpected content")

now = time.time()
out: dict[str, str] = {}          # relative path -> content
ips = [b["ip"] for b in bans]
HDR = ("# Decoyra honeypot fleet: addresses confirmed by at least two agents, blocked right now.\n"
       "# Source: https://github.com/olizimmermann/blocklist  (honeypot traffic only; nothing legitimate talks to a decoy)\n")

# ----------------------------------------------------------------- block lists

out["lists/ips.txt"] = HDR + "".join(i + "\n" for i in ips)
out["lists/ips_collapsed.txt"] = (HDR + "# /24 networks where 3 or more addresses are blocked replace those addresses.\n"
                                  "# Blocks neighbours that share the network (cloud ranges): use with care.\n"
                                  + "".join(b["ip"] + "\n" for b in collapsed))
out["lists/bans.json"] = json.dumps({"source": "Decoyra honeypot fleet", "count": len(bans),
                                     "bans": [{"ip": b["ip"], "expires": iso(b["expires"])} for b in bans]}, indent=1) + "\n"
buf = io.StringIO()
w = csv.writer(buf, lineterminator="\n")
w.writerow(["ip", "expires_utc"])
w.writerows([b["ip"], iso(b["expires"])] for b in bans)
out["lists/bans.csv"] = buf.getvalue()

v4 = [i for i in ips if ":" not in i]
v6 = [i for i in ips if ":" in i]


def nft_elems(items: list[str]) -> str:
    return ",\n".join("    " + i for i in items)


nft = ["#!/usr/sbin/nft -f", "# Decoyra block list. Load: nft -f decoyra.nft  (replaces the sets atomically)",
       "table inet decoyra_blocklist {}", "flush table inet decoyra_blocklist", "table inet decoyra_blocklist {",
       "  set v4 { type ipv4_addr; flags interval; auto-merge;" + (" elements = {\n" + nft_elems(v4) + "\n  }" if v4 else "") + " }",
       "  set v6 { type ipv6_addr; flags interval; auto-merge;" + (" elements = {\n" + nft_elems(v6) + "\n  }" if v6 else "") + " }",
       "  chain input { type filter hook input priority -10; policy accept;",
       "    ip saddr @v4 drop", "    ip6 saddr @v6 drop", "  }", "}"]
out["lists/decoyra.nft"] = "\n".join(nft) + "\n"

ipset = ["# Decoyra block list for ipset. Load: ipset restore -exist < decoyra.ipset",
         "# then: iptables -I INPUT -m set --match-set decoyra src -j DROP",
         "create decoyra hash:net family inet maxelem 262144 -exist", "create decoyra_tmp hash:net family inet maxelem 262144 -exist",
         "flush decoyra_tmp"] + [f"add decoyra_tmp {i}" for i in v4] + ["swap decoyra_tmp decoyra", "destroy decoyra_tmp"]
out["lists/decoyra.ipset"] = "\n".join(ipset) + "\n"

ros = ["# Decoyra block list for MikroTik RouterOS. /import file-name=decoyra.rsc",
       "/ip firewall address-list remove [find list=decoyra]"] + \
      [f"/ip firewall address-list add list=decoyra address={i} comment=decoyra" for i in v4]
out["lists/decoyra.rsc"] = "\n".join(ros) + "\n"

out["lists/nginx-deny.conf"] = "# Decoyra block list for nginx: include in http, server or location.\n" + \
    "".join(f"deny {i};\n" for i in ips)

# Rolling history (dates only, so it changes at most once a day per address).
hist_path = ROOT / "data" / "history.json"
history = json.loads(hist_path.read_text()) if hist_path.exists() else {}
today = datetime.now(timezone.utc).date()
for i in ips:
    first, _ = history.get(i, [today.isoformat(), None])
    history[i] = [first, today.isoformat()]
cutoff = today.toordinal() - HISTORY_DAYS
history = {k: v for k, v in history.items() if datetime.fromisoformat(v[1]).toordinal() >= cutoff}
out["data/history.json"] = json.dumps(dict(sorted(history.items(), key=lambda kv: sort_key(kv[0]))), indent=0) + "\n"
for days in (7, 30, 90):
    sel = [k for k, v in history.items() if datetime.fromisoformat(v[1]).toordinal() > today.toordinal() - days]
    out[f"lists/ips_{days}d.txt"] = (f"# Decoyra honeypot fleet: addresses blocked at any time in the last {days} days (UTC dates).\n"
                                     "# Wider net than ips.txt, older entries may have been reassigned.\n"
                                     + "".join(k + "\n" for k in sorted(sel, key=sort_key)))

# ----------------------------------------------------------------- indicators

attrs = misp_src.get("Event", misp_src).get("Attribute", [])
urls = sorted({a["value"] for a in attrs if a.get("type") == "url"})
hashes = {a["value"].lower() for a in attrs if a.get("type") == "sha256" and re.fullmatch(r"[0-9a-fA-F]{64}", a.get("value", ""))}
hosts = set()
for u in urls:
    try:
        h = urlsplit(u).hostname or ""
    except ValueError:
        continue
    n = public_net(h)
    if n or re.fullmatch(r"(?i)[a-z0-9.-]+\.[a-z]{2,}", h):
        hosts.add(h.lower())
WARN = ("# LIVE MALWARE INFRASTRUCTURE: not de-fanged. Never fetch these.\n"
        "# Download and callback URLs that attackers told the honeypots to fetch, last 7 days.\n")
out["iocs/urls.txt"] = WARN + "".join(u + "\n" for u in urls)
out["iocs/hosts.txt"] = WARN.replace("URLs that", "hosts in URLs that") + "".join(h + "\n" for h in sorted(hosts))
out["iocs/sha256.txt"] = "# SHA-256 of files uploaded to the honeypots (SSH/SCP), last 7 days.\n" + "".join(h + "\n" for h in sorted(hashes))
buf = io.StringIO()
w = csv.writer(buf, lineterminator="\n")
w.writerow(["kind", "indicator_defanged", "context", "sources", "hits", "first_seen_utc", "last_seen_utc"])
for i in sorted(iocs, key=lambda x: (-x.get("sources", 0), x.get("indicator", ""))):
    w.writerow([i.get("kind"), i.get("indicator"), i.get("host"), i.get("sources"), i.get("hits"),
                iso(i["first_seen"]) if i.get("first_seen") else "", iso(i["last_seen"]) if i.get("last_seen") else ""])
out["iocs/iocs.csv"] = buf.getvalue()

# ----------------------------------------------------------------- STIX / MISP / Suricata

out["feeds/stix2.json"] = json.dumps(stix, indent=1) + "\n"

# A real MISP feed: manifest.json + one event file, addable in MISP under Sync Actions -> Feeds.
ev = dict(misp_src.get("Event", misp_src))
ev_uuid = ev.get("uuid") or str(uuid.uuid5(NS, "event"))
ts = str(max([int(a.get("timestamp") or 0) for a in attrs] + [0]) or int(now))
m_attrs = []
for a in attrs:
    a = dict(a)
    a["uuid"] = str(uuid.uuid5(NS, f"{a.get('type')}|{a.get('value')}"))
    a.setdefault("timestamp", ts)
    a.setdefault("distribution", "5")
    m_attrs.append(a)
m_attrs.sort(key=lambda a: (a.get("type", ""), a.get("value", "")))
tags = [{"name": "tlp:clear", "colour": "#ffffff"}, {"name": "source:decoyra-honeypot", "colour": "#0b6e4f"}]
event = {"uuid": ev_uuid, "info": ev.get("info", "Decoyra honeypot fleet"), "date": ev.get("date", today.isoformat()),
         "threat_level_id": ev.get("threat_level_id", "2"), "analysis": ev.get("analysis", "1"), "distribution": "3",
         "published": True, "timestamp": ts, "publish_timestamp": ts, "Orgc": ORG, "Tag": tags, "Attribute": m_attrs}
out[f"feeds/misp/{ev_uuid}.json"] = json.dumps({"Event": event}, indent=1) + "\n"
out["feeds/misp/manifest.json"] = json.dumps({ev_uuid: {k: event[k] for k in (
    "info", "date", "threat_level_id", "analysis", "timestamp", "publish_timestamp", "Orgc", "Tag")}}, indent=1) + "\n"
out["feeds/misp/hashes.csv"] = "".join(f"{hashlib.md5(a['value'].encode()).hexdigest()},{ev_uuid}\n" for a in m_attrs)

out["rules/decoyra.rules"] = strip_generated(suricata).rstrip("\n") + "\n"

# ----------------------------------------------------------------- context: CVEs, campaigns, ATT&CK

buf = io.StringIO()
w = csv.writer(buf, lineterminator="\n")
w.writerow(["cve", "name", "cvss", "cisa_kev", "ransomware", "events_7d", "agents", "first_seen_utc", "last_seen_utc", "days_after_disclosure"])
for e in exploits:
    kev = e.get("kev") or {}
    w.writerow([e.get("cve"), e.get("name"), e.get("cvss"), "yes" if kev else "no", "yes" if kev.get("ransomware") else "no",
                e.get("events"), e.get("agents"), iso(e["first_seen"]) if e.get("first_seen") else "",
                iso(e["last_seen"]) if e.get("last_seen") else "", e.get("days_after_disclosure")])
out["intel/cves.csv"] = buf.getvalue()
out["intel/cves.json"] = json.dumps(exploits, indent=1) + "\n"
out["intel/campaigns.json"] = json.dumps(campaigns, indent=1) + "\n"
out["intel/attack.json"] = json.dumps(attack, indent=1) + "\n"
out["intel/playbooks.json"] = json.dumps(playbooks, indent=1) + "\n"

# Situation report without anything that locates the honeypots.
places = {str(t.get(k, "")).strip() for t in targets for k in ("name", "place")} - {""}
sections = re.split(r"(?m)^(?=## )", report_md)
kept = [s for s in sections if not s.startswith("## Attacked locations")]
lines = []
for line in "".join(kept).splitlines():
    if any(re.search(r"(?i)\b" + re.escape(p) + r"\b", line) for p in places):
        continue
    lines.append(re.sub(r"(?i)\s*·?\s*generated \d{4}-\d\d-\d\d \d\d:\d\d UTC", "", line))
out["reports/latest.md"] = "\n".join(lines).rstrip() + "\n"

# ----------------------------------------------------------------- write if changed

leaks = [p for p, c in out.items() if DOMAIN.lower() in c.lower()]
if leaks:
    die("output would contain the central's host name: " + ", ".join(leaks))

changed = [p for p, c in out.items() if not (ROOT / p).exists() or (ROOT / p).read_text() != c]
for stale in (ROOT / "feeds" / "misp").glob("*.json") if (ROOT / "feeds" / "misp").exists() else []:
    rel = str(stale.relative_to(ROOT))
    if rel not in out:
        stale.unlink()
        changed.append(rel)
if not changed:
    print("no changes")
    sys.exit(0)
for p in changed:
    if p in out:
        (ROOT / p).parent.mkdir(parents=True, exist_ok=True)
        (ROOT / p).write_text(out[p])

stats = {"updated_utc": iso(now), "blocked_now": len(ips), "blocked_ipv6": len(v6), "collapsed_entries": len(collapsed),
         "blocked_7d": out["lists/ips_7d.txt"].count("\n") - 2, "blocked_30d": out["lists/ips_30d.txt"].count("\n") - 2,
         "urls": len(urls), "hosts": len(hosts), "sha256": len(hashes), "cves_7d": len(exploits),
         "cves_kev": sum(1 for e in exploits if e.get("kev")), "campaigns_7d": len(campaigns),
         "suricata_rules": sum(1 for line in suricata.splitlines() if line.startswith("alert "))}
(ROOT / "stats.json").write_text(json.dumps(stats, indent=1) + "\n")

readme = ROOT / "README.md"
if readme.exists():
    table = ("| | |\n|---|---|\n" + "\n".join(f"| {k.replace('_', ' ')} | {v} |" for k, v in stats.items()) + "\n")
    text = readme.read_text()
    text = re.sub(r"(<!-- stats:start -->\n).*?(<!-- stats:end -->)", lambda m: m.group(1) + table + m.group(2), text, flags=re.S)
    readme.write_text(text)
print(f"updated {len(changed)} files: {len(ips)} blocked, {len(urls)} URLs, {len(hashes)} hashes, {len(exploits)} CVEs")
