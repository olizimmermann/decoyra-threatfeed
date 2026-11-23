# Threat situation report
Period: last 7 days (2026-11-16 02:54 UTC to 2026-11-23 02:54 UTC) · 18 agents
## Key findings
- **High confidence.** The fleet has less history than this period, so there is no usual level yet: nothing here is called new or rising. _(comparisons start once the fleet has run for 336 hours)_
- **High confidence.** CVE-2017-9841 (PHPUnit eval-stdin remote code execution) is being attempted, a vulnerability CISA lists as exploited in the wild. _(1824 attempts on 18 of 18 agents; first seen by the fleet 10 days ago)_
- **High confidence.** CVE-2025-30208 (Vite bypasses server\[.]fs\[.]deny with raw query) is being attempted. _(398 attempts on 15 of 18 agents; first seen by the fleet 9 days ago)_
- **High confidence.** CVE-2021-44228 (Log4Shell) is being attempted, a vulnerability CISA lists as exploited in the wild and used by ransomware groups. _(292 attempts on 9 of 18 agents; first seen by the fleet 9 days ago)_
- **High confidence.** CVE-2020-11547 (PRTG Network Monitor information disclosure) is being attempted. _(213 attempts on 13 of 18 agents; first seen by the fleet 8 days ago)_
- **High confidence.** The largest campaign uses 332 addresses with the same technique set (admin-panel, iot-router). _(702 events on 18 of 18 agents)_

## Numbers
| Events | Attacking addresses | High severity | Blocked now | Language-model agents | New patterns |
|---|---|---|---|---|---|
| 9224324 | 38488 | 28633 | 664 | 0 | 10 |

## Known exploits
| CVE | Name | CVSS | CISA | Events | Agents |
|---|---|---|---|---|---|
| CVE-2017-9841 | PHPUnit eval-stdin remote code execution | `9.8 ` | exploited | 1824 | 18 |
| CVE-2025-30208 | `Vite bypasses server.fs.deny with raw query ` | `n/a ` | - | 398 | 15 |
| CVE-2021-44228 | Log4Shell | `10.0 ` | exploited, ransomware | 292 | 9 |
| CVE-2020-11547 | PRTG Network Monitor information disclosure | `n/a ` | - | 213 | 13 |
| CVE-2025-55182 | React Server Components remote code execution (React2Shell) | `n/a ` | exploited, ransomware | 195 | 18 |
| CVE-2021-41773 | Apache httpd path traversal | `7.5 ` | exploited, ransomware | 168 | 17 |
| CVE-2021-3129 | Laravel Ignition remote code execution | `9.8 ` | exploited, ransomware | 136 | 1 |
| CVE-2025-31324 | SAP NetWeaver Visual Composer file upload | `10.0 ` | exploited, ransomware | 118 | 18 |
| CVE-2024-0012 | PAN-OS management web interface authentication bypass | `n/a ` | exploited, ransomware | 83 | 18 |
| CVE-2026-65694 | Microweber CMS path traversal via ServeStaticFileController | `n/a ` | - | 78 | 11 |

## Technologies under attack
| Technology | Events | Change | Agents |
|---|---|---|---|
| credential-attack | 151708 | no history yet | 18 |
| ssh | 145360 | no history yet | 18 |
| ssh-shell | 50952 | no history yet | 18 |
| telnet | 50454 | no history yet | 18 |
| smb | 48287 | no history yet | 18 |
| rdp | 44153 | no history yet | 18 |
| mssql | 39516 | no history yet | 18 |
| ssh-login | 38207 | no history yet | 18 |
| smb1 | 32226 | no history yet | 18 |
| shell-recon | 26804 | no history yet | 18 |
| shell-download | 17980 | no history yet | 18 |
| redis | 13164 | no history yet | 18 |

## New request patterns
| Pattern | Events | Addresses | Confidence |
|---|---|---|---|
| telnet chinadsl-net | 1997 | 4 | medium |
| telnet router | 1961 | 6 | medium |
| rdp user | 774 | 19 | high |
| `GET /boaform/adminformlogout//boaform/admin/login.asp ` | 702 | 332 | high |
| `GET /etc/passwd ` | 585 | 31 | medium |
| `GET /elfinder/php/connector.minimal.php ` | 583 | 114 | medium |
| `GET /elfinder/php/connector.php ` | 444 | 110 | medium |
| `SSH-2.0-libssh_0.12.2 ` | 425 | 25 | medium |

## Campaigns
| Techniques | Addresses | Events | Agents |
|---|---|---|---|
| admin-panel, iot-router | 332 | 702 | 18 |
| CVE-2025-31324 | 106 | 111 | 18 |
| admin-panel, iot-router | 101 | 103 | 18 |
| env-secrets | 81 | 125 | 18 |
| java-spring | 73 | 76 | 18 |

## Indicators (de-fanged, never fetch)
| Indicator | Attacking addresses |
|---|---|
| a8460f446be540410004b1a8db4083773fa46f7fe76fa84219c93daa1669f8f2 | 322 |
| 01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b | 142 |
| e150a1ec81e8e93e1eae2c3a77e66ec6dbd6a3b460f89c1d08aecf422ee401a0 | 112 |
| 2634c3097f98e36865f0c572009c4ffd73316bc8b88ccfe8d196af35f46e2394 | 111 |
| c05b56ab6d3d07ccca6778ebd799bf98dfa2b7f10dd43601f0938f04e5070878 | 111 |
| a883dafc480d466ee04e0d6da986bd78eb1fdd2178d04693723da3a8f95d42f4 | 110 |
| 6d78392a5886177fe5b86e585a0b695a2bcd01a05504b3c4e38bc8eeb21e8326 | 107 |
| 6b3a55e0261b0304143f805a24924d0c1c44524821305f31d9277843b8a10f4e | 106 |
| cc10ba3e72e09f1e742e4155968aa081fd309c76b6acf28eea1e3046438f005e | 104 |
| 5ecf8d2cc410094e8b82dd0bc178a57f3aa1e80916689beb00fe56148b1b1256 | 104 |
| f33ae3bc9a22cd7564990a794789954409977013966fb1a8f43c35776b833a95 | 103 |
| 3c56dd5ed61af7e7b20f54288947a89a4891d181b10fe04560b55c5e82de1fa2 | 102 |
| 53175bcc0524f37b47062fafdda28e3f8eb91d519ca0a184ca71bbebe72f969a | 99 |
| 9d272f1f3e92f7c5efdcfdda0ab92facccd98c340be8be09064060503fd167e4 | 91 |
| 3b5485dd0909db36922ecd8578f18da11954810e63582f302c10881ac5c47534 | 91 |

## ATT&CK techniques
| Tactic | Technique | Name | Events | Agents | Confidence |
|---|---|---|---|---|---|
| Reconnaissance | `T1595.001 ` | Scanning IP Blocks | 283706 | 18 | high |
| Reconnaissance | `T1595.002 ` | Vulnerability Scanning | 19248 | 18 | high |
| Reconnaissance | `T1595.003 ` | Wordlist Scanning | 15573 | 18 | high |
| Reconnaissance | T1594 | Search Victim-Owned Websites | 6041 | 18 | high |
| Initial Access | T1133 | External Remote Services | 110052 | 18 | high |
| Initial Access | T1078 | Valid Accounts | 38218 | 18 | high |
| Initial Access | T1190 | Exploit Public-Facing Application | 4237 | 18 | high |
| Execution | `T1059.004 ` | Unix Shell | 52007 | 18 | high |
| Persistence | `T1053.003 ` | Cron | 8009 | 18 | high |
| Persistence | T1098 | Account Manipulation | 472 | 17 | high |
| Persistence | `T1098.004 ` | SSH Authorized Keys | 379 | 12 | high |
| Stealth | `T1070.004 ` | File Deletion | 8513 | 18 | high |
| Stealth | `T1070.003 ` | Clear Command History | 249 | 18 | high |
| Defense Impairment | `T1222.002 ` | Linux and Mac Permissions | 720 | 18 | high |
| Credential Access | `T1110.001 ` | Password Guessing | 151708 | 18 | high |
| Credential Access | `T1552.001 ` | Credentials In Files | 5491 | 18 | high |
| Discovery | T1082 | System Information Discovery | 27042 | 18 | high |
| Discovery | T1057 | Process Discovery | 8126 | 18 | high |
| Discovery | T1033 | `System Owner/User Discovery ` | 723 | 18 | high |
| Discovery | T1083 | File and Directory Discovery | 457 | 18 | high |
| Discovery | T1016 | System Network Configuration Discovery | 267 | 17 | high |
| Command and Control | T1105 | Ingress Tool Transfer | 20324 | 18 | high |
| Command and Control | T1090 | Proxy | 10213 | 18 | high |
| Impact | `T1496.001 ` | Compute Hijacking | 7771 | 18 | high |

## Recommendations
- Patch or take offline anything affected by CVE-2017-9841 (PHPUnit eval-stdin remote code execution). _1824 attempts on 18 agents in this period, listed by CISA as exploited in the wild._
- Patch or take offline anything affected by CVE-2025-30208 (Vite bypasses server\[.]fs\[.]deny with raw query). _398 attempts on 15 agents in this period._
- Patch or take offline anything affected by CVE-2021-44228 (Log4Shell). _292 attempts on 9 agents in this period, listed by CISA as exploited in the wild, known ransomware use._
- Patch or take offline anything affected by CVE-2020-11547 (PRTG Network Monitor information disclosure). _213 attempts on 13 agents in this period._
- Patch or take offline anything affected by CVE-2025-55182 (React Server Components remote code execution (React2Shell)). _195 attempts on 18 agents in this period, listed by CISA as exploited in the wild, known ransomware use._
- Patch or take offline anything affected by CVE-2021-41773 (Apache httpd path traversal). _168 attempts on 17 agents in this period, listed by CISA as exploited in the wild, known ransomware use._
- Patch or take offline anything affected by CVE-2021-3129 (Laravel Ignition remote code execution). _136 attempts on 1 agents in this period, listed by CISA as exploited in the wild, known ransomware use._
- Patch or take offline anything affected by CVE-2025-31324 (SAP NetWeaver Visual Composer file upload). _118 attempts on 18 agents in this period, listed by CISA as exploited in the wild, known ransomware use._
- Patch or take offline anything affected by CVE-2024-0012 (PAN-OS management web interface authentication bypass). _83 attempts on 18 agents in this period, listed by CISA as exploited in the wild, known ransomware use._
- Patch or take offline anything affected by CVE-2026-65694 (Microweber CMS path traversal via ServeStaticFileController). _78 attempts on 11 agents in this period._

## Method and limits
- Source: decoy services (honeypots) on internet-facing servers. They have no legitimate users, so everything recorded is unsolicited.
- Coverage: untargeted, automated activity. The fleet does not see targeted attacks on your organisation, and it does not observe what happens after a successful break-in.
- Confidence: high = seen by at least half of a multi-agent fleet and by ten or more addresses; medium = several addresses or more than one agent; low = a single agent and few addresses.
- Change is measured against the average of the seven preceding periods of equal length.
- ATT&CK techniques describe what a request attempted. No technique succeeded: decoys never execute what they receive.
- CVE dates and scores: CVE Program. Exploited-in-the-wild status: CISA KEV. Origin countries are where a network is registered, not necessarily where an operator sits.
