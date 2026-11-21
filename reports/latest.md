# Threat situation report
Period: last 7 days (2026-11-14 18:03 UTC to 2026-11-21 18:03 UTC) · 18 agents
## Key findings
- **High confidence.** The fleet has less history than this period, so there is no usual level yet: nothing here is called new or rising. _(comparisons start once the fleet has run for 336 hours)_
- **High confidence.** CVE-2017-9841 (PHPUnit eval-stdin remote code execution) is being attempted, a vulnerability CISA lists as exploited in the wild. _(1784 attempts on 17 of 18 agents; first seen by the fleet 8 days ago)_
- **High confidence.** CVE-2025-30208 (Vite bypasses server\[.]fs\[.]deny with raw query) is being attempted. _(207 attempts on 16 of 18 agents; first seen by the fleet 8 days ago)_
- **High confidence.** CVE-2020-11547 (PRTG Network Monitor information disclosure) is being attempted. _(192 attempts on 13 of 18 agents; first seen by the fleet 7 days ago)_
- **High confidence.** CVE-2026-104935 (Ivanti Connect Secure Authentication Bypass by Spoofing Vulnerability) is being attempted, a vulnerability CISA lists as exploited in the wild. _(179 attempts on 16 of 18 agents; first seen by the fleet 8 days ago)_
- **High confidence.** The largest campaign uses 165 addresses with the same technique set (admin-panel, iot-router). _(344 events on 18 of 18 agents)_

## Numbers
| Events | Attacking addresses | High severity | Blocked now | Language-model agents | New patterns |
|---|---|---|---|---|---|
| 7219190 | 33716 | 24175 | 776 | 0 | 10 |

## Known exploits
| CVE | Name | CVSS | CISA | Events | Agents |
|---|---|---|---|---|---|
| CVE-2017-9841 | PHPUnit eval-stdin remote code execution | `9.8 ` | exploited | 1784 | 17 |
| CVE-2025-30208 | `Vite bypasses server.fs.deny with raw query ` | `n/a ` | - | 207 | 16 |
| CVE-2020-11547 | PRTG Network Monitor information disclosure | `n/a ` | - | 192 | 13 |
| CVE-2026-104935 | Ivanti Connect Secure Authentication Bypass by Spoofing Vulnerability | `n/a ` | exploited | 179 | 16 |
| CVE-2026-123158 | OpenSSH password authentication bypass (musl libc without PAM) | `8.1 ` | exploited | 147 | 13 |
| CVE-2021-3129 | Laravel Ignition remote code execution | `9.8 ` | exploited, ransomware | 137 | 2 |
| CVE-2025-31324 | SAP NetWeaver Visual Composer file upload | `10.0 ` | exploited, ransomware | 130 | 18 |
| CVE-2021-41773 | Apache httpd path traversal | `7.5 ` | exploited, ransomware | 114 | 16 |
| CVE-2021-44228 | Log4Shell | `10.0 ` | exploited, ransomware | 100 | 8 |
| CVE-2024-0012 | PAN-OS management web interface authentication bypass | `n/a ` | exploited, ransomware | 98 | 18 |

## Technologies under attack
| Technology | Events | Change | Agents |
|---|---|---|---|
| credential-attack | 152866 | no history yet | 18 |
| ssh | 150459 | no history yet | 18 |
| ssh-shell | 51448 | no history yet | 18 |
| rdp | 48912 | no history yet | 18 |
| telnet | 48735 | no history yet | 18 |
| smb | 45391 | no history yet | 18 |
| mssql | 40950 | no history yet | 18 |
| ssh-login | 37018 | no history yet | 18 |
| smb1 | 29546 | no history yet | 18 |
| shell-recon | 26184 | no history yet | 18 |
| shell-download | 16905 | no history yet | 18 |
| mysql | 12792 | no history yet | 18 |

## New request patterns
| Pattern | Events | Addresses | Confidence |
|---|---|---|---|
| mssql Admin | 1663 | 7 | medium |
| telnet chinadsl-net | 1650 | 4 | medium |
| telnet router | 1612 | 5 | medium |
| mssql Administrator | 1182 | 6 | medium |
| mssql server | 989 | 7 | medium |
| mssql Support | 706 | 6 | medium |
| `GET /elfinder/php/connector.minimal.php ` | 583 | 114 | medium |
| `WebSiphon/next-{v} ` | 525 | 38 | medium |

## Campaigns
| Techniques | Addresses | Events | Agents |
|---|---|---|---|
| admin-panel, iot-router | 165 | 344 | 18 |
| CVE-2025-31324 | 94 | 97 | 18 |
| admin-panel, iot-router | 75 | 77 | 18 |
| env-secrets | 72 | 105 | 18 |
| java-spring | 60 | 62 | 18 |

## Indicators (de-fanged, never fetch)
| Indicator | Attacking addresses |
|---|---|
| a8460f446be540410004b1a8db4083773fa46f7fe76fa84219c93daa1669f8f2 | 322 |
| 01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b | 142 |
| e150a1ec81e8e93e1eae2c3a77e66ec6dbd6a3b460f89c1d08aecf422ee401a0 | 110 |
| 2634c3097f98e36865f0c572009c4ffd73316bc8b88ccfe8d196af35f46e2394 | 108 |
| c05b56ab6d3d07ccca6778ebd799bf98dfa2b7f10dd43601f0938f04e5070878 | 107 |
| a883dafc480d466ee04e0d6da986bd78eb1fdd2178d04693723da3a8f95d42f4 | 105 |
| 6d78392a5886177fe5b86e585a0b695a2bcd01a05504b3c4e38bc8eeb21e8326 | 104 |
| 6b3a55e0261b0304143f805a24924d0c1c44524821305f31d9277843b8a10f4e | 102 |
| cc10ba3e72e09f1e742e4155968aa081fd309c76b6acf28eea1e3046438f005e | 99 |
| 3c56dd5ed61af7e7b20f54288947a89a4891d181b10fe04560b55c5e82de1fa2 | 99 |
| f33ae3bc9a22cd7564990a794789954409977013966fb1a8f43c35776b833a95 | 97 |
| 5ecf8d2cc410094e8b82dd0bc178a57f3aa1e80916689beb00fe56148b1b1256 | 97 |
| 53175bcc0524f37b47062fafdda28e3f8eb91d519ca0a184ca71bbebe72f969a | 94 |
| 9d272f1f3e92f7c5efdcfdda0ab92facccd98c340be8be09064060503fd167e4 | 82 |
| 3b5485dd0909db36922ecd8578f18da11954810e63582f302c10881ac5c47534 | 82 |

## ATT&CK techniques
| Tactic | Technique | Name | Events | Agents | Confidence |
|---|---|---|---|---|---|
| Reconnaissance | `T1595.001 ` | Scanning IP Blocks | 286534 | 18 | high |
| Reconnaissance | `T1595.002 ` | Vulnerability Scanning | 19441 | 18 | high |
| Reconnaissance | `T1595.003 ` | Wordlist Scanning | 16804 | 18 | high |
| Reconnaissance | T1594 | Search Victim-Owned Websites | 6306 | 18 | high |
| Initial Access | T1133 | External Remote Services | 110576 | 18 | high |
| Initial Access | T1078 | Valid Accounts | 37037 | 18 | high |
| Initial Access | T1190 | Exploit Public-Facing Application | 3438 | 18 | high |
| Execution | `T1059.004 ` | Unix Shell | 52344 | 18 | high |
| Persistence | `T1053.003 ` | Cron | 7345 | 18 | high |
| Persistence | T1098 | Account Manipulation | 675 | 15 | high |
| Persistence | `T1098.004 ` | SSH Authorized Keys | 492 | 12 | high |
| Stealth | `T1070.004 ` | File Deletion | 7888 | 18 | high |
| Stealth | `T1070.003 ` | Clear Command History | 289 | 17 | high |
| Defense Impairment | `T1222.002 ` | Linux and Mac Permissions | 1002 | 18 | high |
| Credential Access | `T1110.001 ` | Password Guessing | 152866 | 18 | high |
| Credential Access | `T1552.001 ` | Credentials In Files | 6535 | 18 | high |
| Discovery | T1082 | System Information Discovery | 26115 | 18 | high |
| Discovery | T1057 | Process Discovery | 7447 | 18 | high |
| Discovery | T1033 | `System Owner/User Discovery ` | 935 | 16 | high |
| Discovery | T1083 | File and Directory Discovery | 565 | 18 | high |
| Discovery | T1016 | System Network Configuration Discovery | 267 | 17 | high |
| Command and Control | T1105 | Ingress Tool Transfer | 18908 | 18 | high |
| Command and Control | T1090 | Proxy | 10957 | 18 | high |
| Impact | `T1496.001 ` | Compute Hijacking | 6995 | 18 | high |

## Recommendations
- Patch or take offline anything affected by CVE-2017-9841 (PHPUnit eval-stdin remote code execution). _1784 attempts on 17 agents in this period, listed by CISA as exploited in the wild._
- Patch or take offline anything affected by CVE-2025-30208 (Vite bypasses server\[.]fs\[.]deny with raw query). _207 attempts on 16 agents in this period._
- Patch or take offline anything affected by CVE-2020-11547 (PRTG Network Monitor information disclosure). _192 attempts on 13 agents in this period._
- Patch or take offline anything affected by CVE-2026-104935 (Ivanti Connect Secure Authentication Bypass by Spoofing Vulnerability). _179 attempts on 16 agents in this period, listed by CISA as exploited in the wild._
- Patch or take offline anything affected by CVE-2026-123158 (OpenSSH password authentication bypass (musl libc without PAM)). _147 attempts on 13 agents in this period, listed by CISA as exploited in the wild._
- Patch or take offline anything affected by CVE-2021-3129 (Laravel Ignition remote code execution). _137 attempts on 2 agents in this period, listed by CISA as exploited in the wild, known ransomware use._
- Patch or take offline anything affected by CVE-2025-31324 (SAP NetWeaver Visual Composer file upload). _130 attempts on 18 agents in this period, listed by CISA as exploited in the wild, known ransomware use._
- Patch or take offline anything affected by CVE-2021-41773 (Apache httpd path traversal). _114 attempts on 16 agents in this period, listed by CISA as exploited in the wild, known ransomware use._
- Patch or take offline anything affected by CVE-2021-44228 (Log4Shell). _100 attempts on 8 agents in this period, listed by CISA as exploited in the wild, known ransomware use._
- Patch or take offline anything affected by CVE-2024-0012 (PAN-OS management web interface authentication bypass). _98 attempts on 18 agents in this period, listed by CISA as exploited in the wild, known ransomware use._

## Method and limits
- Source: decoy services (honeypots) on internet-facing servers. They have no legitimate users, so everything recorded is unsolicited.
- Coverage: untargeted, automated activity. The fleet does not see targeted attacks on your organisation, and it does not observe what happens after a successful break-in.
- Confidence: high = seen by at least half of a multi-agent fleet and by ten or more addresses; medium = several addresses or more than one agent; low = a single agent and few addresses.
- Change is measured against the average of the seven preceding periods of equal length.
- ATT&CK techniques describe what a request attempted. No technique succeeded: decoys never execute what they receive.
- CVE dates and scores: CVE Program. Exploited-in-the-wild status: CISA KEV. Origin countries are where a network is registered, not necessarily where an operator sits.
