# Threat situation report
Period: last 7 days (2026-11-15 07:02 UTC to 2026-11-22 07:02 UTC) · 18 agents
## Key findings
- **High confidence.** The fleet has less history than this period, so there is no usual level yet: nothing here is called new or rising. _(comparisons start once the fleet has run for 336 hours)_
- **High confidence.** CVE-2017-9841 (PHPUnit eval-stdin remote code execution) is being attempted, a vulnerability CISA lists as exploited in the wild. _(1797 attempts on 17 of 18 agents; first seen by the fleet 9 days ago)_
- **High confidence.** CVE-2025-30208 (Vite bypasses server\[.]fs\[.]deny with raw query) is being attempted. _(313 attempts on 16 of 18 agents; first seen by the fleet 8 days ago)_
- **High confidence.** CVE-2021-44228 (Log4Shell) is being attempted, a vulnerability CISA lists as exploited in the wild and used by ransomware groups. _(288 attempts on 9 of 18 agents; first seen by the fleet 8 days ago)_
- **High confidence.** CVE-2020-11547 (PRTG Network Monitor information disclosure) is being attempted. _(201 attempts on 13 of 18 agents; first seen by the fleet 8 days ago)_
- **High confidence.** The largest campaign uses 223 addresses with the same technique set (admin-panel, iot-router). _(470 events on 18 of 18 agents)_

## Numbers
| Events | Attacking addresses | High severity | Blocked now | Language-model agents | New patterns |
|---|---|---|---|---|---|
| 7943970 | 35645 | 26408 | 702 | 0 | 10 |

## Known exploits
| CVE | Name | CVSS | CISA | Events | Agents |
|---|---|---|---|---|---|
| CVE-2017-9841 | PHPUnit eval-stdin remote code execution | `9.8 ` | exploited | 1797 | 17 |
| CVE-2025-30208 | `Vite bypasses server.fs.deny with raw query ` | `n/a ` | - | 313 | 16 |
| CVE-2021-44228 | Log4Shell | `10.0 ` | exploited, ransomware | 288 | 9 |
| CVE-2020-11547 | PRTG Network Monitor information disclosure | `n/a ` | - | 201 | 13 |
| CVE-2021-41773 | Apache httpd path traversal | `7.5 ` | exploited, ransomware | 166 | 16 |
| CVE-2021-3129 | Laravel Ignition remote code execution | `9.8 ` | exploited, ransomware | 136 | 1 |
| CVE-2025-31324 | SAP NetWeaver Visual Composer file upload | `10.0 ` | exploited, ransomware | 115 | 18 |
| CVE-2024-0012 | PAN-OS management web interface authentication bypass | `n/a ` | exploited, ransomware | 95 | 18 |
| CVE-2018-13379 | FortiOS SSL VPN file read | `9.1 ` | exploited, ransomware | 88 | 16 |
| CVE-2026-104935 | Ivanti Connect Secure Authentication Bypass by Spoofing Vulnerability | `n/a ` | exploited | 84 | 16 |

## Technologies under attack
| Technology | Events | Change | Agents |
|---|---|---|---|
| credential-attack | 153340 | no history yet | 18 |
| ssh | 148884 | no history yet | 18 |
| ssh-shell | 51179 | no history yet | 18 |
| telnet | 50130 | no history yet | 18 |
| smb | 46851 | no history yet | 18 |
| rdp | 46539 | no history yet | 18 |
| mssql | 41400 | no history yet | 18 |
| ssh-login | 37421 | no history yet | 18 |
| smb1 | 30593 | no history yet | 18 |
| shell-recon | 26482 | no history yet | 18 |
| shell-download | 17374 | no history yet | 18 |
| mysql | 12689 | no history yet | 18 |

## New request patterns
| Pattern | Events | Addresses | Confidence |
|---|---|---|---|
| telnet chinadsl-net | 1650 | 4 | medium |
| telnet router | 1612 | 5 | medium |
| mssql Administrator | 1182 | 6 | medium |
| mssql server | 989 | 7 | medium |
| mssql Support | 706 | 6 | medium |
| `GET /elfinder/php/connector.minimal.php ` | 583 | 114 | medium |
| `WebSiphon/next-{v} ` | 525 | 38 | medium |
| mssql test | 506 | 6 | medium |

## Campaigns
| Techniques | Addresses | Events | Agents |
|---|---|---|---|
| admin-panel, iot-router | 223 | 470 | 18 |
| CVE-2025-31324 | 94 | 97 | 18 |
| admin-panel, iot-router | 84 | 86 | 18 |
| env-secrets | 73 | 107 | 18 |
| java-spring | 61 | 121 | 18 |

## Indicators (de-fanged, never fetch)
| Indicator | Attacking addresses |
|---|---|
| a8460f446be540410004b1a8db4083773fa46f7fe76fa84219c93daa1669f8f2 | 322 |
| 01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b | 142 |
| e150a1ec81e8e93e1eae2c3a77e66ec6dbd6a3b460f89c1d08aecf422ee401a0 | 111 |
| c05b56ab6d3d07ccca6778ebd799bf98dfa2b7f10dd43601f0938f04e5070878 | 110 |
| 2634c3097f98e36865f0c572009c4ffd73316bc8b88ccfe8d196af35f46e2394 | 109 |
| a883dafc480d466ee04e0d6da986bd78eb1fdd2178d04693723da3a8f95d42f4 | 107 |
| 6d78392a5886177fe5b86e585a0b695a2bcd01a05504b3c4e38bc8eeb21e8326 | 106 |
| 6b3a55e0261b0304143f805a24924d0c1c44524821305f31d9277843b8a10f4e | 105 |
| f33ae3bc9a22cd7564990a794789954409977013966fb1a8f43c35776b833a95 | 101 |
| 5ecf8d2cc410094e8b82dd0bc178a57f3aa1e80916689beb00fe56148b1b1256 | 101 |
| 3c56dd5ed61af7e7b20f54288947a89a4891d181b10fe04560b55c5e82de1fa2 | 101 |
| cc10ba3e72e09f1e742e4155968aa081fd309c76b6acf28eea1e3046438f005e | 100 |
| 53175bcc0524f37b47062fafdda28e3f8eb91d519ca0a184ca71bbebe72f969a | 95 |
| 3b5485dd0909db36922ecd8578f18da11954810e63582f302c10881ac5c47534 | 89 |
| 9d272f1f3e92f7c5efdcfdda0ab92facccd98c340be8be09064060503fd167e4 | 88 |

## ATT&CK techniques
| Tactic | Technique | Name | Events | Agents | Confidence |
|---|---|---|---|---|---|
| Reconnaissance | `T1595.001 ` | Scanning IP Blocks | 286941 | 18 | high |
| Reconnaissance | `T1595.002 ` | Vulnerability Scanning | 19300 | 18 | high |
| Reconnaissance | `T1595.003 ` | Wordlist Scanning | 16793 | 18 | high |
| Reconnaissance | T1594 | Search Victim-Owned Websites | 6191 | 18 | high |
| Initial Access | T1133 | External Remote Services | 110795 | 18 | high |
| Initial Access | T1078 | Valid Accounts | 37440 | 18 | high |
| Initial Access | T1190 | Exploit Public-Facing Application | 3651 | 18 | high |
| Execution | `T1059.004 ` | Unix Shell | 52021 | 18 | high |
| Persistence | `T1053.003 ` | Cron | 7666 | 18 | high |
| Persistence | T1098 | Account Manipulation | 583 | 15 | high |
| Persistence | `T1098.004 ` | SSH Authorized Keys | 440 | 12 | high |
| Stealth | `T1070.004 ` | File Deletion | 8199 | 18 | high |
| Stealth | `T1070.003 ` | Clear Command History | 266 | 18 | high |
| Defense Impairment | `T1222.002 ` | Linux and Mac Permissions | 864 | 18 | high |
| Credential Access | `T1110.001 ` | Password Guessing | 153340 | 18 | high |
| Credential Access | `T1552.001 ` | Credentials In Files | 6526 | 18 | high |
| Discovery | T1082 | System Information Discovery | 26504 | 18 | high |
| Discovery | T1057 | Process Discovery | 7767 | 18 | high |
| Discovery | T1033 | `System Owner/User Discovery ` | 837 | 17 | high |
| Discovery | T1083 | File and Directory Discovery | 515 | 18 | high |
| Discovery | T1016 | System Network Configuration Discovery | 267 | 17 | high |
| Command and Control | T1105 | Ingress Tool Transfer | 19415 | 18 | high |
| Command and Control | T1090 | Proxy | 10673 | 18 | high |
| Impact | `T1496.001 ` | Compute Hijacking | 7366 | 18 | high |

## Recommendations
- Patch or take offline anything affected by CVE-2017-9841 (PHPUnit eval-stdin remote code execution). _1797 attempts on 17 agents in this period, listed by CISA as exploited in the wild._
- Patch or take offline anything affected by CVE-2025-30208 (Vite bypasses server\[.]fs\[.]deny with raw query). _313 attempts on 16 agents in this period._
- Patch or take offline anything affected by CVE-2021-44228 (Log4Shell). _288 attempts on 9 agents in this period, listed by CISA as exploited in the wild, known ransomware use._
- Patch or take offline anything affected by CVE-2020-11547 (PRTG Network Monitor information disclosure). _201 attempts on 13 agents in this period._
- Patch or take offline anything affected by CVE-2021-41773 (Apache httpd path traversal). _166 attempts on 16 agents in this period, listed by CISA as exploited in the wild, known ransomware use._
- Patch or take offline anything affected by CVE-2021-3129 (Laravel Ignition remote code execution). _136 attempts on 1 agents in this period, listed by CISA as exploited in the wild, known ransomware use._
- Patch or take offline anything affected by CVE-2025-31324 (SAP NetWeaver Visual Composer file upload). _115 attempts on 18 agents in this period, listed by CISA as exploited in the wild, known ransomware use._
- Patch or take offline anything affected by CVE-2024-0012 (PAN-OS management web interface authentication bypass). _95 attempts on 18 agents in this period, listed by CISA as exploited in the wild, known ransomware use._
- Patch or take offline anything affected by CVE-2018-13379 (FortiOS SSL VPN file read). _88 attempts on 16 agents in this period, listed by CISA as exploited in the wild, known ransomware use._
- Patch or take offline anything affected by CVE-2026-104935 (Ivanti Connect Secure Authentication Bypass by Spoofing Vulnerability). _84 attempts on 16 agents in this period, listed by CISA as exploited in the wild._

## Method and limits
- Source: decoy services (honeypots) on internet-facing servers. They have no legitimate users, so everything recorded is unsolicited.
- Coverage: untargeted, automated activity. The fleet does not see targeted attacks on your organisation, and it does not observe what happens after a successful break-in.
- Confidence: high = seen by at least half of a multi-agent fleet and by ten or more addresses; medium = several addresses or more than one agent; low = a single agent and few addresses.
- Change is measured against the average of the seven preceding periods of equal length.
- ATT&CK techniques describe what a request attempted. No technique succeeded: decoys never execute what they receive.
- CVE dates and scores: CVE Program. Exploited-in-the-wild status: CISA KEV. Origin countries are where a network is registered, not necessarily where an operator sits.
