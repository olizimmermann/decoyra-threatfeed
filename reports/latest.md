# Threat situation report
Period: last 7 days (2026-11-14 11:19 UTC to 2026-11-21 11:19 UTC) · 18 agents
## Key findings
- **High confidence.** The fleet has less history than this period, so there is no usual level yet: nothing here is called new or rising. _(comparisons start once the fleet has run for 336 hours)_
- **High confidence.** CVE-2017-9841 (PHPUnit eval-stdin remote code execution) is being attempted, a vulnerability CISA lists as exploited in the wild. _(1794 attempts on 16 of 18 agents; first seen by the fleet 8 days ago)_
- **High confidence.** CVE-2026-104935 (Ivanti Connect Secure Authentication Bypass by Spoofing Vulnerability) is being attempted, a vulnerability CISA lists as exploited in the wild. _(194 attempts on 16 of 18 agents; first seen by the fleet 7 days ago)_
- **High confidence.** CVE-2026-123158 (OpenSSH password authentication bypass (musl libc without PAM)) is being attempted, a vulnerability CISA lists as exploited in the wild. _(147 attempts on 13 of 18 agents; first seen by the fleet 7 days ago)_
- **Medium confidence.** CVE-2021-3129 (Laravel Ignition remote code execution) is being attempted, a vulnerability CISA lists as exploited in the wild and used by ransomware groups. _(137 attempts on 2 of 18 agents; first seen by the fleet 6 days ago)_
- **High confidence.** The largest campaign uses 135 addresses with the same technique set (admin-panel, iot-router). _(278 events on 18 of 18 agents)_

## Numbers
| Events | Attacking addresses | High severity | Blocked now | Language-model agents | New patterns |
|---|---|---|---|---|---|
| 6905499 | 32717 | 23345 | 808 | 0 | 10 |

## Known exploits
| CVE | Name | CVSS | CISA | Events | Agents |
|---|---|---|---|---|---|
| CVE-2017-9841 | PHPUnit eval-stdin remote code execution | `9.8 ` | exploited | 1794 | 16 |
| CVE-2026-104935 | Ivanti Connect Secure Authentication Bypass by Spoofing Vulnerability | `n/a ` | exploited | 194 | 16 |
| CVE-2026-123158 | OpenSSH password authentication bypass (musl libc without PAM) | `8.1 ` | exploited | 147 | 13 |
| CVE-2021-3129 | Laravel Ignition remote code execution | `9.8 ` | exploited, ransomware | 137 | 2 |
| CVE-2025-31324 | SAP NetWeaver Visual Composer file upload | `10.0 ` | exploited, ransomware | 130 | 18 |
| CVE-2021-41773 | Apache httpd path traversal | `7.5 ` | exploited, ransomware | 114 | 16 |
| CVE-2021-44228 | Log4Shell | `10.0 ` | exploited, ransomware | 100 | 8 |
| CVE-2024-0012 | PAN-OS management web interface authentication bypass | `n/a ` | exploited, ransomware | 99 | 18 |
| CVE-2018-13379 | FortiOS SSL VPN file read | `9.1 ` | exploited, ransomware | 94 | 16 |
| CVE-2024-4577 | PHP-CGI argument injection | `9.8 ` | exploited, ransomware | 82 | 14 |

## Technologies under attack
| Technology | Events | Change | Agents |
|---|---|---|---|
| credential-attack | 151626 | no history yet | 18 |
| ssh | 151546 | no history yet | 18 |
| ssh-shell | 51833 | no history yet | 18 |
| rdp | 50354 | no history yet | 18 |
| telnet | 48059 | no history yet | 18 |
| smb | 45242 | no history yet | 18 |
| mssql | 39880 | no history yet | 18 |
| ssh-login | 36994 | no history yet | 18 |
| smb1 | 29669 | no history yet | 18 |
| shell-recon | 26349 | no history yet | 18 |
| shell-download | 16980 | no history yet | 18 |
| mysql | 12740 | no history yet | 18 |

## New request patterns
| Pattern | Events | Addresses | Confidence |
|---|---|---|---|
| `Mozilla/{v} (compatible; AhrefsBot/{v}; +http://ahrefs.com/robot/) ` | 26537 | 614 | medium |
| mssql Admin | 1663 | 7 | medium |
| telnet chinadsl-net | 1460 | 4 | medium |
| telnet bin | 1439 | 6 | medium |
| telnet vstarcam2015 | 1426 | 7 | medium |
| telnet router | 1419 | 5 | medium |
| `CONNECT {n}.{n}.{n}.{n}:{n} ` | 1367 | 38 | high |
| redis default | 1281 | 84 | high |

## Campaigns
| Techniques | Addresses | Events | Agents |
|---|---|---|---|
| admin-panel, iot-router | 135 | 278 | 18 |
| CVE-2025-31324 | 94 | 97 | 18 |
| admin-panel, iot-router | 72 | 74 | 18 |
| env-secrets | 69 | 98 | 18 |
| java-spring | 60 | 62 | 18 |

## Indicators (de-fanged, never fetch)
| Indicator | Attacking addresses |
|---|---|
| a8460f446be540410004b1a8db4083773fa46f7fe76fa84219c93daa1669f8f2 | 320 |
| 01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b | 140 |
| e150a1ec81e8e93e1eae2c3a77e66ec6dbd6a3b460f89c1d08aecf422ee401a0 | 110 |
| 2634c3097f98e36865f0c572009c4ffd73316bc8b88ccfe8d196af35f46e2394 | 108 |
| c05b56ab6d3d07ccca6778ebd799bf98dfa2b7f10dd43601f0938f04e5070878 | 107 |
| a883dafc480d466ee04e0d6da986bd78eb1fdd2178d04693723da3a8f95d42f4 | 105 |
| 6d78392a5886177fe5b86e585a0b695a2bcd01a05504b3c4e38bc8eeb21e8326 | 104 |
| 6b3a55e0261b0304143f805a24924d0c1c44524821305f31d9277843b8a10f4e | 102 |
| cc10ba3e72e09f1e742e4155968aa081fd309c76b6acf28eea1e3046438f005e | 99 |
| 3c56dd5ed61af7e7b20f54288947a89a4891d181b10fe04560b55c5e82de1fa2 | 99 |
| f33ae3bc9a22cd7564990a794789954409977013966fb1a8f43c35776b833a95 | 96 |
| 5ecf8d2cc410094e8b82dd0bc178a57f3aa1e80916689beb00fe56148b1b1256 | 95 |
| 53175bcc0524f37b47062fafdda28e3f8eb91d519ca0a184ca71bbebe72f969a | 92 |
| 3b5485dd0909db36922ecd8578f18da11954810e63582f302c10881ac5c47534 | 82 |
| 9d272f1f3e92f7c5efdcfdda0ab92facccd98c340be8be09064060503fd167e4 | 79 |

## ATT&CK techniques
| Tactic | Technique | Name | Events | Agents | Confidence |
|---|---|---|---|---|---|
| Reconnaissance | `T1595.001 ` | Scanning IP Blocks | 286734 | 18 | high |
| Reconnaissance | `T1595.002 ` | Vulnerability Scanning | 19773 | 18 | high |
| Reconnaissance | `T1595.003 ` | Wordlist Scanning | 16866 | 18 | high |
| Reconnaissance | T1594 | Search Victim-Owned Websites | 6342 | 18 | high |
| Initial Access | T1133 | External Remote Services | 110232 | 18 | high |
| Initial Access | T1078 | Valid Accounts | 37013 | 18 | high |
| Initial Access | T1190 | Exploit Public-Facing Application | 3428 | 18 | high |
| Execution | `T1059.004 ` | Unix Shell | 52776 | 18 | high |
| Persistence | `T1053.003 ` | Cron | 7346 | 18 | high |
| Persistence | T1098 | Account Manipulation | 718 | 15 | high |
| Persistence | `T1098.004 ` | SSH Authorized Keys | 514 | 11 | high |
| Stealth | `T1070.004 ` | File Deletion | 7887 | 18 | high |
| Stealth | `T1070.003 ` | Clear Command History | 317 | 17 | high |
| Defense Impairment | `T1222.002 ` | Linux and Mac Permissions | 1069 | 18 | high |
| Credential Access | `T1110.001 ` | Password Guessing | 151626 | 18 | high |
| Credential Access | `T1552.001 ` | Credentials In Files | 6657 | 18 | high |
| Discovery | T1082 | System Information Discovery | 26230 | 18 | high |
| Discovery | T1057 | Process Discovery | 7442 | 18 | high |
| Discovery | T1033 | `System Owner/User Discovery ` | 987 | 17 | high |
| Discovery | T1083 | File and Directory Discovery | 586 | 18 | high |
| Discovery | T1016 | System Network Configuration Discovery | 265 | 17 | high |
| Command and Control | T1105 | Ingress Tool Transfer | 18936 | 18 | high |
| Command and Control | T1090 | Proxy | 10995 | 18 | high |
| Impact | `T1496.001 ` | Compute Hijacking | 6971 | 18 | high |

## Recommendations
- Patch or take offline anything affected by CVE-2017-9841 (PHPUnit eval-stdin remote code execution). _1794 attempts on 16 agents in this period, listed by CISA as exploited in the wild._
- Patch or take offline anything affected by CVE-2026-104935 (Ivanti Connect Secure Authentication Bypass by Spoofing Vulnerability). _194 attempts on 16 agents in this period, listed by CISA as exploited in the wild._
- Patch or take offline anything affected by CVE-2026-123158 (OpenSSH password authentication bypass (musl libc without PAM)). _147 attempts on 13 agents in this period, listed by CISA as exploited in the wild._
- Patch or take offline anything affected by CVE-2021-3129 (Laravel Ignition remote code execution). _137 attempts on 2 agents in this period, listed by CISA as exploited in the wild, known ransomware use._
- Patch or take offline anything affected by CVE-2025-31324 (SAP NetWeaver Visual Composer file upload). _130 attempts on 18 agents in this period, listed by CISA as exploited in the wild, known ransomware use._
- Patch or take offline anything affected by CVE-2021-41773 (Apache httpd path traversal). _114 attempts on 16 agents in this period, listed by CISA as exploited in the wild, known ransomware use._
- Patch or take offline anything affected by CVE-2021-44228 (Log4Shell). _100 attempts on 8 agents in this period, listed by CISA as exploited in the wild, known ransomware use._
- Patch or take offline anything affected by CVE-2024-0012 (PAN-OS management web interface authentication bypass). _99 attempts on 18 agents in this period, listed by CISA as exploited in the wild, known ransomware use._
- Patch or take offline anything affected by CVE-2018-13379 (FortiOS SSL VPN file read). _94 attempts on 16 agents in this period, listed by CISA as exploited in the wild, known ransomware use._
- Patch or take offline anything affected by CVE-2024-4577 (PHP-CGI argument injection). _82 attempts on 14 agents in this period, listed by CISA as exploited in the wild, known ransomware use._

## Method and limits
- Source: decoy services (honeypots) on internet-facing servers. They have no legitimate users, so everything recorded is unsolicited.
- Coverage: untargeted, automated activity. The fleet does not see targeted attacks on your organisation, and it does not observe what happens after a successful break-in.
- Confidence: high = seen by at least half of a multi-agent fleet and by ten or more addresses; medium = several addresses or more than one agent; low = a single agent and few addresses.
- Change is measured against the average of the seven preceding periods of equal length.
- ATT&CK techniques describe what a request attempted. No technique succeeded: decoys never execute what they receive.
- CVE dates and scores: CVE Program. Exploited-in-the-wild status: CISA KEV. Origin countries are where a network is registered, not necessarily where an operator sits.
