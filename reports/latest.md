# Threat situation report
Period: last 7 days (2026-11-09 11:38 UTC to 2026-11-16 11:38 UTC) · 17 agents
## Key findings
- **High confidence.** The fleet has less history than this period, so there is no usual level yet: nothing here is called new or rising. _(comparisons start once the fleet has run for 336 hours)_
- **High confidence.** CVE-2017-9841 (PHPUnit eval-stdin remote code execution) is being attempted, a vulnerability CISA lists as exploited in the wild. _(299 attempts on 11 of 17 agents; first seen by the fleet 3 days ago)_
- **High confidence.** CVE-2026-104935 (Ivanti Connect Secure Authentication Bypass by Spoofing Vulnerability) is being attempted, a vulnerability CISA lists as exploited in the wild. _(147 attempts on 16 of 17 agents; first seen by the fleet 2 days ago)_
- **High confidence.** CVE-2026-123158 (OpenSSH password authentication bypass (musl libc without PAM)) is being attempted, a vulnerability CISA lists as exploited in the wild. _(128 attempts on 9 of 17 agents; first seen by the fleet 2 days ago)_
- **High confidence.** CVE-2024-4577 (PHP-CGI argument injection) is being attempted, a vulnerability CISA lists as exploited in the wild and used by ransomware groups. _(52 attempts on 11 of 17 agents; first seen by the fleet 3 days ago)_
- **High confidence.** The largest campaign uses 46 addresses with the same technique set (git-exposure). _(165 events on 15 of 17 agents)_

## Numbers
| Events | Attacking addresses | High severity | Blocked now | Language-model agents | New patterns |
|---|---|---|---|---|---|
| 2207169 | 13141 | 5326 | 813 | 0 | 10 |

## Known exploits
| CVE | Name | CVSS | CISA | Events | Agents |
|---|---|---|---|---|---|
| CVE-2017-9841 | PHPUnit eval-stdin remote code execution | `9.8 ` | exploited | 299 | 11 |
| CVE-2026-104935 | Ivanti Connect Secure Authentication Bypass by Spoofing Vulnerability | `n/a ` | exploited | 147 | 16 |
| CVE-2026-123158 | OpenSSH password authentication bypass (musl libc without PAM) | `8.1 ` | exploited | 128 | 9 |
| CVE-2024-4577 | PHP-CGI argument injection | `9.8 ` | exploited, ransomware | 52 | 11 |
| CVE-2018-13379 | FortiOS SSL VPN file read | `9.1 ` | exploited, ransomware | 46 | 16 |
| CVE-2026-96652 | Plex Media Server Server-Side Request Forgery (SSRF) Vulnerability | `n/a ` | exploited | 45 | 15 |
| CVE-2025-31324 | SAP NetWeaver Visual Composer file upload | `10.0 ` | exploited, ransomware | 44 | 15 |
| CVE-2021-41773 | Apache httpd path traversal | `7.5 ` | exploited, ransomware | 30 | 13 |
| CVE-2018-10561 | GPON router authentication bypass | `9.8 ` | exploited | 16 | 10 |
| CVE-2018-20062 | ThinkPHP remote code execution | `9.8 ` | exploited | 15 | 7 |

## Technologies under attack
| Technology | Events | Change | Agents |
|---|---|---|---|
| ssh | 67735 | no history yet | 17 |
| credential-attack | 64445 | no history yet | 17 |
| rdp | 31570 | no history yet | 17 |
| ssh-shell | 30524 | no history yet | 16 |
| telnet | 25138 | no history yet | 17 |
| ssh-login | 17907 | no history yet | 16 |
| shell-recon | 15770 | no history yet | 16 |
| smb | 14092 | no history yet | 16 |
| mssql | 14018 | no history yet | 16 |
| shell-download | 9306 | no history yet | 16 |
| smb1 | 8524 | no history yet | 16 |
| mysql | 5490 | no history yet | 16 |

## New request patterns
| Pattern | Events | Addresses | Confidence |
|---|---|---|---|
| `SSH-2.0-Go ` | 28461 | 742 | high |
| ssh root | 26287 | 837 | high |
| RDP tls,nla | 14336 | 533 | high |
| `shell-recon > shell-download > shell-recon ` | 13055 | 76 | high |
| `GET / ` | 12921 | 4186 | high |
| `0a07365cc01fa9fc82608ba4019af499 SSH-2.0-Go ` | 11392 | 149 | high |
| ssh admin | 9581 | 397 | high |
| (many distinct values from one address) | 9340 | 71 | high |

## Campaigns
| Techniques | Addresses | Events | Agents |
|---|---|---|---|
| git-exposure | 46 | 165 | 15 |
| admin-panel, iot-router | 30 | 30 | 11 |
| env-secrets | 27 | 32 | 15 |
| env-secrets, git-exposure, java-spring | 23 | 550 | 15 |
| vpn-gateway | 22 | 44 | 15 |

## Indicators (de-fanged, never fetch)
| Indicator | Attacking addresses |
|---|---|
| a8460f446be540410004b1a8db4083773fa46f7fe76fa84219c93daa1669f8f2 | 185 |
| e150a1ec81e8e93e1eae2c3a77e66ec6dbd6a3b460f89c1d08aecf422ee401a0 | 82 |
| c05b56ab6d3d07ccca6778ebd799bf98dfa2b7f10dd43601f0938f04e5070878 | 82 |
| 2634c3097f98e36865f0c572009c4ffd73316bc8b88ccfe8d196af35f46e2394 | 81 |
| a883dafc480d466ee04e0d6da986bd78eb1fdd2178d04693723da3a8f95d42f4 | 74 |
| 6d78392a5886177fe5b86e585a0b695a2bcd01a05504b3c4e38bc8eeb21e8326 | 71 |
| 6b3a55e0261b0304143f805a24924d0c1c44524821305f31d9277843b8a10f4e | 71 |
| cc10ba3e72e09f1e742e4155968aa081fd309c76b6acf28eea1e3046438f005e | 63 |
| 3c56dd5ed61af7e7b20f54288947a89a4891d181b10fe04560b55c5e82de1fa2 | 61 |
| f33ae3bc9a22cd7564990a794789954409977013966fb1a8f43c35776b833a95 | 60 |
| 01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b | 58 |
| 5ecf8d2cc410094e8b82dd0bc178a57f3aa1e80916689beb00fe56148b1b1256 | 57 |
| 3b5485dd0909db36922ecd8578f18da11954810e63582f302c10881ac5c47534 | 51 |
| 53175bcc0524f37b47062fafdda28e3f8eb91d519ca0a184ca71bbebe72f969a | 48 |
| 9d272f1f3e92f7c5efdcfdda0ab92facccd98c340be8be09064060503fd167e4 | 45 |

## ATT&CK techniques
| Tactic | Technique | Name | Events | Agents | Confidence |
|---|---|---|---|---|---|
| Reconnaissance | `T1595.001 ` | Scanning IP Blocks | 131568 | 17 | high |
| Reconnaissance | `T1595.003 ` | Wordlist Scanning | 6871 | 17 | high |
| Reconnaissance | `T1595.002 ` | Vulnerability Scanning | 6067 | 16 | high |
| Reconnaissance | T1594 | Search Victim-Owned Websites | 1904 | 16 | high |
| Initial Access | T1133 | External Remote Services | 49447 | 17 | high |
| Initial Access | T1078 | Valid Accounts | 17917 | 16 | high |
| Initial Access | T1190 | Exploit Public-Facing Application | 1165 | 16 | high |
| Execution | `T1059.004 ` | Unix Shell | 31251 | 16 | high |
| Persistence | `T1053.003 ` | Cron | 3510 | 16 | high |
| Persistence | T1098 | Account Manipulation | 504 | 12 | high |
| Persistence | `T1098.004 ` | SSH Authorized Keys | 324 | 11 | high |
| Stealth | `T1070.004 ` | File Deletion | 3720 | 16 | high |
| Stealth | `T1070.003 ` | Clear Command History | 305 | 16 | high |
| Defense Impairment | `T1222.002 ` | Linux and Mac Permissions | 853 | 16 | high |
| Credential Access | `T1110.001 ` | Password Guessing | 64445 | 17 | high |
| Credential Access | `T1552.001 ` | Credentials In Files | 3526 | 16 | high |
| Discovery | T1082 | System Information Discovery | 15689 | 16 | high |
| Discovery | T1057 | Process Discovery | 3529 | 16 | high |
| Discovery | T1033 | `System Owner/User Discovery ` | 618 | 14 | high |
| Discovery | T1083 | File and Directory Discovery | 342 | 16 | high |
| Discovery | T1016 | System Network Configuration Discovery | 121 | 11 | high |
| Command and Control | T1105 | Ingress Tool Transfer | 10526 | 16 | high |
| Command and Control | T1090 | Proxy | 3207 | 16 | high |
| Impact | `T1496.001 ` | Compute Hijacking | 3241 | 16 | high |

## Recommendations
- Patch or take offline anything affected by CVE-2017-9841 (PHPUnit eval-stdin remote code execution). _299 attempts on 11 agents in this period, listed by CISA as exploited in the wild._
- Patch or take offline anything affected by CVE-2026-104935 (Ivanti Connect Secure Authentication Bypass by Spoofing Vulnerability). _147 attempts on 16 agents in this period, listed by CISA as exploited in the wild._
- Patch or take offline anything affected by CVE-2026-123158 (OpenSSH password authentication bypass (musl libc without PAM)). _128 attempts on 9 agents in this period, listed by CISA as exploited in the wild._
- Patch or take offline anything affected by CVE-2024-4577 (PHP-CGI argument injection). _52 attempts on 11 agents in this period, listed by CISA as exploited in the wild, known ransomware use._
- Patch or take offline anything affected by CVE-2018-13379 (FortiOS SSL VPN file read). _46 attempts on 16 agents in this period, listed by CISA as exploited in the wild, known ransomware use._
- Patch or take offline anything affected by CVE-2026-96652 (Plex Media Server Server-Side Request Forgery (SSRF) Vulnerability). _45 attempts on 15 agents in this period, listed by CISA as exploited in the wild._
- Patch or take offline anything affected by CVE-2025-31324 (SAP NetWeaver Visual Composer file upload). _44 attempts on 15 agents in this period, listed by CISA as exploited in the wild, known ransomware use._
- Patch or take offline anything affected by CVE-2021-41773 (Apache httpd path traversal). _30 attempts on 13 agents in this period, listed by CISA as exploited in the wild, known ransomware use._
- Patch or take offline anything affected by CVE-2018-10561 (GPON router authentication bypass). _16 attempts on 10 agents in this period, listed by CISA as exploited in the wild._
- Patch or take offline anything affected by CVE-2018-20062 (ThinkPHP remote code execution). _15 attempts on 7 agents in this period, listed by CISA as exploited in the wild._

## Method and limits
- Source: decoy services (honeypots) on internet-facing servers. They have no legitimate users, so everything recorded is unsolicited.
- Coverage: untargeted, automated activity. The fleet does not see targeted attacks on your organisation, and it does not observe what happens after a successful break-in.
- Confidence: high = seen by at least half of a multi-agent fleet and by ten or more addresses; medium = several addresses or more than one agent; low = a single agent and few addresses.
- Change is measured against the average of the seven preceding periods of equal length.
- ATT&CK techniques describe what a request attempted. No technique succeeded: decoys never execute what they receive.
- CVE dates and scores: CVE Program. Exploited-in-the-wild status: CISA KEV. Origin countries are where a network is registered, not necessarily where an operator sits.
