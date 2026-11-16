# Threat situation report
Period: last 7 days (2026-11-09 02:49 UTC to 2026-11-16 02:49 UTC) · 17 agents
## Key findings
- **High confidence.** The fleet has less history than this period, so there is no usual level yet: nothing here is called new or rising. _(comparisons start once the fleet has run for 336 hours)_
- **High confidence.** CVE-2017-9841 (PHPUnit eval-stdin remote code execution) is being attempted, a vulnerability CISA lists as exploited in the wild. _(295 attempts on 11 of 17 agents; first seen by the fleet 3 days ago)_
- **High confidence.** CVE-2026-123158 (OpenSSH password authentication bypass (musl libc without PAM)) is being attempted, a vulnerability CISA lists as exploited in the wild. _(128 attempts on 9 of 17 agents; first seen by the fleet 2 days ago)_
- **High confidence.** CVE-2024-4577 (PHP-CGI argument injection) is being attempted, a vulnerability CISA lists as exploited in the wild and used by ransomware groups. _(50 attempts on 11 of 17 agents; first seen by the fleet 3 days ago)_
- **High confidence.** CVE-2025-31324 (SAP NetWeaver Visual Composer file upload) is being attempted, a vulnerability CISA lists as exploited in the wild and used by ransomware groups. _(44 attempts on 15 of 17 agents; first seen by the fleet 2 days ago)_
- **High confidence.** The largest campaign uses 47 addresses with the same technique set (git-exposure). _(163 events on 15 of 17 agents)_

## Numbers
| Events | Attacking addresses | High severity | Blocked now | Language-model agents | New patterns |
|---|---|---|---|---|---|
| 2005446 | 13023 | 5287 | 763 | 0 | 10 |

## Known exploits
| CVE | Name | CVSS | CISA | Events | Agents |
|---|---|---|---|---|---|
| CVE-2017-9841 | PHPUnit eval-stdin remote code execution | `9.8 ` | exploited | 295 | 11 |
| CVE-2026-123158 | OpenSSH password authentication bypass (musl libc without PAM) | `n/a ` | exploited | 128 | 9 |
| CVE-2024-4577 | PHP-CGI argument injection | `9.8 ` | exploited, ransomware | 50 | 11 |
| CVE-2025-31324 | SAP NetWeaver Visual Composer file upload | `10.0 ` | exploited, ransomware | 44 | 15 |
| CVE-2018-13379 | FortiOS SSL VPN file read | `9.1 ` | exploited, ransomware | 36 | 15 |
| CVE-2021-41773 | Apache httpd path traversal | `7.5 ` | exploited, ransomware | 27 | 11 |
| CVE-2018-10561 | GPON router authentication bypass | `9.8 ` | exploited | 15 | 9 |
| CVE-2018-20062 | ThinkPHP remote code execution | `9.8 ` | exploited | 15 | 7 |
| CVE-2023-1389 | TP-Link Archer command injection | `8.8 ` | exploited | 7 | 6 |
| CVE-2022-22965 | Spring4Shell | `9.8 ` | exploited | 6 | 6 |

## Technologies under attack
| Technology | Events | Change | Agents |
|---|---|---|---|
| ssh | 60195 | no history yet | 17 |
| credential-attack | 56932 | no history yet | 17 |
| rdp | 28116 | no history yet | 17 |
| ssh-shell | 27271 | no history yet | 16 |
| telnet | 22299 | no history yet | 17 |
| ssh-login | 15864 | no history yet | 16 |
| shell-recon | 14098 | no history yet | 16 |
| mssql | 11854 | no history yet | 16 |
| smb | 11463 | no history yet | 16 |
| shell-download | 8282 | no history yet | 16 |
| smb1 | 6737 | no history yet | 16 |
| mysql | 4821 | no history yet | 16 |

## New request patterns
| Pattern | Events | Addresses | Confidence |
|---|---|---|---|
| `SSH-2.0-Go ` | 25733 | 674 | high |
| ssh root | 23518 | 758 | high |
| RDP tls,nla | 12378 | 477 | high |
| `shell-recon > shell-download > shell-recon ` | 11127 | 72 | high |
| `GET / ` | 10776 | 3690 | high |
| `0a07365cc01fa9fc82608ba4019af499 SSH-2.0-Go ` | 10230 | 143 | high |
| ssh admin | 8436 | 364 | high |
| (many distinct values from one address) | 8292 | 65 | high |

## Campaigns
| Techniques | Addresses | Events | Agents |
|---|---|---|---|
| git-exposure | 47 | 163 | 15 |
| admin-panel, iot-router | 31 | 31 | 12 |
| env-secrets | 27 | 30 | 15 |
| php, wordpress | 18 | 22 | 1 |
| command-injection | 17 | 17 | 11 |

## Indicators (de-fanged, never fetch)
| Indicator | Attacking addresses |
|---|---|
| a8460f446be540410004b1a8db4083773fa46f7fe76fa84219c93daa1669f8f2 | 164 |
| e150a1ec81e8e93e1eae2c3a77e66ec6dbd6a3b460f89c1d08aecf422ee401a0 | 78 |
| 2634c3097f98e36865f0c572009c4ffd73316bc8b88ccfe8d196af35f46e2394 | 77 |
| c05b56ab6d3d07ccca6778ebd799bf98dfa2b7f10dd43601f0938f04e5070878 | 76 |
| a883dafc480d466ee04e0d6da986bd78eb1fdd2178d04693723da3a8f95d42f4 | 70 |
| 6d78392a5886177fe5b86e585a0b695a2bcd01a05504b3c4e38bc8eeb21e8326 | 67 |
| 6b3a55e0261b0304143f805a24924d0c1c44524821305f31d9277843b8a10f4e | 66 |
| cc10ba3e72e09f1e742e4155968aa081fd309c76b6acf28eea1e3046438f005e | 59 |
| f33ae3bc9a22cd7564990a794789954409977013966fb1a8f43c35776b833a95 | 56 |
| 3c56dd5ed61af7e7b20f54288947a89a4891d181b10fe04560b55c5e82de1fa2 | 55 |
| 5ecf8d2cc410094e8b82dd0bc178a57f3aa1e80916689beb00fe56148b1b1256 | 52 |
| 01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b | 49 |
| 3b5485dd0909db36922ecd8578f18da11954810e63582f302c10881ac5c47534 | 45 |
| 9d272f1f3e92f7c5efdcfdda0ab92facccd98c340be8be09064060503fd167e4 | 44 |
| 53175bcc0524f37b47062fafdda28e3f8eb91d519ca0a184ca71bbebe72f969a | 42 |

## ATT&CK techniques
| Tactic | Technique | Name | Events | Agents | Confidence |
|---|---|---|---|---|---|
| Reconnaissance | `T1595.001 ` | Scanning IP Blocks | 115068 | 17 | high |
| Reconnaissance | `T1595.003 ` | Wordlist Scanning | 5534 | 17 | high |
| Reconnaissance | `T1595.002 ` | Vulnerability Scanning | 5087 | 16 | high |
| Reconnaissance | T1594 | Search Victim-Owned Websites | 1496 | 16 | high |
| Initial Access | T1133 | External Remote Services | 44145 | 17 | high |
| Initial Access | T1078 | Valid Accounts | 15874 | 16 | high |
| Initial Access | T1190 | Exploit Public-Facing Application | 1065 | 16 | high |
| Execution | `T1059.004 ` | Unix Shell | 27924 | 16 | high |
| Persistence | `T1053.003 ` | Cron | 3103 | 16 | high |
| Persistence | T1098 | Account Manipulation | 431 | 10 | high |
| Persistence | `T1098.004 ` | SSH Authorized Keys | 292 | 10 | high |
| Stealth | `T1070.004 ` | File Deletion | 3238 | 16 | high |
| Stealth | `T1070.003 ` | Clear Command History | 300 | 16 | high |
| Defense Impairment | `T1222.002 ` | Linux and Mac Permissions | 783 | 16 | high |
| Credential Access | `T1110.001 ` | Password Guessing | 56932 | 17 | high |
| Credential Access | `T1552.001 ` | Credentials In Files | 2798 | 16 | high |
| Discovery | T1082 | System Information Discovery | 14102 | 16 | high |
| Discovery | T1057 | Process Discovery | 3083 | 16 | high |
| Discovery | T1033 | `System Owner/User Discovery ` | 491 | 13 | high |
| Discovery | T1083 | File and Directory Discovery | 255 | 12 | high |
| Discovery | T1016 | System Network Configuration Discovery | 9 | 5 | medium |
| Command and Control | T1105 | Ingress Tool Transfer | 9405 | 16 | high |
| Command and Control | T1090 | Proxy | 2713 | 16 | high |
| Impact | `T1496.001 ` | Compute Hijacking | 2865 | 16 | high |

## Recommendations
- Patch or take offline anything affected by CVE-2017-9841 (PHPUnit eval-stdin remote code execution). _295 attempts on 11 agents in this period, listed by CISA as exploited in the wild._
- Patch or take offline anything affected by CVE-2026-123158 (OpenSSH password authentication bypass (musl libc without PAM)). _128 attempts on 9 agents in this period, listed by CISA as exploited in the wild._
- Patch or take offline anything affected by CVE-2024-4577 (PHP-CGI argument injection). _50 attempts on 11 agents in this period, listed by CISA as exploited in the wild, known ransomware use._
- Patch or take offline anything affected by CVE-2025-31324 (SAP NetWeaver Visual Composer file upload). _44 attempts on 15 agents in this period, listed by CISA as exploited in the wild, known ransomware use._
- Patch or take offline anything affected by CVE-2018-13379 (FortiOS SSL VPN file read). _36 attempts on 15 agents in this period, listed by CISA as exploited in the wild, known ransomware use._
- Patch or take offline anything affected by CVE-2021-41773 (Apache httpd path traversal). _27 attempts on 11 agents in this period, listed by CISA as exploited in the wild, known ransomware use._
- Patch or take offline anything affected by CVE-2018-10561 (GPON router authentication bypass). _15 attempts on 9 agents in this period, listed by CISA as exploited in the wild._
- Patch or take offline anything affected by CVE-2018-20062 (ThinkPHP remote code execution). _15 attempts on 7 agents in this period, listed by CISA as exploited in the wild._
- Patch or take offline anything affected by CVE-2023-1389 (TP-Link Archer command injection). _7 attempts on 6 agents in this period, listed by CISA as exploited in the wild._
- Patch or take offline anything affected by CVE-2022-22965 (Spring4Shell). _6 attempts on 6 agents in this period, listed by CISA as exploited in the wild._

## Method and limits
- Source: decoy services (honeypots) on internet-facing servers. They have no legitimate users, so everything recorded is unsolicited.
- Coverage: untargeted, automated activity. The fleet does not see targeted attacks on your organisation, and it does not observe what happens after a successful break-in.
- Confidence: high = seen by at least half of a multi-agent fleet and by ten or more addresses; medium = several addresses or more than one agent; low = a single agent and few addresses.
- Change is measured against the average of the seven preceding periods of equal length.
- ATT&CK techniques describe what a request attempted. No technique succeeded: decoys never execute what they receive.
- CVE dates and scores: CVE Program. Exploited-in-the-wild status: CISA KEV. Origin countries are where a network is registered, not necessarily where an operator sits.
