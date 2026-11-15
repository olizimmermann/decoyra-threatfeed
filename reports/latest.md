# Threat situation report
Period: last 7 days (2026-11-08 11:08 UTC to 2026-11-15 11:08 UTC) · 16 agents
## Key findings
- **High confidence.** The fleet has less history than this period, so there is no usual level yet: nothing here is called new or rising. _(comparisons start once the fleet has run for 336 hours)_
- **High confidence.** CVE-2017-9841 (PHPUnit eval-stdin remote code execution) is being attempted, a vulnerability CISA lists as exploited in the wild. _(244 attempts on 10 of 16 agents; first seen by the fleet 2 days ago)_
- **High confidence.** CVE-2026-123158 (OpenSSH password authentication bypass (musl libc without PAM)) is being attempted, a vulnerability CISA lists as exploited in the wild. _(124 attempts on 8 of 16 agents; first seen by the fleet 33 hours ago)_
- **High confidence.** CVE-2024-4577 (PHP-CGI argument injection) is being attempted, a vulnerability CISA lists as exploited in the wild and used by ransomware groups. _(37 attempts on 10 of 16 agents; first seen by the fleet 2 days ago)_
- **High confidence.** CVE-2025-31324 (SAP NetWeaver Visual Composer file upload) is being attempted, a vulnerability CISA lists as exploited in the wild and used by ransomware groups. _(29 attempts on 15 of 16 agents; first seen by the fleet 34 hours ago)_
- **High confidence.** The largest campaign uses 48 addresses with the same technique set (git-exposure). _(118 events on 14 of 16 agents)_

## Numbers
| Events | Attacking addresses | High severity | Blocked now | Language-model agents | New patterns |
|---|---|---|---|---|---|
| 1689436 | 13352 | 5722 | 716 | 0 | 10 |

## Known exploits
| CVE | Name | CVSS | CISA | Events | Agents |
|---|---|---|---|---|---|
| CVE-2017-9841 | PHPUnit eval-stdin remote code execution | `9.8 ` | exploited | 244 | 10 |
| CVE-2026-123158 | OpenSSH password authentication bypass (musl libc without PAM) | `n/a ` | exploited | 124 | 8 |
| CVE-2024-4577 | PHP-CGI argument injection | `9.8 ` | exploited, ransomware | 37 | 10 |
| CVE-2025-31324 | SAP NetWeaver Visual Composer file upload | `10.0 ` | exploited, ransomware | 29 | 15 |
| CVE-2021-41773 | Apache httpd path traversal | `7.5 ` | exploited, ransomware | 20 | 10 |
| CVE-2018-13379 | FortiOS SSL VPN file read | `9.1 ` | exploited, ransomware | 16 | 8 |
| CVE-2018-20062 | ThinkPHP remote code execution | `9.8 ` | exploited | 14 | 6 |
| CVE-2018-10561 | GPON router authentication bypass | `9.8 ` | exploited | 11 | 8 |
| CVE-2023-1389 | TP-Link Archer command injection | `8.8 ` | exploited | 4 | 4 |
| CVE-2021-3129 | Laravel Ignition remote code execution | `9.8 ` | exploited, ransomware | 1 | 1 |

## Technologies under attack
| Technology | Events | Change | Agents |
|---|---|---|---|
| ssh | 47456 | no history yet | 16 |
| credential-attack | 43507 | no history yet | 16 |
| rdp | 24127 | no history yet | 16 |
| ssh-shell | 22408 | no history yet | 15 |
| telnet | 17490 | no history yet | 16 |
| ssh-login | 12395 | no history yet | 15 |
| shell-recon | 11184 | no history yet | 15 |
| smb | 8635 | no history yet | 15 |
| mssql | 7214 | no history yet | 15 |
| shell-download | 6207 | no history yet | 15 |
| smb1 | 5211 | no history yet | 15 |
| mysql | 3747 | no history yet | 15 |

## New request patterns
| Pattern | Events | Addresses | Confidence |
|---|---|---|---|
| `SSH-2.0-Go ` | 20869 | 575 | high |
| ssh root | 18972 | 638 | high |
| RDP tls,nla | 10949 | 365 | high |
| `0a07365cc01fa9fc82608ba4019af499 SSH-2.0-Go ` | 7823 | 131 | high |
| `GET / ` | 7699 | 2790 | high |
| `shell-recon > shell-download > shell-recon ` | 7619 | 58 | high |
| (many distinct values from one address) | 7241 | 58 | high |
| ssh admin | 6373 | 312 | high |

## Campaigns
| Techniques | Addresses | Events | Agents |
|---|---|---|---|
| git-exposure | 48 | 118 | 14 |
| admin-panel, iot-router | 29 | 29 | 13 |
| java-spring | 23 | 23 | 15 |
| env-secrets | 22 | 23 | 14 |
| php, wordpress | 22 | 31 | 1 |

## Indicators (de-fanged, never fetch)
| Indicator | Attacking addresses |
|---|---|
| a8460f446be540410004b1a8db4083773fa46f7fe76fa84219c93daa1669f8f2 | 137 |
| e150a1ec81e8e93e1eae2c3a77e66ec6dbd6a3b460f89c1d08aecf422ee401a0 | 65 |
| 2634c3097f98e36865f0c572009c4ffd73316bc8b88ccfe8d196af35f46e2394 | 64 |
| c05b56ab6d3d07ccca6778ebd799bf98dfa2b7f10dd43601f0938f04e5070878 | 64 |
| a883dafc480d466ee04e0d6da986bd78eb1fdd2178d04693723da3a8f95d42f4 | 57 |
| 6b3a55e0261b0304143f805a24924d0c1c44524821305f31d9277843b8a10f4e | 54 |
| 6d78392a5886177fe5b86e585a0b695a2bcd01a05504b3c4e38bc8eeb21e8326 | 53 |
| cc10ba3e72e09f1e742e4155968aa081fd309c76b6acf28eea1e3046438f005e | 49 |
| f33ae3bc9a22cd7564990a794789954409977013966fb1a8f43c35776b833a95 | 48 |
| 3c56dd5ed61af7e7b20f54288947a89a4891d181b10fe04560b55c5e82de1fa2 | 41 |
| `hxxp://103[.]160[.]59[.]94:28816/CZRmrtxnrNONBXhwfFeqjNfBrliNaShG ` | 40 |
| 9ba5884baa8b8a7533446fe7b6b5323d40b4ab1e335dc54a54be1a0a40459b07 | 40 |
| 01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b | 40 |
| 5ecf8d2cc410094e8b82dd0bc178a57f3aa1e80916689beb00fe56148b1b1256 | 39 |
| 3b5485dd0909db36922ecd8578f18da11954810e63582f302c10881ac5c47534 | 35 |

## ATT&CK techniques
| Tactic | Technique | Name | Events | Agents | Confidence |
|---|---|---|---|---|---|
| Reconnaissance | `T1595.001 ` | Scanning IP Blocks | 90102 | 16 | high |
| Reconnaissance | `T1595.002 ` | Vulnerability Scanning | 3657 | 15 | high |
| Reconnaissance | `T1595.003 ` | Wordlist Scanning | 3135 | 16 | high |
| Reconnaissance | T1594 | Search Victim-Owned Websites | 915 | 15 | high |
| Initial Access | T1133 | External Remote Services | 35295 | 16 | high |
| Initial Access | T1078 | Valid Accounts | 12395 | 15 | high |
| Initial Access | T1190 | Exploit Public-Facing Application | 810 | 15 | high |
| Execution | `T1059.004 ` | Unix Shell | 22909 | 15 | high |
| Persistence | `T1053.003 ` | Cron | 2306 | 15 | high |
| Persistence | T1098 | Account Manipulation | 341 | 9 | high |
| Persistence | `T1098.004 ` | SSH Authorized Keys | 244 | 10 | high |
| Stealth | `T1070.004 ` | File Deletion | 2398 | 15 | high |
| Stealth | `T1070.003 ` | Clear Command History | 288 | 15 | high |
| Defense Impairment | `T1222.002 ` | Linux and Mac Permissions | 672 | 15 | high |
| Credential Access | `T1110.001 ` | Password Guessing | 43507 | 16 | high |
| Credential Access | `T1552.001 ` | Credentials In Files | 1387 | 15 | high |
| Discovery | T1082 | System Information Discovery | 11198 | 15 | high |
| Discovery | T1057 | Process Discovery | 2266 | 15 | high |
| Discovery | T1033 | `System Owner/User Discovery ` | 391 | 11 | high |
| Discovery | T1083 | File and Directory Discovery | 193 | 9 | high |
| Discovery | T1016 | System Network Configuration Discovery | 2 | 1 | low |
| Command and Control | T1105 | Ingress Tool Transfer | 7133 | 15 | high |
| Command and Control | T1090 | Proxy | 1854 | 15 | high |
| Impact | `T1496.001 ` | Compute Hijacking | 2115 | 15 | high |

## Recommendations
- Patch or take offline anything affected by CVE-2017-9841 (PHPUnit eval-stdin remote code execution). _244 attempts on 10 agents in this period, listed by CISA as exploited in the wild._
- Patch or take offline anything affected by CVE-2026-123158 (OpenSSH password authentication bypass (musl libc without PAM)). _124 attempts on 8 agents in this period, listed by CISA as exploited in the wild._
- Patch or take offline anything affected by CVE-2024-4577 (PHP-CGI argument injection). _37 attempts on 10 agents in this period, listed by CISA as exploited in the wild, known ransomware use._
- Patch or take offline anything affected by CVE-2025-31324 (SAP NetWeaver Visual Composer file upload). _29 attempts on 15 agents in this period, listed by CISA as exploited in the wild, known ransomware use._
- Patch or take offline anything affected by CVE-2021-41773 (Apache httpd path traversal). _20 attempts on 10 agents in this period, listed by CISA as exploited in the wild, known ransomware use._
- Patch or take offline anything affected by CVE-2018-13379 (FortiOS SSL VPN file read). _16 attempts on 8 agents in this period, listed by CISA as exploited in the wild, known ransomware use._
- Patch or take offline anything affected by CVE-2018-20062 (ThinkPHP remote code execution). _14 attempts on 6 agents in this period, listed by CISA as exploited in the wild._
- Patch or take offline anything affected by CVE-2018-10561 (GPON router authentication bypass). _11 attempts on 8 agents in this period, listed by CISA as exploited in the wild._
- Patch or take offline anything affected by CVE-2023-1389 (TP-Link Archer command injection). _4 attempts on 4 agents in this period, listed by CISA as exploited in the wild._
- Patch or take offline anything affected by CVE-2021-3129 (Laravel Ignition remote code execution). _1 attempts on 1 agents in this period, listed by CISA as exploited in the wild, known ransomware use._

## Method and limits
- Source: decoy services (honeypots) on internet-facing servers. They have no legitimate users, so everything recorded is unsolicited.
- Coverage: untargeted, automated activity. The fleet does not see targeted attacks on your organisation, and it does not observe what happens after a successful break-in.
- Confidence: high = seen by at least half of a multi-agent fleet and by ten or more addresses; medium = several addresses or more than one agent; low = a single agent and few addresses.
- Change is measured against the average of the seven preceding periods of equal length.
- ATT&CK techniques describe what a request attempted. No technique succeeded: decoys never execute what they receive.
- CVE dates and scores: CVE Program. Exploited-in-the-wild status: CISA KEV. Origin countries are where a network is registered, not necessarily where an operator sits.
