# Threat situation report
Period: last 7 days (2026-11-07 10:35 UTC to 2026-11-14 10:35 UTC) · 16 agents
## Key findings
- **High confidence.** The fleet has less history than this period, so there is no usual level yet: nothing here is called new or rising. _(comparisons start once the fleet has run for 336 hours)_
- **Medium confidence.** CVE-2017-9841 (PHPUnit eval-stdin remote code execution) is being attempted, a vulnerability CISA lists as exploited in the wild. _(161 attempts on 7 of 16 agents; first seen by the fleet 24 hours ago)_
- **High confidence.** CVE-2024-4577 (PHP-CGI argument injection) is being attempted, a vulnerability CISA lists as exploited in the wild and used by ransomware groups. _(23 attempts on 8 of 16 agents; first seen by the fleet 31 hours ago)_
- **High confidence.** CVE-2025-31324 (SAP NetWeaver Visual Composer file upload) is being attempted, a vulnerability CISA lists as exploited in the wild and used by ransomware groups. _(14 attempts on 14 of 16 agents; first seen by the fleet 10 hours ago)_
- **High confidence.** CVE-2021-41773 (Apache httpd path traversal) is being attempted, a vulnerability CISA lists as exploited in the wild and used by ransomware groups. _(13 attempts on 8 of 16 agents; first seen by the fleet 31 hours ago)_
- **High confidence.** The largest campaign uses 24 addresses with the same technique set (git-exposure). _(42 events on 10 of 16 agents)_

## Numbers
| Events | Attacking addresses | High severity | Blocked now | Language-model agents | New patterns |
|---|---|---|---|---|---|
| 611863 | 7985 | 2864 | 697 | 0 | 10 |

## Known exploits
| CVE | Name | CVSS | CISA | Events | Agents |
|---|---|---|---|---|---|
| CVE-2017-9841 | PHPUnit eval-stdin remote code execution | `9.8 ` | exploited | 161 | 7 |
| CVE-2024-4577 | PHP-CGI argument injection | `9.8 ` | exploited, ransomware | 23 | 8 |
| CVE-2025-31324 | SAP NetWeaver Visual Composer file upload | `10.0 ` | exploited, ransomware | 14 | 14 |
| CVE-2021-41773 | Apache httpd path traversal | `7.5 ` | exploited, ransomware | 13 | 8 |
| CVE-2018-20062 | ThinkPHP remote code execution | `9.8 ` | exploited | 11 | 5 |
| CVE-2018-13379 | FortiOS SSL VPN file read | `9.1 ` | exploited, ransomware | 8 | 4 |
| CVE-2018-10561 | GPON router authentication bypass | `9.8 ` | exploited | 2 | 2 |
| CVE-2026-123158 | OpenSSH password authentication bypass (musl libc without PAM) | `n/a ` | exploited | 1 | 1 |

## Technologies under attack
| Technology | Events | Change | Agents |
|---|---|---|---|
| ssh | 26300 | no history yet | 16 |
| credential-attack | 21557 | no history yet | 16 |
| rdp | 14393 | no history yet | 16 |
| ssh-shell | 13212 | no history yet | 15 |
| telnet | 11926 | no history yet | 16 |
| ssh-login | 6964 | no history yet | 15 |
| shell-recon | 6549 | no history yet | 15 |
| shell-download | 3643 | no history yet | 15 |
| smb | 3577 | no history yet | 15 |
| smb1 | 2133 | no history yet | 15 |
| mysql | 2081 | no history yet | 15 |
| redis | 1846 | no history yet | 15 |

## New request patterns
| Pattern | Events | Addresses | Confidence |
|---|---|---|---|
| `SSH-2.0-Go ` | 12338 | 396 | high |
| ssh root | 10958 | 416 | high |
| RDP tls,nla | 4813 | 167 | high |
| `0a07365cc01fa9fc82608ba4019af499 SSH-2.0-Go ` | 4761 | 101 | high |
| (many distinct values from one address) | 4280 | 44 | high |
| uname -s -v -n -r -m | 3647 | 82 | high |
| nproc | 3497 | 43 | high |
| `uname -m \| awk '{printf $1}' ` | 3494 | 42 | high |

## Campaigns
| Techniques | Addresses | Events | Agents |
|---|---|---|---|
| git-exposure | 24 | 42 | 10 |
| php, wordpress | 15 | 18 | 1 |
| admin-panel, iot-router | 14 | 14 | 10 |
| env-secrets | 11 | 86 | 15 |
| admin-panel, php | 10 | 58 | 13 |

## Indicators (de-fanged, never fetch)
| Indicator | Attacking addresses |
|---|---|
| a8460f446be540410004b1a8db4083773fa46f7fe76fa84219c93daa1669f8f2 | 70 |
| e150a1ec81e8e93e1eae2c3a77e66ec6dbd6a3b460f89c1d08aecf422ee401a0 | 40 |
| c05b56ab6d3d07ccca6778ebd799bf98dfa2b7f10dd43601f0938f04e5070878 | 40 |
| 2634c3097f98e36865f0c572009c4ffd73316bc8b88ccfe8d196af35f46e2394 | 39 |
| `hxxp://103[.]160[.]59[.]94:28816/CZRmrtxnrNONBXhwfFeqjNfBrliNaShG ` | 38 |
| 9ba5884baa8b8a7533446fe7b6b5323d40b4ab1e335dc54a54be1a0a40459b07 | 38 |
| a883dafc480d466ee04e0d6da986bd78eb1fdd2178d04693723da3a8f95d42f4 | 36 |
| 6d78392a5886177fe5b86e585a0b695a2bcd01a05504b3c4e38bc8eeb21e8326 | 33 |
| 6b3a55e0261b0304143f805a24924d0c1c44524821305f31d9277843b8a10f4e | 31 |
| cc10ba3e72e09f1e742e4155968aa081fd309c76b6acf28eea1e3046438f005e | 30 |
| f33ae3bc9a22cd7564990a794789954409977013966fb1a8f43c35776b833a95 | 27 |
| `hxxps://modat[.]io/ ` | 23 |
| 5ecf8d2cc410094e8b82dd0bc178a57f3aa1e80916689beb00fe56148b1b1256 | 23 |
| 53175bcc0524f37b47062fafdda28e3f8eb91d519ca0a184ca71bbebe72f969a | 22 |
| 9d272f1f3e92f7c5efdcfdda0ab92facccd98c340be8be09064060503fd167e4 | 21 |

## ATT&CK techniques
| Tactic | Technique | Name | Events | Agents | Confidence |
|---|---|---|---|---|---|
| Reconnaissance | `T1595.001 ` | Scanning IP Blocks | 49082 | 16 | high |
| Reconnaissance | `T1595.002 ` | Vulnerability Scanning | 1250 | 15 | high |
| Reconnaissance | `T1595.003 ` | Wordlist Scanning | 973 | 16 | high |
| Reconnaissance | T1594 | Search Victim-Owned Websites | 362 | 15 | high |
| Initial Access | T1133 | External Remote Services | 19728 | 16 | high |
| Initial Access | T1078 | Valid Accounts | 6964 | 15 | high |
| Initial Access | T1190 | Exploit Public-Facing Application | 466 | 15 | high |
| Execution | `T1059.004 ` | Unix Shell | 13488 | 15 | high |
| Persistence | `T1053.003 ` | Cron | 1267 | 15 | high |
| Persistence | T1098 | Account Manipulation | 172 | 9 | high |
| Persistence | `T1098.004 ` | SSH Authorized Keys | 125 | 9 | high |
| Stealth | `T1070.004 ` | File Deletion | 1320 | 15 | high |
| Stealth | `T1070.003 ` | Clear Command History | 170 | 15 | high |
| Defense Impairment | `T1222.002 ` | Linux and Mac Permissions | 362 | 15 | high |
| Credential Access | `T1110.001 ` | Password Guessing | 21555 | 16 | high |
| Credential Access | `T1552.001 ` | Credentials In Files | 765 | 15 | high |
| Discovery | T1082 | System Information Discovery | 6518 | 15 | high |
| Discovery | T1057 | Process Discovery | 1247 | 15 | high |
| Discovery | T1033 | `System Owner/User Discovery ` | 191 | 9 | high |
| Discovery | T1083 | File and Directory Discovery | 99 | 9 | high |
| Discovery | T1016 | System Network Configuration Discovery | 2 | 1 | low |
| Command and Control | T1105 | Ingress Tool Transfer | 4181 | 15 | high |
| Command and Control | T1090 | Proxy | 688 | 15 | high |
| Impact | `T1496.001 ` | Compute Hijacking | 1170 | 15 | high |

## Recommendations
- Patch or take offline anything affected by CVE-2017-9841 (PHPUnit eval-stdin remote code execution). _161 attempts on 7 agents in this period, listed by CISA as exploited in the wild._
- Patch or take offline anything affected by CVE-2024-4577 (PHP-CGI argument injection). _23 attempts on 8 agents in this period, listed by CISA as exploited in the wild, known ransomware use._
- Patch or take offline anything affected by CVE-2025-31324 (SAP NetWeaver Visual Composer file upload). _14 attempts on 14 agents in this period, listed by CISA as exploited in the wild, known ransomware use._
- Patch or take offline anything affected by CVE-2021-41773 (Apache httpd path traversal). _13 attempts on 8 agents in this period, listed by CISA as exploited in the wild, known ransomware use._
- Patch or take offline anything affected by CVE-2018-20062 (ThinkPHP remote code execution). _11 attempts on 5 agents in this period, listed by CISA as exploited in the wild._
- Patch or take offline anything affected by CVE-2018-13379 (FortiOS SSL VPN file read). _8 attempts on 4 agents in this period, listed by CISA as exploited in the wild, known ransomware use._
- Patch or take offline anything affected by CVE-2018-10561 (GPON router authentication bypass). _2 attempts on 2 agents in this period, listed by CISA as exploited in the wild._
- Patch or take offline anything affected by CVE-2026-123158 (OpenSSH password authentication bypass (musl libc without PAM)). _1 attempts on 1 agents in this period, listed by CISA as exploited in the wild._
- Turn off password sign-in on internet-facing SSH, Telnet, FTP and admin logins; use keys or two-step sign-in. _Password guessing is constant and automated._
- Check that web servers do not serve .env files, .git directories or credential files. _Scanners ask every reachable web server for them._

## Method and limits
- Source: decoy services (honeypots) on internet-facing servers. They have no legitimate users, so everything recorded is unsolicited.
- Coverage: untargeted, automated activity. The fleet does not see targeted attacks on your organisation, and it does not observe what happens after a successful break-in.
- Confidence: high = seen by at least half of a multi-agent fleet and by ten or more addresses; medium = several addresses or more than one agent; low = a single agent and few addresses.
- Change is measured against the average of the seven preceding periods of equal length.
- ATT&CK techniques describe what a request attempted. No technique succeeded: decoys never execute what they receive.
- CVE dates and scores: CVE Program. Exploited-in-the-wild status: CISA KEV. Origin countries are where a network is registered, not necessarily where an operator sits.
