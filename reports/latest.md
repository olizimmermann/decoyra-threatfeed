# Threat situation report
Period: last 7 days (2026-11-07 17:05 UTC to 2026-11-14 17:05 UTC) · 16 agents
## Key findings
- **High confidence.** The fleet has less history than this period, so there is no usual level yet: nothing here is called new or rising. _(comparisons start once the fleet has run for 336 hours)_
- **Medium confidence.** CVE-2017-9841 (PHPUnit eval-stdin remote code execution) is being attempted, a vulnerability CISA lists as exploited in the wild. _(174 attempts on 7 of 16 agents; first seen by the fleet 30 hours ago)_
- **High confidence.** CVE-2024-4577 (PHP-CGI argument injection) is being attempted, a vulnerability CISA lists as exploited in the wild and used by ransomware groups. _(25 attempts on 8 of 16 agents; first seen by the fleet 37 hours ago)_
- **High confidence.** CVE-2021-41773 (Apache httpd path traversal) is being attempted, a vulnerability CISA lists as exploited in the wild and used by ransomware groups. _(14 attempts on 8 of 16 agents; first seen by the fleet 37 hours ago)_
- **High confidence.** CVE-2025-31324 (SAP NetWeaver Visual Composer file upload) is being attempted, a vulnerability CISA lists as exploited in the wild and used by ransomware groups. _(14 attempts on 14 of 16 agents; first seen by the fleet 16 hours ago)_
- **High confidence.** The largest campaign uses 26 addresses with the same technique set (git-exposure). _(45 events on 11 of 16 agents)_

## Numbers
| Events | Attacking addresses | High severity | Blocked now | Language-model agents | New patterns |
|---|---|---|---|---|---|
| 784545 | 9505 | 3502 | 763 | 0 | 10 |

## Known exploits
| CVE | Name | CVSS | CISA | Events | Agents |
|---|---|---|---|---|---|
| CVE-2017-9841 | PHPUnit eval-stdin remote code execution | `9.8 ` | exploited | 174 | 7 |
| CVE-2024-4577 | PHP-CGI argument injection | `9.8 ` | exploited, ransomware | 25 | 8 |
| CVE-2021-41773 | Apache httpd path traversal | `7.5 ` | exploited, ransomware | 14 | 8 |
| CVE-2025-31324 | SAP NetWeaver Visual Composer file upload | `10.0 ` | exploited, ransomware | 14 | 14 |
| CVE-2018-20062 | ThinkPHP remote code execution | `9.8 ` | exploited | 11 | 5 |
| CVE-2018-13379 | FortiOS SSL VPN file read | `9.1 ` | exploited, ransomware | 8 | 4 |
| CVE-2018-10561 | GPON router authentication bypass | `9.8 ` | exploited | 3 | 2 |
| CVE-2021-44228 | Log4Shell | `10.0 ` | exploited, ransomware | 1 | 1 |
| CVE-2026-123158 | OpenSSH password authentication bypass (musl libc without PAM) | `n/a ` | exploited | 1 | 1 |

## Technologies under attack
| Technology | Events | Change | Agents |
|---|---|---|---|
| ssh | 32389 | no history yet | 16 |
| credential-attack | 27043 | no history yet | 16 |
| rdp | 16970 | no history yet | 16 |
| ssh-shell | 15775 | no history yet | 15 |
| telnet | 13418 | no history yet | 16 |
| ssh-login | 8448 | no history yet | 15 |
| shell-recon | 7729 | no history yet | 15 |
| smb | 5088 | no history yet | 15 |
| shell-download | 4322 | no history yet | 15 |
| smb1 | 3281 | no history yet | 15 |
| mysql | 2536 | no history yet | 15 |
| mssql | 2410 | no history yet | 15 |

## New request patterns
| Pattern | Events | Addresses | Confidence |
|---|---|---|---|
| `SSH-2.0-Go ` | 14859 | 419 | high |
| ssh root | 13015 | 463 | high |
| RDP tls,nla | 6314 | 229 | high |
| `0a07365cc01fa9fc82608ba4019af499 SSH-2.0-Go ` | 5653 | 109 | high |
| (many distinct values from one address) | 5039 | 46 | high |
| `GET / ` | 4499 | 1856 | high |
| `shell-recon > shell-download > shell-recon ` | 4446 | 37 | high |
| uname -s -v -n -r -m | 4311 | 91 | high |

## Campaigns
| Techniques | Addresses | Events | Agents |
|---|---|---|---|
| git-exposure | 26 | 45 | 11 |
| admin-panel, iot-router | 18 | 18 | 10 |
| php, wordpress | 17 | 21 | 1 |
| env-secrets | 12 | 105 | 15 |
| admin-panel, php | 11 | 68 | 13 |

## Indicators (de-fanged, never fetch)
| Indicator | Attacking addresses |
|---|---|
| a8460f446be540410004b1a8db4083773fa46f7fe76fa84219c93daa1669f8f2 | 81 |
| e150a1ec81e8e93e1eae2c3a77e66ec6dbd6a3b460f89c1d08aecf422ee401a0 | 48 |
| c05b56ab6d3d07ccca6778ebd799bf98dfa2b7f10dd43601f0938f04e5070878 | 48 |
| 2634c3097f98e36865f0c572009c4ffd73316bc8b88ccfe8d196af35f46e2394 | 47 |
| a883dafc480d466ee04e0d6da986bd78eb1fdd2178d04693723da3a8f95d42f4 | 43 |
| `hxxp://103[.]160[.]59[.]94:28816/CZRmrtxnrNONBXhwfFeqjNfBrliNaShG ` | 39 |
| 9ba5884baa8b8a7533446fe7b6b5323d40b4ab1e335dc54a54be1a0a40459b07 | 39 |
| 6d78392a5886177fe5b86e585a0b695a2bcd01a05504b3c4e38bc8eeb21e8326 | 39 |
| 6b3a55e0261b0304143f805a24924d0c1c44524821305f31d9277843b8a10f4e | 38 |
| cc10ba3e72e09f1e742e4155968aa081fd309c76b6acf28eea1e3046438f005e | 35 |
| f33ae3bc9a22cd7564990a794789954409977013966fb1a8f43c35776b833a95 | 32 |
| 5ecf8d2cc410094e8b82dd0bc178a57f3aa1e80916689beb00fe56148b1b1256 | 28 |
| 53175bcc0524f37b47062fafdda28e3f8eb91d519ca0a184ca71bbebe72f969a | 26 |
| 9d272f1f3e92f7c5efdcfdda0ab92facccd98c340be8be09064060503fd167e4 | 26 |
| 3c56dd5ed61af7e7b20f54288947a89a4891d181b10fe04560b55c5e82de1fa2 | 26 |

## ATT&CK techniques
| Tactic | Technique | Name | Events | Agents | Confidence |
|---|---|---|---|---|---|
| Reconnaissance | `T1595.001 ` | Scanning IP Blocks | 59920 | 16 | high |
| Reconnaissance | `T1595.002 ` | Vulnerability Scanning | 1938 | 15 | high |
| Reconnaissance | `T1595.003 ` | Wordlist Scanning | 1462 | 16 | high |
| Reconnaissance | T1594 | Search Victim-Owned Websites | 465 | 15 | high |
| Initial Access | T1133 | External Remote Services | 24052 | 16 | high |
| Initial Access | T1078 | Valid Accounts | 8448 | 15 | high |
| Initial Access | T1190 | Exploit Public-Facing Application | 535 | 15 | high |
| Execution | `T1059.004 ` | Unix Shell | 16103 | 15 | high |
| Persistence | `T1053.003 ` | Cron | 1504 | 15 | high |
| Persistence | T1098 | Account Manipulation | 196 | 9 | high |
| Persistence | `T1098.004 ` | SSH Authorized Keys | 141 | 9 | high |
| Stealth | `T1070.004 ` | File Deletion | 1572 | 15 | high |
| Stealth | `T1070.003 ` | Clear Command History | 188 | 15 | high |
| Defense Impairment | `T1222.002 ` | Linux and Mac Permissions | 412 | 15 | high |
| Credential Access | `T1110.001 ` | Password Guessing | 27043 | 16 | high |
| Credential Access | `T1552.001 ` | Credentials In Files | 905 | 15 | high |
| Discovery | T1082 | System Information Discovery | 7749 | 15 | high |
| Discovery | T1057 | Process Discovery | 1484 | 15 | high |
| Discovery | T1033 | `System Owner/User Discovery ` | 221 | 9 | high |
| Discovery | T1083 | File and Directory Discovery | 114 | 9 | high |
| Discovery | T1016 | System Network Configuration Discovery | 2 | 1 | low |
| Command and Control | T1105 | Ingress Tool Transfer | 4935 | 15 | high |
| Command and Control | T1090 | Proxy | 973 | 15 | high |
| Impact | `T1496.001 ` | Compute Hijacking | 1392 | 15 | high |

## Recommendations
- Patch or take offline anything affected by CVE-2017-9841 (PHPUnit eval-stdin remote code execution). _174 attempts on 7 agents in this period, listed by CISA as exploited in the wild._
- Patch or take offline anything affected by CVE-2024-4577 (PHP-CGI argument injection). _25 attempts on 8 agents in this period, listed by CISA as exploited in the wild, known ransomware use._
- Patch or take offline anything affected by CVE-2021-41773 (Apache httpd path traversal). _14 attempts on 8 agents in this period, listed by CISA as exploited in the wild, known ransomware use._
- Patch or take offline anything affected by CVE-2025-31324 (SAP NetWeaver Visual Composer file upload). _14 attempts on 14 agents in this period, listed by CISA as exploited in the wild, known ransomware use._
- Patch or take offline anything affected by CVE-2018-20062 (ThinkPHP remote code execution). _11 attempts on 5 agents in this period, listed by CISA as exploited in the wild._
- Patch or take offline anything affected by CVE-2018-13379 (FortiOS SSL VPN file read). _8 attempts on 4 agents in this period, listed by CISA as exploited in the wild, known ransomware use._
- Patch or take offline anything affected by CVE-2018-10561 (GPON router authentication bypass). _3 attempts on 2 agents in this period, listed by CISA as exploited in the wild._
- Patch or take offline anything affected by CVE-2021-44228 (Log4Shell). _1 attempts on 1 agents in this period, listed by CISA as exploited in the wild, known ransomware use._
- Patch or take offline anything affected by CVE-2026-123158 (OpenSSH password authentication bypass (musl libc without PAM)). _1 attempts on 1 agents in this period, listed by CISA as exploited in the wild._
- Turn off password sign-in on internet-facing SSH, Telnet, FTP and admin logins; use keys or two-step sign-in. _Password guessing is constant and automated._

## Method and limits
- Source: decoy services (honeypots) on internet-facing servers. They have no legitimate users, so everything recorded is unsolicited.
- Coverage: untargeted, automated activity. The fleet does not see targeted attacks on your organisation, and it does not observe what happens after a successful break-in.
- Confidence: high = seen by at least half of a multi-agent fleet and by ten or more addresses; medium = several addresses or more than one agent; low = a single agent and few addresses.
- Change is measured against the average of the seven preceding periods of equal length.
- ATT&CK techniques describe what a request attempted. No technique succeeded: decoys never execute what they receive.
- CVE dates and scores: CVE Program. Exploited-in-the-wild status: CISA KEV. Origin countries are where a network is registered, not necessarily where an operator sits.
