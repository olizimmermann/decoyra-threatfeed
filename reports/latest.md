# Threat situation report
Period: last 7 days (2026-11-13 03:28 UTC to 2026-11-20 03:28 UTC) · 18 agents
## Key findings
- **High confidence.** The fleet has less history than this period, so there is no usual level yet: nothing here is called new or rising. _(comparisons start once the fleet has run for 336 hours)_
- **High confidence.** CVE-2017-9841 (PHPUnit eval-stdin remote code execution) is being attempted, a vulnerability CISA lists as exploited in the wild. _(1869 attempts on 16 of 18 agents; first seen by the fleet 7 days ago)_
- **High confidence.** CVE-2026-104935 (Ivanti Connect Secure Authentication Bypass by Spoofing Vulnerability) is being attempted, a vulnerability CISA lists as exploited in the wild. _(202 attempts on 16 of 18 agents; first seen by the fleet 6 days ago)_
- **High confidence.** CVE-2026-123158 (OpenSSH password authentication bypass (musl libc without PAM)) is being attempted, a vulnerability CISA lists as exploited in the wild. _(144 attempts on 13 of 18 agents; first seen by the fleet 6 days ago)_
- **Medium confidence.** CVE-2021-3129 (Laravel Ignition remote code execution) is being attempted, a vulnerability CISA lists as exploited in the wild and used by ransomware groups. _(137 attempts on 2 of 18 agents; first seen by the fleet 5 days ago)_
- **High confidence.** The largest campaign uses 62 addresses with the same technique set (CVE-2025-31324). _(63 events on 17 of 18 agents)_

## Numbers
| Events | Attacking addresses | High severity | Blocked now | Language-model agents | New patterns |
|---|---|---|---|---|---|
| 4868850 | 27361 | 19403 | 940 | 0 | 10 |

## Known exploits
| CVE | Name | CVSS | CISA | Events | Agents |
|---|---|---|---|---|---|
| CVE-2017-9841 | PHPUnit eval-stdin remote code execution | `9.8 ` | exploited | 1869 | 16 |
| CVE-2026-104935 | Ivanti Connect Secure Authentication Bypass by Spoofing Vulnerability | `n/a ` | exploited | 202 | 16 |
| CVE-2026-123158 | OpenSSH password authentication bypass (musl libc without PAM) | `8.1 ` | exploited | 144 | 13 |
| CVE-2021-3129 | Laravel Ignition remote code execution | `9.8 ` | exploited, ransomware | 137 | 2 |
| CVE-2021-41773 | Apache httpd path traversal | `7.5 ` | exploited, ransomware | 119 | 16 |
| CVE-2025-31324 | SAP NetWeaver Visual Composer file upload | `10.0 ` | exploited, ransomware | 109 | 17 |
| CVE-2018-13379 | FortiOS SSL VPN file read | `9.1 ` | exploited, ransomware | 102 | 16 |
| CVE-2021-44228 | Log4Shell | `10.0 ` | exploited, ransomware | 101 | 8 |
| CVE-2024-4577 | PHP-CGI argument injection | `9.8 ` | exploited, ransomware | 91 | 15 |
| CVE-2020-3452 | Cisco ASA and FTD Read-Only Path Traversal Vulnerability | `n/a ` | exploited | 82 | 16 |

## Technologies under attack
| Technology | Events | Change | Agents |
|---|---|---|---|
| ssh | 149790 | no history yet | 18 |
| credential-attack | 138676 | no history yet | 18 |
| rdp | 57595 | no history yet | 18 |
| ssh-shell | 54189 | no history yet | 18 |
| telnet | 47410 | no history yet | 18 |
| smb | 38256 | no history yet | 18 |
| ssh-login | 35852 | no history yet | 18 |
| mssql | 30692 | no history yet | 18 |
| shell-recon | 26791 | no history yet | 18 |
| smb1 | 24942 | no history yet | 18 |
| shell-download | 16284 | no history yet | 18 |
| php | 13054 | no history yet | 18 |

## New request patterns
| Pattern | Events | Addresses | Confidence |
|---|---|---|---|
| RDP tls,nla | 29618 | 1137 | high |
| `Mozilla/{v} (compatible; AhrefsBot/{v}; +http://ahrefs.com/robot/) ` | 26537 | 614 | medium |
| `shell-recon > shell-download > shell-recon ` | 26480 | 106 | high |
| rdp probe | 19042 | 43 | high |
| mssql sa | 18524 | 917 | high |
| `SMB1 NT LM 0.12,SMB 2.002,SMB 2.??? ` | 17666 | 650 | high |
| mssql go-mssqldb | 14883 | 30 | high |
| `Mozilla/{v} (Windows NT {v}; Win64; x64) AppleWebKit/{v} (KHTML, like Gecko) Chrome/{v} Safari/{v} ( ` | 12783 | 261 | medium |

## Campaigns
| Techniques | Addresses | Events | Agents |
|---|---|---|---|
| CVE-2025-31324 | 62 | 63 | 17 |
| env-secrets, git-exposure, java-spring | 59 | 1485 | 16 |
| vpn-gateway | 56 | 114 | 16 |
| env-secrets | 45 | 70 | 16 |
| java-spring | 45 | 46 | 17 |

## Indicators (de-fanged, never fetch)
| Indicator | Attacking addresses |
|---|---|
| a8460f446be540410004b1a8db4083773fa46f7fe76fa84219c93daa1669f8f2 | 301 |
| 01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b | 127 |
| e150a1ec81e8e93e1eae2c3a77e66ec6dbd6a3b460f89c1d08aecf422ee401a0 | 107 |
| 2634c3097f98e36865f0c572009c4ffd73316bc8b88ccfe8d196af35f46e2394 | 105 |
| c05b56ab6d3d07ccca6778ebd799bf98dfa2b7f10dd43601f0938f04e5070878 | 103 |
| a883dafc480d466ee04e0d6da986bd78eb1fdd2178d04693723da3a8f95d42f4 | 101 |
| 6d78392a5886177fe5b86e585a0b695a2bcd01a05504b3c4e38bc8eeb21e8326 | 100 |
| 6b3a55e0261b0304143f805a24924d0c1c44524821305f31d9277843b8a10f4e | 97 |
| cc10ba3e72e09f1e742e4155968aa081fd309c76b6acf28eea1e3046438f005e | 92 |
| 3c56dd5ed61af7e7b20f54288947a89a4891d181b10fe04560b55c5e82de1fa2 | 91 |
| f33ae3bc9a22cd7564990a794789954409977013966fb1a8f43c35776b833a95 | 89 |
| 53175bcc0524f37b47062fafdda28e3f8eb91d519ca0a184ca71bbebe72f969a | 85 |
| 5ecf8d2cc410094e8b82dd0bc178a57f3aa1e80916689beb00fe56148b1b1256 | 84 |
| 3b5485dd0909db36922ecd8578f18da11954810e63582f302c10881ac5c47534 | 73 |
| 9d272f1f3e92f7c5efdcfdda0ab92facccd98c340be8be09064060503fd167e4 | 71 |

## ATT&CK techniques
| Tactic | Technique | Name | Events | Agents | Confidence |
|---|---|---|---|---|---|
| Reconnaissance | `T1595.001 ` | Scanning IP Blocks | 275465 | 18 | high |
| Reconnaissance | `T1595.002 ` | Vulnerability Scanning | 19294 | 18 | high |
| Reconnaissance | `T1595.003 ` | Wordlist Scanning | 15716 | 18 | high |
| Reconnaissance | T1594 | Search Victim-Owned Websites | 6275 | 18 | high |
| Initial Access | T1133 | External Remote Services | 106341 | 18 | high |
| Initial Access | T1078 | Valid Accounts | 35871 | 18 | high |
| Initial Access | T1190 | Exploit Public-Facing Application | 3680 | 18 | high |
| Execution | `T1059.004 ` | Unix Shell | 55321 | 18 | high |
| Persistence | `T1053.003 ` | Cron | 6790 | 18 | high |
| Persistence | T1098 | Account Manipulation | 825 | 15 | high |
| Persistence | `T1098.004 ` | SSH Authorized Keys | 578 | 12 | high |
| Stealth | `T1070.004 ` | File Deletion | 7299 | 18 | high |
| Stealth | `T1070.003 ` | Clear Command History | 413 | 17 | high |
| Defense Impairment | `T1222.002 ` | Linux and Mac Permissions | 1297 | 17 | high |
| Credential Access | `T1110.001 ` | Password Guessing | 138676 | 18 | high |
| Credential Access | `T1552.001 ` | Credentials In Files | 6881 | 18 | high |
| Discovery | T1082 | System Information Discovery | 26604 | 18 | high |
| Discovery | T1057 | Process Discovery | 6853 | 18 | high |
| Discovery | T1033 | `System Owner/User Discovery ` | 1061 | 17 | high |
| Discovery | T1083 | File and Directory Discovery | 613 | 18 | high |
| Discovery | T1016 | System Network Configuration Discovery | 236 | 17 | high |
| Command and Control | T1105 | Ingress Tool Transfer | 18375 | 18 | high |
| Command and Control | T1090 | Proxy | 10258 | 18 | high |
| Impact | `T1496.001 ` | Compute Hijacking | 6357 | 18 | high |

## Recommendations
- Patch or take offline anything affected by CVE-2017-9841 (PHPUnit eval-stdin remote code execution). _1869 attempts on 16 agents in this period, listed by CISA as exploited in the wild._
- Patch or take offline anything affected by CVE-2026-104935 (Ivanti Connect Secure Authentication Bypass by Spoofing Vulnerability). _202 attempts on 16 agents in this period, listed by CISA as exploited in the wild._
- Patch or take offline anything affected by CVE-2026-123158 (OpenSSH password authentication bypass (musl libc without PAM)). _144 attempts on 13 agents in this period, listed by CISA as exploited in the wild._
- Patch or take offline anything affected by CVE-2021-3129 (Laravel Ignition remote code execution). _137 attempts on 2 agents in this period, listed by CISA as exploited in the wild, known ransomware use._
- Patch or take offline anything affected by CVE-2021-41773 (Apache httpd path traversal). _119 attempts on 16 agents in this period, listed by CISA as exploited in the wild, known ransomware use._
- Patch or take offline anything affected by CVE-2025-31324 (SAP NetWeaver Visual Composer file upload). _109 attempts on 17 agents in this period, listed by CISA as exploited in the wild, known ransomware use._
- Patch or take offline anything affected by CVE-2018-13379 (FortiOS SSL VPN file read). _102 attempts on 16 agents in this period, listed by CISA as exploited in the wild, known ransomware use._
- Patch or take offline anything affected by CVE-2021-44228 (Log4Shell). _101 attempts on 8 agents in this period, listed by CISA as exploited in the wild, known ransomware use._
- Patch or take offline anything affected by CVE-2024-4577 (PHP-CGI argument injection). _91 attempts on 15 agents in this period, listed by CISA as exploited in the wild, known ransomware use._
- Patch or take offline anything affected by CVE-2020-3452 (Cisco ASA and FTD Read-Only Path Traversal Vulnerability). _82 attempts on 16 agents in this period, listed by CISA as exploited in the wild._

## Method and limits
- Source: decoy services (honeypots) on internet-facing servers. They have no legitimate users, so everything recorded is unsolicited.
- Coverage: untargeted, automated activity. The fleet does not see targeted attacks on your organisation, and it does not observe what happens after a successful break-in.
- Confidence: high = seen by at least half of a multi-agent fleet and by ten or more addresses; medium = several addresses or more than one agent; low = a single agent and few addresses.
- Change is measured against the average of the seven preceding periods of equal length.
- ATT&CK techniques describe what a request attempted. No technique succeeded: decoys never execute what they receive.
- CVE dates and scores: CVE Program. Exploited-in-the-wild status: CISA KEV. Origin countries are where a network is registered, not necessarily where an operator sits.
