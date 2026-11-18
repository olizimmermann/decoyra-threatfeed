# Threat situation report
Period: last 7 days (2026-11-11 04:30 UTC to 2026-11-18 04:30 UTC) · 17 agents
## Key findings
- **High confidence.** The fleet has less history than this period, so there is no usual level yet: nothing here is called new or rising. _(comparisons start once the fleet has run for 336 hours)_
- **High confidence.** CVE-2017-9841 (PHPUnit eval-stdin remote code execution) is being attempted, a vulnerability CISA lists as exploited in the wild. _(564 attempts on 15 of 17 agents; first seen by the fleet 5 days ago)_
- **High confidence.** CVE-2026-104935 (Ivanti Connect Secure Authentication Bypass by Spoofing Vulnerability) is being attempted, a vulnerability CISA lists as exploited in the wild. _(201 attempts on 16 of 17 agents; first seen by the fleet 4 days ago)_
- **High confidence.** CVE-2026-123158 (OpenSSH password authentication bypass (musl libc without PAM)) is being attempted, a vulnerability CISA lists as exploited in the wild. _(140 attempts on 13 of 17 agents; first seen by the fleet 4 days ago)_
- **High confidence.** CVE-2021-41773 (Apache httpd path traversal) is being attempted, a vulnerability CISA lists as exploited in the wild and used by ransomware groups. _(110 attempts on 15 of 17 agents; first seen by the fleet 5 days ago)_
- **High confidence.** The largest campaign uses 65 addresses with the same technique set (env-secrets, git-exposure, java-spring). _(1652 events on 16 of 17 agents)_

## Numbers
| Events | Attacking addresses | High severity | Blocked now | Language-model agents | New patterns |
|---|---|---|---|---|---|
| 3003742 | 18341 | 9354 | 906 | 0 | 10 |

## Known exploits
| CVE | Name | CVSS | CISA | Events | Agents |
|---|---|---|---|---|---|
| CVE-2017-9841 | PHPUnit eval-stdin remote code execution | `9.8 ` | exploited | 564 | 15 |
| CVE-2026-104935 | Ivanti Connect Secure Authentication Bypass by Spoofing Vulnerability | `n/a ` | exploited | 201 | 16 |
| CVE-2026-123158 | OpenSSH password authentication bypass (musl libc without PAM) | `8.1 ` | exploited | 140 | 13 |
| CVE-2021-41773 | Apache httpd path traversal | `7.5 ` | exploited, ransomware | 110 | 15 |
| CVE-2018-13379 | FortiOS SSL VPN file read | `9.1 ` | exploited, ransomware | 102 | 16 |
| CVE-2021-44228 | Log4Shell | `10.0 ` | exploited, ransomware | 101 | 8 |
| CVE-2020-3452 | Cisco ASA and FTD Read-Only Path Traversal Vulnerability | `n/a ` | exploited | 82 | 16 |
| CVE-2022-40684 | Fortinet Multiple Products Authentication Bypass Vulnerability | `n/a ` | exploited, ransomware | 82 | 16 |
| CVE-2025-31324 | SAP NetWeaver Visual Composer file upload | `10.0 ` | exploited, ransomware | 76 | 16 |
| CVE-2024-4577 | PHP-CGI argument injection | `9.8 ` | exploited, ransomware | 74 | 13 |

## Technologies under attack
| Technology | Events | Change | Agents |
|---|---|---|---|
| ssh | 103694 | no history yet | 17 |
| credential-attack | 98056 | no history yet | 17 |
| rdp | 46455 | no history yet | 17 |
| ssh-shell | 41736 | no history yet | 16 |
| telnet | 35611 | no history yet | 17 |
| ssh-login | 25987 | no history yet | 16 |
| smb | 25724 | no history yet | 16 |
| mssql | 22424 | no history yet | 16 |
| shell-recon | 20900 | no history yet | 16 |
| smb1 | 16685 | no history yet | 16 |
| shell-download | 12386 | no history yet | 16 |
| mysql | 8758 | no history yet | 16 |

## New request patterns
| Pattern | Events | Addresses | Confidence |
|---|---|---|---|
| `SSH-2.0-Go ` | 39489 | 1011 | high |
| ssh root | 39486 | 1239 | high |
| `Mozilla/{v} AppleWebKit/{v} (KHTML, like Gecko; compatible; bingbot/{v}; +http://www.bing.com/bingbo ` | 23836 | 425 | medium |
| RDP tls,nla | 23419 | 832 | high |
| `GET / ` | 21451 | 5000 | high |
| `shell-recon > shell-download > shell-recon ` | 18208 | 98 | high |
| `0a07365cc01fa9fc82608ba4019af499 SSH-2.0-Go ` | 15666 | 179 | high |
| rdp probe | 15199 | 36 | high |

## Campaigns
| Techniques | Addresses | Events | Agents |
|---|---|---|---|
| env-secrets, git-exposure, java-spring | 65 | 1652 | 16 |
| vpn-gateway | 62 | 126 | 16 |
| env-secrets | 44 | 64 | 16 |
| git-exposure | 36 | 110 | 14 |
| CVE-2025-31324 | 32 | 32 | 16 |

## Indicators (de-fanged, never fetch)
| Indicator | Attacking addresses |
|---|---|
| a8460f446be540410004b1a8db4083773fa46f7fe76fa84219c93daa1669f8f2 | 242 |
| e150a1ec81e8e93e1eae2c3a77e66ec6dbd6a3b460f89c1d08aecf422ee401a0 | 101 |
| 2634c3097f98e36865f0c572009c4ffd73316bc8b88ccfe8d196af35f46e2394 | 96 |
| c05b56ab6d3d07ccca6778ebd799bf98dfa2b7f10dd43601f0938f04e5070878 | 93 |
| a883dafc480d466ee04e0d6da986bd78eb1fdd2178d04693723da3a8f95d42f4 | 92 |
| 6b3a55e0261b0304143f805a24924d0c1c44524821305f31d9277843b8a10f4e | 91 |
| 01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b | 91 |
| 6d78392a5886177fe5b86e585a0b695a2bcd01a05504b3c4e38bc8eeb21e8326 | 90 |
| cc10ba3e72e09f1e742e4155968aa081fd309c76b6acf28eea1e3046438f005e | 78 |
| 3c56dd5ed61af7e7b20f54288947a89a4891d181b10fe04560b55c5e82de1fa2 | 77 |
| f33ae3bc9a22cd7564990a794789954409977013966fb1a8f43c35776b833a95 | 73 |
| 5ecf8d2cc410094e8b82dd0bc178a57f3aa1e80916689beb00fe56148b1b1256 | 73 |
| 53175bcc0524f37b47062fafdda28e3f8eb91d519ca0a184ca71bbebe72f969a | 66 |
| 3b5485dd0909db36922ecd8578f18da11954810e63582f302c10881ac5c47534 | 60 |
| 9d272f1f3e92f7c5efdcfdda0ab92facccd98c340be8be09064060503fd167e4 | 55 |

## ATT&CK techniques
| Tactic | Technique | Name | Events | Agents | Confidence |
|---|---|---|---|---|---|
| Reconnaissance | `T1595.001 ` | Scanning IP Blocks | 201545 | 17 | high |
| Reconnaissance | `T1595.002 ` | Vulnerability Scanning | 11519 | 16 | high |
| Reconnaissance | `T1595.003 ` | Wordlist Scanning | 10775 | 17 | high |
| Reconnaissance | T1594 | Search Victim-Owned Websites | 3324 | 16 | high |
| Initial Access | T1133 | External Remote Services | 74319 | 17 | high |
| Initial Access | T1078 | Valid Accounts | 26003 | 16 | high |
| Initial Access | T1190 | Exploit Public-Facing Application | 1998 | 16 | high |
| Execution | `T1059.004 ` | Unix Shell | 42763 | 16 | high |
| Persistence | `T1053.003 ` | Cron | 4969 | 16 | high |
| Persistence | T1098 | Account Manipulation | 655 | 12 | high |
| Persistence | `T1098.004 ` | SSH Authorized Keys | 487 | 12 | high |
| Stealth | `T1070.004 ` | File Deletion | 5317 | 16 | high |
| Stealth | `T1070.003 ` | Clear Command History | 395 | 16 | high |
| Defense Impairment | `T1222.002 ` | Linux and Mac Permissions | 1114 | 16 | high |
| Credential Access | `T1110.001 ` | Password Guessing | 98056 | 17 | high |
| Credential Access | `T1552.001 ` | Credentials In Files | 4712 | 16 | high |
| Discovery | T1082 | System Information Discovery | 20677 | 16 | high |
| Discovery | T1057 | Process Discovery | 4968 | 16 | high |
| Discovery | T1033 | `System Owner/User Discovery ` | 848 | 15 | high |
| Discovery | T1083 | File and Directory Discovery | 471 | 16 | high |
| Discovery | T1016 | System Network Configuration Discovery | 153 | 14 | high |
| Command and Control | T1105 | Ingress Tool Transfer | 14105 | 16 | high |
| Command and Control | T1090 | Proxy | 6218 | 16 | high |
| Impact | `T1496.001 ` | Compute Hijacking | 4614 | 16 | high |

## Recommendations
- Patch or take offline anything affected by CVE-2017-9841 (PHPUnit eval-stdin remote code execution). _564 attempts on 15 agents in this period, listed by CISA as exploited in the wild._
- Patch or take offline anything affected by CVE-2026-104935 (Ivanti Connect Secure Authentication Bypass by Spoofing Vulnerability). _201 attempts on 16 agents in this period, listed by CISA as exploited in the wild._
- Patch or take offline anything affected by CVE-2026-123158 (OpenSSH password authentication bypass (musl libc without PAM)). _140 attempts on 13 agents in this period, listed by CISA as exploited in the wild._
- Patch or take offline anything affected by CVE-2021-41773 (Apache httpd path traversal). _110 attempts on 15 agents in this period, listed by CISA as exploited in the wild, known ransomware use._
- Patch or take offline anything affected by CVE-2018-13379 (FortiOS SSL VPN file read). _102 attempts on 16 agents in this period, listed by CISA as exploited in the wild, known ransomware use._
- Patch or take offline anything affected by CVE-2021-44228 (Log4Shell). _101 attempts on 8 agents in this period, listed by CISA as exploited in the wild, known ransomware use._
- Patch or take offline anything affected by CVE-2020-3452 (Cisco ASA and FTD Read-Only Path Traversal Vulnerability). _82 attempts on 16 agents in this period, listed by CISA as exploited in the wild._
- Patch or take offline anything affected by CVE-2022-40684 (Fortinet Multiple Products Authentication Bypass Vulnerability). _82 attempts on 16 agents in this period, listed by CISA as exploited in the wild, known ransomware use._
- Patch or take offline anything affected by CVE-2025-31324 (SAP NetWeaver Visual Composer file upload). _76 attempts on 16 agents in this period, listed by CISA as exploited in the wild, known ransomware use._
- Patch or take offline anything affected by CVE-2024-4577 (PHP-CGI argument injection). _74 attempts on 13 agents in this period, listed by CISA as exploited in the wild, known ransomware use._

## Method and limits
- Source: decoy services (honeypots) on internet-facing servers. They have no legitimate users, so everything recorded is unsolicited.
- Coverage: untargeted, automated activity. The fleet does not see targeted attacks on your organisation, and it does not observe what happens after a successful break-in.
- Confidence: high = seen by at least half of a multi-agent fleet and by ten or more addresses; medium = several addresses or more than one agent; low = a single agent and few addresses.
- Change is measured against the average of the seven preceding periods of equal length.
- ATT&CK techniques describe what a request attempted. No technique succeeded: decoys never execute what they receive.
- CVE dates and scores: CVE Program. Exploited-in-the-wild status: CISA KEV. Origin countries are where a network is registered, not necessarily where an operator sits.
