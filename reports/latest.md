# Threat situation report
Period: last 7 days (2026-11-09 22:15 UTC to 2026-11-16 22:15 UTC) · 17 agents
## Key findings
- **High confidence.** The fleet has less history than this period, so there is no usual level yet: nothing here is called new or rising. _(comparisons start once the fleet has run for 336 hours)_
- **High confidence.** CVE-2017-9841 (PHPUnit eval-stdin remote code execution) is being attempted, a vulnerability CISA lists as exploited in the wild. _(440 attempts on 13 of 17 agents; first seen by the fleet 3 days ago)_
- **High confidence.** CVE-2026-104935 (Ivanti Connect Secure Authentication Bypass by Spoofing Vulnerability) is being attempted, a vulnerability CISA lists as exploited in the wild. _(160 attempts on 16 of 17 agents; first seen by the fleet 3 days ago)_
- **High confidence.** CVE-2026-123158 (OpenSSH password authentication bypass (musl libc without PAM)) is being attempted, a vulnerability CISA lists as exploited in the wild. _(129 attempts on 10 of 17 agents; first seen by the fleet 3 days ago)_
- **High confidence.** CVE-2021-41773 (Apache httpd path traversal) is being attempted, a vulnerability CISA lists as exploited in the wild and used by ransomware groups. _(104 attempts on 15 of 17 agents; first seen by the fleet 4 days ago)_
- **High confidence.** The largest campaign uses 51 addresses with the same technique set (git-exposure). _(202 events on 16 of 17 agents)_

## Numbers
| Events | Attacking addresses | High severity | Blocked now | Language-model agents | New patterns |
|---|---|---|---|---|---|
| 2860098 | 15494 | 7793 | 805 | 0 | 10 |

## Known exploits
| CVE | Name | CVSS | CISA | Events | Agents |
|---|---|---|---|---|---|
| CVE-2017-9841 | PHPUnit eval-stdin remote code execution | `9.8 ` | exploited | 440 | 13 |
| CVE-2026-104935 | Ivanti Connect Secure Authentication Bypass by Spoofing Vulnerability | `n/a ` | exploited | 160 | 16 |
| CVE-2026-123158 | OpenSSH password authentication bypass (musl libc without PAM) | `8.1 ` | exploited | 129 | 10 |
| CVE-2021-41773 | Apache httpd path traversal | `7.5 ` | exploited, ransomware | 104 | 15 |
| CVE-2021-44228 | Log4Shell | `10.0 ` | exploited, ransomware | 101 | 8 |
| CVE-2018-13379 | FortiOS SSL VPN file read | `9.1 ` | exploited, ransomware | 61 | 16 |
| CVE-2025-31324 | SAP NetWeaver Visual Composer file upload | `10.0 ` | exploited, ransomware | 60 | 16 |
| CVE-2024-4577 | PHP-CGI argument injection | `9.8 ` | exploited, ransomware | 56 | 12 |
| CVE-2026-96652 | Plex Media Server Server-Side Request Forgery (SSRF) Vulnerability | `n/a ` | exploited | 45 | 15 |
| CVE-2020-3452 | Cisco ASA and FTD Read-Only Path Traversal Vulnerability | `n/a ` | exploited | 41 | 16 |

## Technologies under attack
| Technology | Events | Change | Agents |
|---|---|---|---|
| ssh | 78583 | no history yet | 17 |
| credential-attack | 75306 | no history yet | 17 |
| rdp | 35571 | no history yet | 17 |
| ssh-shell | 34447 | no history yet | 16 |
| telnet | 27577 | no history yet | 17 |
| ssh-login | 20395 | no history yet | 16 |
| shell-recon | 17867 | no history yet | 16 |
| mssql | 17330 | no history yet | 16 |
| smb | 15766 | no history yet | 16 |
| shell-download | 10476 | no history yet | 16 |
| smb1 | 9617 | no history yet | 16 |
| mysql | 6266 | no history yet | 16 |

## New request patterns
| Pattern | Events | Addresses | Confidence |
|---|---|---|---|
| `SSH-2.0-Go ` | 32160 | 811 | high |
| ssh root | 30623 | 979 | high |
| RDP tls,nla | 16998 | 596 | high |
| `GET / ` | 15052 | 4747 | high |
| `shell-recon > shell-download > shell-recon ` | 14712 | 88 | high |
| `Mozilla/{v} AppleWebKit/{v} (KHTML, like Gecko; compatible; bingbot/{v}; +http://www.bing.com/bingbo ` | 13906 | 357 | medium |
| `0a07365cc01fa9fc82608ba4019af499 SSH-2.0-Go ` | 13260 | 167 | high |
| ssh admin | 10855 | 423 | high |

## Campaigns
| Techniques | Addresses | Events | Agents |
|---|---|---|---|
| git-exposure | 51 | 202 | 16 |
| CVE-2025-31324 | 46 | 46 | 16 |
| vpn-gateway | 37 | 74 | 16 |
| env-secrets, git-exposure, java-spring | 36 | 865 | 16 |
| env-secrets | 35 | 47 | 16 |

## Indicators (de-fanged, never fetch)
| Indicator | Attacking addresses |
|---|---|
| a8460f446be540410004b1a8db4083773fa46f7fe76fa84219c93daa1669f8f2 | 207 |
| e150a1ec81e8e93e1eae2c3a77e66ec6dbd6a3b460f89c1d08aecf422ee401a0 | 95 |
| 2634c3097f98e36865f0c572009c4ffd73316bc8b88ccfe8d196af35f46e2394 | 88 |
| c05b56ab6d3d07ccca6778ebd799bf98dfa2b7f10dd43601f0938f04e5070878 | 87 |
| a883dafc480d466ee04e0d6da986bd78eb1fdd2178d04693723da3a8f95d42f4 | 83 |
| 6b3a55e0261b0304143f805a24924d0c1c44524821305f31d9277843b8a10f4e | 82 |
| 6d78392a5886177fe5b86e585a0b695a2bcd01a05504b3c4e38bc8eeb21e8326 | 80 |
| cc10ba3e72e09f1e742e4155968aa081fd309c76b6acf28eea1e3046438f005e | 72 |
| 3c56dd5ed61af7e7b20f54288947a89a4891d181b10fe04560b55c5e82de1fa2 | 68 |
| 01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b | 68 |
| f33ae3bc9a22cd7564990a794789954409977013966fb1a8f43c35776b833a95 | 67 |
| 5ecf8d2cc410094e8b82dd0bc178a57f3aa1e80916689beb00fe56148b1b1256 | 61 |
| 53175bcc0524f37b47062fafdda28e3f8eb91d519ca0a184ca71bbebe72f969a | 57 |
| 3b5485dd0909db36922ecd8578f18da11954810e63582f302c10881ac5c47534 | 55 |
| 9d272f1f3e92f7c5efdcfdda0ab92facccd98c340be8be09064060503fd167e4 | 49 |

## ATT&CK techniques
| Tactic | Technique | Name | Events | Agents | Confidence |
|---|---|---|---|---|---|
| Reconnaissance | `T1595.001 ` | Scanning IP Blocks | 150740 | 17 | high |
| Reconnaissance | `T1595.003 ` | Wordlist Scanning | 8066 | 17 | high |
| Reconnaissance | `T1595.002 ` | Vulnerability Scanning | 7496 | 16 | high |
| Reconnaissance | T1594 | Search Victim-Owned Websites | 2412 | 16 | high |
| Initial Access | T1133 | External Remote Services | 56764 | 17 | high |
| Initial Access | T1078 | Valid Accounts | 20411 | 16 | high |
| Initial Access | T1190 | Exploit Public-Facing Application | 1480 | 16 | high |
| Execution | `T1059.004 ` | Unix Shell | 35300 | 16 | high |
| Persistence | `T1053.003 ` | Cron | 4049 | 16 | high |
| Persistence | T1098 | Account Manipulation | 549 | 12 | high |
| Persistence | `T1098.004 ` | SSH Authorized Keys | 388 | 12 | high |
| Stealth | `T1070.004 ` | File Deletion | 4282 | 16 | high |
| Stealth | `T1070.003 ` | Clear Command History | 343 | 16 | high |
| Defense Impairment | `T1222.002 ` | Linux and Mac Permissions | 946 | 16 | high |
| Credential Access | `T1110.001 ` | Password Guessing | 75306 | 17 | high |
| Credential Access | `T1552.001 ` | Credentials In Files | 4102 | 16 | high |
| Discovery | T1082 | System Information Discovery | 17758 | 16 | high |
| Discovery | T1057 | Process Discovery | 4037 | 16 | high |
| Discovery | T1033 | `System Owner/User Discovery ` | 682 | 14 | high |
| Discovery | T1083 | File and Directory Discovery | 374 | 16 | high |
| Discovery | T1016 | System Network Configuration Discovery | 131 | 11 | high |
| Command and Control | T1105 | Ingress Tool Transfer | 11919 | 16 | high |
| Command and Control | T1090 | Proxy | 3883 | 16 | high |
| Impact | `T1496.001 ` | Compute Hijacking | 3753 | 16 | high |

## Recommendations
- Patch or take offline anything affected by CVE-2017-9841 (PHPUnit eval-stdin remote code execution). _440 attempts on 13 agents in this period, listed by CISA as exploited in the wild._
- Patch or take offline anything affected by CVE-2026-104935 (Ivanti Connect Secure Authentication Bypass by Spoofing Vulnerability). _160 attempts on 16 agents in this period, listed by CISA as exploited in the wild._
- Patch or take offline anything affected by CVE-2026-123158 (OpenSSH password authentication bypass (musl libc without PAM)). _129 attempts on 10 agents in this period, listed by CISA as exploited in the wild._
- Patch or take offline anything affected by CVE-2021-41773 (Apache httpd path traversal). _104 attempts on 15 agents in this period, listed by CISA as exploited in the wild, known ransomware use._
- Patch or take offline anything affected by CVE-2021-44228 (Log4Shell). _101 attempts on 8 agents in this period, listed by CISA as exploited in the wild, known ransomware use._
- Patch or take offline anything affected by CVE-2018-13379 (FortiOS SSL VPN file read). _61 attempts on 16 agents in this period, listed by CISA as exploited in the wild, known ransomware use._
- Patch or take offline anything affected by CVE-2025-31324 (SAP NetWeaver Visual Composer file upload). _60 attempts on 16 agents in this period, listed by CISA as exploited in the wild, known ransomware use._
- Patch or take offline anything affected by CVE-2024-4577 (PHP-CGI argument injection). _56 attempts on 12 agents in this period, listed by CISA as exploited in the wild, known ransomware use._
- Patch or take offline anything affected by CVE-2026-96652 (Plex Media Server Server-Side Request Forgery (SSRF) Vulnerability). _45 attempts on 15 agents in this period, listed by CISA as exploited in the wild._
- Patch or take offline anything affected by CVE-2020-3452 (Cisco ASA and FTD Read-Only Path Traversal Vulnerability). _41 attempts on 16 agents in this period, listed by CISA as exploited in the wild._

## Method and limits
- Source: decoy services (honeypots) on internet-facing servers. They have no legitimate users, so everything recorded is unsolicited.
- Coverage: untargeted, automated activity. The fleet does not see targeted attacks on your organisation, and it does not observe what happens after a successful break-in.
- Confidence: high = seen by at least half of a multi-agent fleet and by ten or more addresses; medium = several addresses or more than one agent; low = a single agent and few addresses.
- Change is measured against the average of the seven preceding periods of equal length.
- ATT&CK techniques describe what a request attempted. No technique succeeded: decoys never execute what they receive.
- CVE dates and scores: CVE Program. Exploited-in-the-wild status: CISA KEV. Origin countries are where a network is registered, not necessarily where an operator sits.
