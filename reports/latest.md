# Threat situation report
Period: last 7 days (2026-11-08 02:46 UTC to 2026-11-15 02:46 UTC) · 16 agents
## Key findings
- **High confidence.** The fleet has less history than this period, so there is no usual level yet: nothing here is called new or rising. _(comparisons start once the fleet has run for 336 hours)_
- **High confidence.** CVE-2017-9841 (PHPUnit eval-stdin remote code execution) is being attempted, a vulnerability CISA lists as exploited in the wild. _(187 attempts on 8 of 16 agents; first seen by the fleet 40 hours ago)_
- **High confidence.** CVE-2026-123158 (OpenSSH password authentication bypass (musl libc without PAM)) is being attempted, a vulnerability CISA lists as exploited in the wild. _(124 attempts on 8 of 16 agents; first seen by the fleet 25 hours ago)_
- **High confidence.** CVE-2024-4577 (PHP-CGI argument injection) is being attempted, a vulnerability CISA lists as exploited in the wild and used by ransomware groups. _(31 attempts on 10 of 16 agents; first seen by the fleet 47 hours ago)_
- **High confidence.** CVE-2025-31324 (SAP NetWeaver Visual Composer file upload) is being attempted, a vulnerability CISA lists as exploited in the wild and used by ransomware groups. _(29 attempts on 15 of 16 agents; first seen by the fleet 26 hours ago)_
- **High confidence.** The largest campaign uses 44 addresses with the same technique set (git-exposure). _(102 events on 12 of 16 agents)_

## Numbers
| Events | Attacking addresses | High severity | Blocked now | Language-model agents | New patterns |
|---|---|---|---|---|---|
| 1155369 | 11625 | 4740 | 778 | 0 | 10 |

## Known exploits
| CVE | Name | CVSS | CISA | Events | Agents |
|---|---|---|---|---|---|
| CVE-2017-9841 | PHPUnit eval-stdin remote code execution | `9.8 ` | exploited | 187 | 8 |
| CVE-2026-123158 | OpenSSH password authentication bypass (musl libc without PAM) | `n/a ` | exploited | 124 | 8 |
| CVE-2024-4577 | PHP-CGI argument injection | `9.8 ` | exploited, ransomware | 31 | 10 |
| CVE-2025-31324 | SAP NetWeaver Visual Composer file upload | `10.0 ` | exploited, ransomware | 29 | 15 |
| CVE-2021-41773 | Apache httpd path traversal | `7.5 ` | exploited, ransomware | 17 | 10 |
| CVE-2018-20062 | ThinkPHP remote code execution | `9.8 ` | exploited | 11 | 5 |
| CVE-2018-13379 | FortiOS SSL VPN file read | `9.1 ` | exploited, ransomware | 10 | 5 |
| CVE-2018-10561 | GPON router authentication bypass | `9.8 ` | exploited | 7 | 5 |
| CVE-2021-44228 | Log4Shell | `10.0 ` | exploited, ransomware | 1 | 1 |
| CVE-2023-23752 | Joomla configuration disclosure | `5.3 ` | exploited | 1 | 1 |

## Technologies under attack
| Technology | Events | Change | Agents |
|---|---|---|---|
| ssh | 40031 | no history yet | 16 |
| credential-attack | 34784 | no history yet | 16 |
| rdp | 20977 | no history yet | 16 |
| ssh-shell | 19156 | no history yet | 15 |
| telnet | 15429 | no history yet | 16 |
| ssh-login | 10624 | no history yet | 15 |
| shell-recon | 9519 | no history yet | 15 |
| smb | 6643 | no history yet | 15 |
| shell-download | 5390 | no history yet | 15 |
| mssql | 4368 | no history yet | 15 |
| smb1 | 4008 | no history yet | 15 |
| mysql | 3215 | no history yet | 15 |

## New request patterns
| Pattern | Events | Addresses | Confidence |
|---|---|---|---|
| `SSH-2.0-Go ` | 17940 | 512 | high |
| ssh root | 16098 | 565 | high |
| RDP tls,nla | 8952 | 311 | high |
| `0a07365cc01fa9fc82608ba4019af499 SSH-2.0-Go ` | 6806 | 122 | high |
| `GET / ` | 6321 | 2386 | high |
| `shell-recon > shell-download > shell-recon ` | 6206 | 51 | high |
| (many distinct values from one address) | 6110 | 52 | high |
| uname -s -v -n -r -m | 5385 | 104 | high |

## Campaigns
| Techniques | Addresses | Events | Agents |
|---|---|---|---|
| git-exposure | 44 | 102 | 12 |
| admin-panel, iot-router | 26 | 26 | 12 |
| java-spring | 23 | 23 | 15 |
| php, wordpress | 20 | 26 | 1 |
| env-secrets | 16 | 16 | 13 |

## Indicators (de-fanged, never fetch)
| Indicator | Attacking addresses |
|---|---|
| a8460f446be540410004b1a8db4083773fa46f7fe76fa84219c93daa1669f8f2 | 106 |
| e150a1ec81e8e93e1eae2c3a77e66ec6dbd6a3b460f89c1d08aecf422ee401a0 | 59 |
| 2634c3097f98e36865f0c572009c4ffd73316bc8b88ccfe8d196af35f46e2394 | 58 |
| c05b56ab6d3d07ccca6778ebd799bf98dfa2b7f10dd43601f0938f04e5070878 | 57 |
| a883dafc480d466ee04e0d6da986bd78eb1fdd2178d04693723da3a8f95d42f4 | 51 |
| 6d78392a5886177fe5b86e585a0b695a2bcd01a05504b3c4e38bc8eeb21e8326 | 48 |
| 6b3a55e0261b0304143f805a24924d0c1c44524821305f31d9277843b8a10f4e | 46 |
| cc10ba3e72e09f1e742e4155968aa081fd309c76b6acf28eea1e3046438f005e | 44 |
| f33ae3bc9a22cd7564990a794789954409977013966fb1a8f43c35776b833a95 | 41 |
| `hxxp://103[.]160[.]59[.]94:28816/CZRmrtxnrNONBXhwfFeqjNfBrliNaShG ` | 40 |
| 9ba5884baa8b8a7533446fe7b6b5323d40b4ab1e335dc54a54be1a0a40459b07 | 40 |
| 3c56dd5ed61af7e7b20f54288947a89a4891d181b10fe04560b55c5e82de1fa2 | 37 |
| 5ecf8d2cc410094e8b82dd0bc178a57f3aa1e80916689beb00fe56148b1b1256 | 35 |
| 01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b | 34 |
| `hxxps://modat[.]io/ ` | 32 |

## ATT&CK techniques
| Tactic | Technique | Name | Events | Agents | Confidence |
|---|---|---|---|---|---|
| Reconnaissance | `T1595.001 ` | Scanning IP Blocks | 74903 | 16 | high |
| Reconnaissance | `T1595.002 ` | Vulnerability Scanning | 2942 | 15 | high |
| Reconnaissance | `T1595.003 ` | Wordlist Scanning | 2269 | 16 | high |
| Reconnaissance | T1594 | Search Victim-Owned Websites | 744 | 15 | high |
| Initial Access | T1133 | External Remote Services | 29737 | 16 | high |
| Initial Access | T1078 | Valid Accounts | 10624 | 15 | high |
| Initial Access | T1190 | Exploit Public-Facing Application | 654 | 15 | high |
| Execution | `T1059.004 ` | Unix Shell | 19569 | 15 | high |
| Persistence | `T1053.003 ` | Cron | 1966 | 15 | high |
| Persistence | T1098 | Account Manipulation | 256 | 9 | high |
| Persistence | `T1098.004 ` | SSH Authorized Keys | 196 | 10 | high |
| Stealth | `T1070.004 ` | File Deletion | 2047 | 15 | high |
| Stealth | `T1070.003 ` | Clear Command History | 252 | 15 | high |
| Defense Impairment | `T1222.002 ` | Linux and Mac Permissions | 544 | 15 | high |
| Credential Access | `T1110.001 ` | Password Guessing | 34784 | 16 | high |
| Credential Access | `T1552.001 ` | Credentials In Files | 1140 | 15 | high |
| Discovery | T1082 | System Information Discovery | 9585 | 15 | high |
| Discovery | T1057 | Process Discovery | 1926 | 15 | high |
| Discovery | T1033 | `System Owner/User Discovery ` | 297 | 11 | high |
| Discovery | T1083 | File and Directory Discovery | 148 | 9 | high |
| Discovery | T1016 | System Network Configuration Discovery | 2 | 1 | low |
| Command and Control | T1105 | Ingress Tool Transfer | 6146 | 15 | high |
| Command and Control | T1090 | Proxy | 1466 | 15 | high |
| Impact | `T1496.001 ` | Compute Hijacking | 1820 | 15 | high |

## Recommendations
- Patch or take offline anything affected by CVE-2017-9841 (PHPUnit eval-stdin remote code execution). _187 attempts on 8 agents in this period, listed by CISA as exploited in the wild._
- Patch or take offline anything affected by CVE-2026-123158 (OpenSSH password authentication bypass (musl libc without PAM)). _124 attempts on 8 agents in this period, listed by CISA as exploited in the wild._
- Patch or take offline anything affected by CVE-2024-4577 (PHP-CGI argument injection). _31 attempts on 10 agents in this period, listed by CISA as exploited in the wild, known ransomware use._
- Patch or take offline anything affected by CVE-2025-31324 (SAP NetWeaver Visual Composer file upload). _29 attempts on 15 agents in this period, listed by CISA as exploited in the wild, known ransomware use._
- Patch or take offline anything affected by CVE-2021-41773 (Apache httpd path traversal). _17 attempts on 10 agents in this period, listed by CISA as exploited in the wild, known ransomware use._
- Patch or take offline anything affected by CVE-2018-20062 (ThinkPHP remote code execution). _11 attempts on 5 agents in this period, listed by CISA as exploited in the wild._
- Patch or take offline anything affected by CVE-2018-13379 (FortiOS SSL VPN file read). _10 attempts on 5 agents in this period, listed by CISA as exploited in the wild, known ransomware use._
- Patch or take offline anything affected by CVE-2018-10561 (GPON router authentication bypass). _7 attempts on 5 agents in this period, listed by CISA as exploited in the wild._
- Patch or take offline anything affected by CVE-2021-44228 (Log4Shell). _1 attempts on 1 agents in this period, listed by CISA as exploited in the wild, known ransomware use._
- Patch or take offline anything affected by CVE-2023-23752 (Joomla configuration disclosure). _1 attempts on 1 agents in this period, listed by CISA as exploited in the wild._

## Method and limits
- Source: decoy services (honeypots) on internet-facing servers. They have no legitimate users, so everything recorded is unsolicited.
- Coverage: untargeted, automated activity. The fleet does not see targeted attacks on your organisation, and it does not observe what happens after a successful break-in.
- Confidence: high = seen by at least half of a multi-agent fleet and by ten or more addresses; medium = several addresses or more than one agent; low = a single agent and few addresses.
- Change is measured against the average of the seven preceding periods of equal length.
- ATT&CK techniques describe what a request attempted. No technique succeeded: decoys never execute what they receive.
- CVE dates and scores: CVE Program. Exploited-in-the-wild status: CISA KEV. Origin countries are where a network is registered, not necessarily where an operator sits.
