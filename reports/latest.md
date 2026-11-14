# Threat situation report
Period: last 7 days (2026-11-07 23:02 UTC to 2026-11-14 23:02 UTC) · 16 agents
## Key findings
- **High confidence.** The fleet has less history than this period, so there is no usual level yet: nothing here is called new or rising. _(comparisons start once the fleet has run for 336 hours)_
- **High confidence.** CVE-2017-9841 (PHPUnit eval-stdin remote code execution) is being attempted, a vulnerability CISA lists as exploited in the wild. _(187 attempts on 8 of 16 agents; first seen by the fleet 36 hours ago)_
- **Medium confidence.** CVE-2026-123158 (OpenSSH password authentication bypass (musl libc without PAM)) is being attempted, a vulnerability CISA lists as exploited in the wild. _(79 attempts on 7 of 16 agents; first seen by the fleet 21 hours ago)_
- **High confidence.** CVE-2024-4577 (PHP-CGI argument injection) is being attempted, a vulnerability CISA lists as exploited in the wild and used by ransomware groups. _(29 attempts on 10 of 16 agents; first seen by the fleet 43 hours ago)_
- **High confidence.** CVE-2021-41773 (Apache httpd path traversal) is being attempted, a vulnerability CISA lists as exploited in the wild and used by ransomware groups. _(16 attempts on 10 of 16 agents; first seen by the fleet 43 hours ago)_
- **High confidence.** The largest campaign uses 40 addresses with the same technique set (git-exposure). _(85 events on 12 of 16 agents)_

## Numbers
| Events | Attacking addresses | High severity | Blocked now | Language-model agents | New patterns |
|---|---|---|---|---|---|
| 949934 | 10824 | 4144 | 769 | 0 | 10 |

## Known exploits
| CVE | Name | CVSS | CISA | Events | Agents |
|---|---|---|---|---|---|
| CVE-2017-9841 | PHPUnit eval-stdin remote code execution | `9.8 ` | exploited | 187 | 8 |
| CVE-2026-123158 | OpenSSH password authentication bypass (musl libc without PAM) | `n/a ` | exploited | 79 | 7 |
| CVE-2024-4577 | PHP-CGI argument injection | `9.8 ` | exploited, ransomware | 29 | 10 |
| CVE-2021-41773 | Apache httpd path traversal | `7.5 ` | exploited, ransomware | 16 | 10 |
| CVE-2025-31324 | SAP NetWeaver Visual Composer file upload | `10.0 ` | exploited, ransomware | 14 | 14 |
| CVE-2018-20062 | ThinkPHP remote code execution | `9.8 ` | exploited | 11 | 5 |
| CVE-2018-13379 | FortiOS SSL VPN file read | `9.1 ` | exploited, ransomware | 8 | 4 |
| CVE-2018-10561 | GPON router authentication bypass | `9.8 ` | exploited | 5 | 4 |
| CVE-2021-44228 | Log4Shell | `10.0 ` | exploited, ransomware | 1 | 1 |

## Technologies under attack
| Technology | Events | Change | Agents |
|---|---|---|---|
| ssh | 36901 | no history yet | 16 |
| credential-attack | 31475 | no history yet | 16 |
| rdp | 19266 | no history yet | 16 |
| ssh-shell | 17857 | no history yet | 15 |
| telnet | 14720 | no history yet | 16 |
| ssh-login | 9619 | no history yet | 15 |
| shell-recon | 8923 | no history yet | 15 |
| smb | 6229 | no history yet | 15 |
| shell-download | 4930 | no history yet | 15 |
| smb1 | 3746 | no history yet | 15 |
| mssql | 3418 | no history yet | 15 |
| mysql | 2983 | no history yet | 15 |

## New request patterns
| Pattern | Events | Addresses | Confidence |
|---|---|---|---|
| `SSH-2.0-Go ` | 16640 | 475 | high |
| ssh root | 14833 | 527 | high |
| RDP tls,nla | 7873 | 281 | high |
| `0a07365cc01fa9fc82608ba4019af499 SSH-2.0-Go ` | 6369 | 117 | high |
| `GET / ` | 5557 | 2215 | high |
| (many distinct values from one address) | 5556 | 49 | high |
| `shell-recon > shell-download > shell-recon ` | 5395 | 45 | high |
| uname -s -v -n -r -m | 4944 | 99 | high |

## Campaigns
| Techniques | Addresses | Events | Agents |
|---|---|---|---|
| git-exposure | 40 | 85 | 12 |
| java-spring | 23 | 23 | 15 |
| admin-panel, iot-router | 22 | 22 | 11 |
| php, wordpress | 19 | 24 | 1 |
| env-secrets | 14 | 119 | 15 |

## Indicators (de-fanged, never fetch)
| Indicator | Attacking addresses |
|---|---|
| a8460f446be540410004b1a8db4083773fa46f7fe76fa84219c93daa1669f8f2 | 100 |
| e150a1ec81e8e93e1eae2c3a77e66ec6dbd6a3b460f89c1d08aecf422ee401a0 | 54 |
| 2634c3097f98e36865f0c572009c4ffd73316bc8b88ccfe8d196af35f46e2394 | 52 |
| c05b56ab6d3d07ccca6778ebd799bf98dfa2b7f10dd43601f0938f04e5070878 | 52 |
| a883dafc480d466ee04e0d6da986bd78eb1fdd2178d04693723da3a8f95d42f4 | 48 |
| 6b3a55e0261b0304143f805a24924d0c1c44524821305f31d9277843b8a10f4e | 44 |
| 6d78392a5886177fe5b86e585a0b695a2bcd01a05504b3c4e38bc8eeb21e8326 | 43 |
| `hxxp://103[.]160[.]59[.]94:28816/CZRmrtxnrNONBXhwfFeqjNfBrliNaShG ` | 40 |
| 9ba5884baa8b8a7533446fe7b6b5323d40b4ab1e335dc54a54be1a0a40459b07 | 40 |
| cc10ba3e72e09f1e742e4155968aa081fd309c76b6acf28eea1e3046438f005e | 40 |
| f33ae3bc9a22cd7564990a794789954409977013966fb1a8f43c35776b833a95 | 36 |
| 01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b | 34 |
| `hxxps://modat[.]io/ ` | 32 |
| 3c56dd5ed61af7e7b20f54288947a89a4891d181b10fe04560b55c5e82de1fa2 | 32 |
| 5ecf8d2cc410094e8b82dd0bc178a57f3aa1e80916689beb00fe56148b1b1256 | 31 |

## ATT&CK techniques
| Tactic | Technique | Name | Events | Agents | Confidence |
|---|---|---|---|---|---|
| Reconnaissance | `T1595.001 ` | Scanning IP Blocks | 68931 | 16 | high |
| Reconnaissance | `T1595.002 ` | Vulnerability Scanning | 2461 | 15 | high |
| Reconnaissance | `T1595.003 ` | Wordlist Scanning | 1951 | 16 | high |
| Reconnaissance | T1594 | Search Victim-Owned Websites | 624 | 15 | high |
| Initial Access | T1133 | External Remote Services | 27481 | 16 | high |
| Initial Access | T1078 | Valid Accounts | 9619 | 15 | high |
| Initial Access | T1190 | Exploit Public-Facing Application | 598 | 15 | high |
| Execution | `T1059.004 ` | Unix Shell | 18232 | 15 | high |
| Persistence | `T1053.003 ` | Cron | 1782 | 15 | high |
| Persistence | T1098 | Account Manipulation | 244 | 9 | high |
| Persistence | `T1098.004 ` | SSH Authorized Keys | 189 | 10 | high |
| Stealth | `T1070.004 ` | File Deletion | 1858 | 15 | high |
| Stealth | `T1070.003 ` | Clear Command History | 246 | 15 | high |
| Defense Impairment | `T1222.002 ` | Linux and Mac Permissions | 512 | 15 | high |
| Credential Access | `T1110.001 ` | Password Guessing | 31475 | 16 | high |
| Credential Access | `T1552.001 ` | Credentials In Files | 1084 | 15 | high |
| Discovery | T1082 | System Information Discovery | 8949 | 15 | high |
| Discovery | T1057 | Process Discovery | 1742 | 15 | high |
| Discovery | T1033 | `System Owner/User Discovery ` | 285 | 11 | high |
| Discovery | T1083 | File and Directory Discovery | 142 | 9 | high |
| Discovery | T1016 | System Network Configuration Discovery | 2 | 1 | low |
| Command and Control | T1105 | Ingress Tool Transfer | 5640 | 15 | high |
| Command and Control | T1090 | Proxy | 1168 | 15 | high |
| Impact | `T1496.001 ` | Compute Hijacking | 1642 | 15 | high |

## Recommendations
- Patch or take offline anything affected by CVE-2017-9841 (PHPUnit eval-stdin remote code execution). _187 attempts on 8 agents in this period, listed by CISA as exploited in the wild._
- Patch or take offline anything affected by CVE-2026-123158 (OpenSSH password authentication bypass (musl libc without PAM)). _79 attempts on 7 agents in this period, listed by CISA as exploited in the wild._
- Patch or take offline anything affected by CVE-2024-4577 (PHP-CGI argument injection). _29 attempts on 10 agents in this period, listed by CISA as exploited in the wild, known ransomware use._
- Patch or take offline anything affected by CVE-2021-41773 (Apache httpd path traversal). _16 attempts on 10 agents in this period, listed by CISA as exploited in the wild, known ransomware use._
- Patch or take offline anything affected by CVE-2025-31324 (SAP NetWeaver Visual Composer file upload). _14 attempts on 14 agents in this period, listed by CISA as exploited in the wild, known ransomware use._
- Patch or take offline anything affected by CVE-2018-20062 (ThinkPHP remote code execution). _11 attempts on 5 agents in this period, listed by CISA as exploited in the wild._
- Patch or take offline anything affected by CVE-2018-13379 (FortiOS SSL VPN file read). _8 attempts on 4 agents in this period, listed by CISA as exploited in the wild, known ransomware use._
- Patch or take offline anything affected by CVE-2018-10561 (GPON router authentication bypass). _5 attempts on 4 agents in this period, listed by CISA as exploited in the wild._
- Patch or take offline anything affected by CVE-2021-44228 (Log4Shell). _1 attempts on 1 agents in this period, listed by CISA as exploited in the wild, known ransomware use._
- Turn off password sign-in on internet-facing SSH, Telnet, FTP and admin logins; use keys or two-step sign-in. _Password guessing is constant and automated._

## Method and limits
- Source: decoy services (honeypots) on internet-facing servers. They have no legitimate users, so everything recorded is unsolicited.
- Coverage: untargeted, automated activity. The fleet does not see targeted attacks on your organisation, and it does not observe what happens after a successful break-in.
- Confidence: high = seen by at least half of a multi-agent fleet and by ten or more addresses; medium = several addresses or more than one agent; low = a single agent and few addresses.
- Change is measured against the average of the seven preceding periods of equal length.
- ATT&CK techniques describe what a request attempted. No technique succeeded: decoys never execute what they receive.
- CVE dates and scores: CVE Program. Exploited-in-the-wild status: CISA KEV. Origin countries are where a network is registered, not necessarily where an operator sits.
