# Threat situation report
Period: last 7 days (2026-11-18 23:41 UTC to 2026-11-25 23:41 UTC) · 18 agents
## Key findings
- **High confidence.** The fleet has less history than this period, so there is no usual level yet: nothing here is called new or rising. _(comparisons start once the fleet has run for 336 hours)_
- **High confidence.** CVE-2017-9841 (PHPUnit eval-stdin remote code execution) is being attempted, a vulnerability CISA lists as exploited in the wild. _(1156 attempts on 18 of 18 agents; first seen by the fleet 13 days ago)_
- **High confidence.** CVE-2025-55182 (React Server Components remote code execution (React2Shell)) is being attempted, a vulnerability CISA lists as exploited in the wild and used by ransomware groups. _(988 attempts on 18 of 18 agents; first seen by the fleet 4 days ago)_
- **High confidence.** CVE-2025-30208 (Vite bypasses server\[.]fs\[.]deny with raw query) is being attempted. _(568 attempts on 15 of 18 agents; first seen by the fleet 12 days ago)_
- **Medium confidence.** CVE-2021-44228 (Log4Shell) is being attempted, a vulnerability CISA lists as exploited in the wild and used by ransomware groups. _(370 attempts on 8 of 18 agents; first seen by the fleet 12 days ago)_
- **High confidence.** The largest campaign uses 481 addresses with the same technique set (admin-panel, iot-router). _(1025 events on 18 of 18 agents)_

## Numbers
| Events | Attacking addresses | High severity | Blocked now | Language-model agents | New patterns |
|---|---|---|---|---|---|
| 9731829 | 38168 | 25851 | 1147 | 0 | 10 |

## Known exploits
| CVE | Name | CVSS | CISA | Events | Agents |
|---|---|---|---|---|---|
| CVE-2017-9841 | PHPUnit eval-stdin remote code execution | `9.8 ` | exploited | 1156 | 18 |
| CVE-2025-55182 | React Server Components remote code execution (React2Shell) | `n/a ` | exploited, ransomware | 988 | 18 |
| CVE-2025-30208 | `Vite bypasses server.fs.deny with raw query ` | `n/a ` | - | 568 | 15 |
| CVE-2021-44228 | Log4Shell | `10.0 ` | exploited, ransomware | 370 | 8 |
| CVE-2026-65694 | Microweber CMS path traversal via ServeStaticFileController | `n/a ` | - | 245 | 10 |
| CVE-2021-41773 | Apache httpd path traversal | `7.5 ` | exploited, ransomware | 214 | 15 |
| CVE-2025-31324 | SAP NetWeaver Visual Composer file upload | `10.0 ` | exploited, ransomware | 123 | 18 |
| CVE-2018-10561 | GPON router authentication bypass | `9.8 ` | exploited | 107 | 17 |
| CVE-2025-3248 | `Langflow unauthenticated RCE via /api/v1/validate/code ` | `n/a ` | exploited, ransomware | 102 | 17 |
| CVE-2023-1389 | TP-Link Archer command injection | `8.8 ` | exploited | 88 | 18 |

## Technologies under attack
| Technology | Events | Change | Agents |
|---|---|---|---|
| credential-attack | 156838 | no history yet | 18 |
| ssh | 145172 | no history yet | 18 |
| ssh-shell | 52758 | no history yet | 18 |
| telnet | 52042 | no history yet | 18 |
| smb | 50599 | no history yet | 18 |
| ssh-login | 40421 | no history yet | 18 |
| mssql | 40384 | no history yet | 18 |
| smb1 | 34424 | no history yet | 18 |
| rdp | 32918 | no history yet | 18 |
| shell-recon | 27946 | no history yet | 18 |
| shell-download | 19470 | no history yet | 18 |
| redis | 17729 | no history yet | 18 |

## New request patterns
| Pattern | Events | Addresses | Confidence |
|---|---|---|---|
| telnet chinadsl-net | 2930 | 5 | medium |
| `GET /boaform/adminformlogout//boaform/admin/login.asp ` | 1025 | 481 | high |
| `GET /etc/passwd ` | 664 | 32 | medium |
| `a591c4ddccc960a2da8099958270fc92 SSH-2.0-libssh_0.12.2 ` | 564 | 34 | medium |
| `6372ee6957562199b2fb773b0be1bf34 SSH-2.0-paramiko_5.1.0 ` | 371 | 102 | medium |
| `POST / [body: cve-2025-55182] ` | 263 | 24 | high |
| `GET /api/settings ` | 246 | 3 | medium |
| `rdp 45.76.127.99 ` | 237 | 23 | medium |

## Campaigns
| Techniques | Addresses | Events | Agents |
|---|---|---|---|
| admin-panel, iot-router | 481 | 1025 | 18 |
| admin-panel, iot-router | 122 | 126 | 18 |
| CVE-2025-31324 | 109 | 114 | 18 |
| java-spring | 79 | 80 | 18 |
| llm-endpoint | 78 | 411 | 18 |

## Indicators (de-fanged, never fetch)
| Indicator | Attacking addresses |
|---|---|
| a8460f446be540410004b1a8db4083773fa46f7fe76fa84219c93daa1669f8f2 | 372 |
| 01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b | 159 |
| e150a1ec81e8e93e1eae2c3a77e66ec6dbd6a3b460f89c1d08aecf422ee401a0 | 114 |
| 2634c3097f98e36865f0c572009c4ffd73316bc8b88ccfe8d196af35f46e2394 | 113 |
| c05b56ab6d3d07ccca6778ebd799bf98dfa2b7f10dd43601f0938f04e5070878 | 113 |
| a883dafc480d466ee04e0d6da986bd78eb1fdd2178d04693723da3a8f95d42f4 | 112 |
| 5ecf8d2cc410094e8b82dd0bc178a57f3aa1e80916689beb00fe56148b1b1256 | 111 |
| 6d78392a5886177fe5b86e585a0b695a2bcd01a05504b3c4e38bc8eeb21e8326 | 110 |
| 6b3a55e0261b0304143f805a24924d0c1c44524821305f31d9277843b8a10f4e | 110 |
| cc10ba3e72e09f1e742e4155968aa081fd309c76b6acf28eea1e3046438f005e | 109 |
| 3c56dd5ed61af7e7b20f54288947a89a4891d181b10fe04560b55c5e82de1fa2 | 107 |
| f33ae3bc9a22cd7564990a794789954409977013966fb1a8f43c35776b833a95 | 106 |
| 53175bcc0524f37b47062fafdda28e3f8eb91d519ca0a184ca71bbebe72f969a | 105 |
| 3b5485dd0909db36922ecd8578f18da11954810e63582f302c10881ac5c47534 | 99 |
| 9d272f1f3e92f7c5efdcfdda0ab92facccd98c340be8be09064060503fd167e4 | 96 |

## ATT&CK techniques
| Tactic | Technique | Name | Events | Agents | Confidence |
|---|---|---|---|---|---|
| Reconnaissance | `T1595.001 ` | Scanning IP Blocks | 279107 | 18 | high |
| Reconnaissance | `T1595.002 ` | Vulnerability Scanning | 16131 | 18 | high |
| Reconnaissance | `T1595.003 ` | Wordlist Scanning | 13126 | 18 | high |
| Reconnaissance | T1594 | Search Victim-Owned Websites | 4379 | 18 | high |
| Initial Access | T1133 | External Remote Services | 111541 | 18 | high |
| Initial Access | T1078 | Valid Accounts | 40427 | 18 | high |
| Initial Access | T1190 | Exploit Public-Facing Application | 4402 | 18 | high |
| Execution | `T1059.004 ` | Unix Shell | 54296 | 18 | high |
| Persistence | `T1053.003 ` | Cron | 8503 | 18 | high |
| Persistence | T1098 | Account Manipulation | 472 | 18 | high |
| Persistence | `T1098.004 ` | SSH Authorized Keys | 284 | 15 | high |
| Stealth | `T1070.004 ` | File Deletion | 8894 | 18 | high |
| Stealth | `T1070.003 ` | Clear Command History | 198 | 18 | high |
| Defense Impairment | `T1222.002 ` | Linux and Mac Permissions | 516 | 18 | high |
| Credential Access | `T1110.001 ` | Password Guessing | 156838 | 18 | high |
| Credential Access | `T1552.001 ` | Credentials In Files | 4101 | 18 | high |
| Discovery | T1082 | System Information Discovery | 28156 | 18 | high |
| Discovery | T1057 | Process Discovery | 8664 | 18 | high |
| Discovery | T1033 | `System Owner/User Discovery ` | 990 | 18 | high |
| Discovery | T1083 | File and Directory Discovery | 405 | 18 | high |
| Discovery | T1016 | System Network Configuration Discovery | 162 | 16 | high |
| Command and Control | T1105 | Ingress Tool Transfer | 21693 | 18 | high |
| Command and Control | T1090 | Proxy | 7321 | 18 | high |
| Impact | `T1496.001 ` | Compute Hijacking | 8351 | 18 | high |

## Recommendations
- Patch or take offline anything affected by CVE-2017-9841 (PHPUnit eval-stdin remote code execution). _1156 attempts on 18 agents in this period, listed by CISA as exploited in the wild._
- Patch or take offline anything affected by CVE-2025-55182 (React Server Components remote code execution (React2Shell)). _988 attempts on 18 agents in this period, listed by CISA as exploited in the wild, known ransomware use._
- Patch or take offline anything affected by CVE-2025-30208 (Vite bypasses server\[.]fs\[.]deny with raw query). _568 attempts on 15 agents in this period._
- Patch or take offline anything affected by CVE-2021-44228 (Log4Shell). _370 attempts on 8 agents in this period, listed by CISA as exploited in the wild, known ransomware use._
- Patch or take offline anything affected by CVE-2026-65694 (Microweber CMS path traversal via ServeStaticFileController). _245 attempts on 10 agents in this period._
- Patch or take offline anything affected by CVE-2021-41773 (Apache httpd path traversal). _214 attempts on 15 agents in this period, listed by CISA as exploited in the wild, known ransomware use._
- Patch or take offline anything affected by CVE-2025-31324 (SAP NetWeaver Visual Composer file upload). _123 attempts on 18 agents in this period, listed by CISA as exploited in the wild, known ransomware use._
- Patch or take offline anything affected by CVE-2018-10561 (GPON router authentication bypass). _107 attempts on 17 agents in this period, listed by CISA as exploited in the wild._
- Patch or take offline anything affected by CVE-2025-3248 (Langflow unauthenticated RCE via /api/v1/validate/code). _102 attempts on 17 agents in this period, listed by CISA as exploited in the wild, known ransomware use._
- Patch or take offline anything affected by CVE-2023-1389 (TP-Link Archer command injection). _88 attempts on 18 agents in this period, listed by CISA as exploited in the wild._

## Method and limits
- Source: decoy services (honeypots) on internet-facing servers. They have no legitimate users, so everything recorded is unsolicited.
- Coverage: untargeted, automated activity. The fleet does not see targeted attacks on your organisation, and it does not observe what happens after a successful break-in.
- Confidence: high = seen by at least half of a multi-agent fleet and by ten or more addresses; medium = several addresses or more than one agent; low = a single agent and few addresses.
- Change is measured against the average of the seven preceding periods of equal length.
- ATT&CK techniques describe what a request attempted. No technique succeeded: decoys never execute what they receive.
- CVE dates and scores: CVE Program. Exploited-in-the-wild status: CISA KEV. Origin countries are where a network is registered, not necessarily where an operator sits.
