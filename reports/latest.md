# Threat situation report
Period: last 7 days (2026-11-18 14:38 UTC to 2026-11-25 14:38 UTC) · 18 agents
## Key findings
- **High confidence.** The fleet has less history than this period, so there is no usual level yet: nothing here is called new or rising. _(comparisons start once the fleet has run for 336 hours)_
- **High confidence.** CVE-2017-9841 (PHPUnit eval-stdin remote code execution) is being attempted, a vulnerability CISA lists as exploited in the wild. _(1828 attempts on 18 of 18 agents; first seen by the fleet 12 days ago)_
- **High confidence.** CVE-2025-55182 (React Server Components remote code execution (React2Shell)) is being attempted, a vulnerability CISA lists as exploited in the wild and used by ransomware groups. _(879 attempts on 18 of 18 agents; first seen by the fleet 4 days ago)_
- **High confidence.** CVE-2025-30208 (Vite bypasses server\[.]fs\[.]deny with raw query) is being attempted. _(537 attempts on 14 of 18 agents; first seen by the fleet 12 days ago)_
- **Medium confidence.** CVE-2021-44228 (Log4Shell) is being attempted, a vulnerability CISA lists as exploited in the wild and used by ransomware groups. _(370 attempts on 8 of 18 agents; first seen by the fleet 11 days ago)_
- **High confidence.** The largest campaign uses 471 addresses with the same technique set (admin-panel, iot-router). _(1002 events on 18 of 18 agents)_

## Numbers
| Events | Attacking addresses | High severity | Blocked now | Language-model agents | New patterns |
|---|---|---|---|---|---|
| 9720980 | 38758 | 28340 | 909 | 0 | 10 |

## Known exploits
| CVE | Name | CVSS | CISA | Events | Agents |
|---|---|---|---|---|---|
| CVE-2017-9841 | PHPUnit eval-stdin remote code execution | `9.8 ` | exploited | 1828 | 18 |
| CVE-2025-55182 | React Server Components remote code execution (React2Shell) | `n/a ` | exploited, ransomware | 879 | 18 |
| CVE-2025-30208 | `Vite bypasses server.fs.deny with raw query ` | `n/a ` | - | 537 | 14 |
| CVE-2021-44228 | Log4Shell | `10.0 ` | exploited, ransomware | 370 | 8 |
| CVE-2026-65694 | Microweber CMS path traversal via ServeStaticFileController | `n/a ` | - | 239 | 10 |
| CVE-2021-41773 | Apache httpd path traversal | `7.5 ` | exploited, ransomware | 214 | 15 |
| CVE-2021-3129 | Laravel Ignition remote code execution | `9.8 ` | exploited, ransomware | 128 | 1 |
| CVE-2025-31324 | SAP NetWeaver Visual Composer file upload | `10.0 ` | exploited, ransomware | 123 | 18 |
| CVE-2018-10561 | GPON router authentication bypass | `9.8 ` | exploited | 104 | 17 |
| CVE-2025-3248 | `Langflow unauthenticated RCE via /api/v1/validate/code ` | `n/a ` | exploited, ransomware | 102 | 17 |

## Technologies under attack
| Technology | Events | Change | Agents |
|---|---|---|---|
| credential-attack | 152270 | no history yet | 18 |
| ssh | 135786 | no history yet | 18 |
| telnet | 52707 | no history yet | 18 |
| ssh-shell | 50314 | no history yet | 18 |
| smb | 50156 | no history yet | 18 |
| mssql | 40708 | no history yet | 18 |
| ssh-login | 38870 | no history yet | 18 |
| smb1 | 34340 | no history yet | 18 |
| rdp | 33641 | no history yet | 18 |
| shell-recon | 26816 | no history yet | 18 |
| shell-download | 19170 | no history yet | 18 |
| redis | 16411 | no history yet | 18 |

## New request patterns
| Pattern | Events | Addresses | Confidence |
|---|---|---|---|
| telnet chinadsl-net | 2846 | 5 | medium |
| telnet router | 2841 | 7 | medium |
| `SSH-2.0-paramiko_5.1.0 ` | 1504 | 141 | medium |
| `4c94058d5e9e31659879f79fd5b46084 SSH-2.0-paramiko_5.1.0 ` | 1026 | 112 | medium |
| `GET /boaform/adminformlogout//boaform/admin/login.asp ` | 1002 | 471 | high |
| `GET /etc/passwd ` | 664 | 32 | medium |
| `a591c4ddccc960a2da8099958270fc92 SSH-2.0-libssh_0.12.2 ` | 500 | 33 | medium |
| `6372ee6957562199b2fb773b0be1bf34 SSH-2.0-paramiko_5.1.0 ` | 371 | 102 | medium |

## Campaigns
| Techniques | Addresses | Events | Agents |
|---|---|---|---|
| admin-panel, iot-router | 471 | 1002 | 18 |
| admin-panel, iot-router | 120 | 124 | 18 |
| CVE-2025-31324 | 109 | 114 | 18 |
| java-spring | 79 | 80 | 18 |
| env-secrets | 77 | 111 | 18 |

## Indicators (de-fanged, never fetch)
| Indicator | Attacking addresses |
|---|---|
| a8460f446be540410004b1a8db4083773fa46f7fe76fa84219c93daa1669f8f2 | 340 |
| 01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b | 147 |
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
| 3b5485dd0909db36922ecd8578f18da11954810e63582f302c10881ac5c47534 | 98 |
| 9d272f1f3e92f7c5efdcfdda0ab92facccd98c340be8be09064060503fd167e4 | 96 |

## ATT&CK techniques
| Tactic | Technique | Name | Events | Agents | Confidence |
|---|---|---|---|---|---|
| Reconnaissance | `T1595.001 ` | Scanning IP Blocks | 274232 | 18 | high |
| Reconnaissance | `T1595.002 ` | Vulnerability Scanning | 17207 | 18 | high |
| Reconnaissance | `T1595.003 ` | Wordlist Scanning | 13941 | 18 | high |
| Reconnaissance | T1594 | Search Victim-Owned Websites | 5126 | 18 | high |
| Initial Access | T1133 | External Remote Services | 106881 | 18 | high |
| Initial Access | T1078 | Valid Accounts | 38879 | 18 | high |
| Initial Access | T1190 | Exploit Public-Facing Application | 5045 | 18 | high |
| Execution | `T1059.004 ` | Unix Shell | 51753 | 18 | high |
| Persistence | `T1053.003 ` | Cron | 8396 | 18 | high |
| Persistence | T1098 | Account Manipulation | 392 | 15 | high |
| Persistence | `T1098.004 ` | SSH Authorized Keys | 217 | 10 | high |
| Stealth | `T1070.004 ` | File Deletion | 8762 | 18 | high |
| Stealth | `T1070.003 ` | Clear Command History | 199 | 18 | high |
| Defense Impairment | `T1222.002 ` | Linux and Mac Permissions | 445 | 18 | high |
| Credential Access | `T1110.001 ` | Password Guessing | 152270 | 18 | high |
| Credential Access | `T1552.001 ` | Credentials In Files | 4732 | 18 | high |
| Discovery | T1082 | System Information Discovery | 27298 | 18 | high |
| Discovery | T1057 | Process Discovery | 8514 | 18 | high |
| Discovery | T1033 | `System Owner/User Discovery ` | 600 | 18 | high |
| Discovery | T1083 | File and Directory Discovery | 305 | 17 | high |
| Discovery | T1016 | System Network Configuration Discovery | 155 | 16 | high |
| Command and Control | T1105 | Ingress Tool Transfer | 21300 | 18 | high |
| Command and Control | T1090 | Proxy | 7775 | 18 | high |
| Impact | `T1496.001 ` | Compute Hijacking | 8275 | 18 | high |

## Recommendations
- Patch or take offline anything affected by CVE-2017-9841 (PHPUnit eval-stdin remote code execution). _1828 attempts on 18 agents in this period, listed by CISA as exploited in the wild._
- Patch or take offline anything affected by CVE-2025-55182 (React Server Components remote code execution (React2Shell)). _879 attempts on 18 agents in this period, listed by CISA as exploited in the wild, known ransomware use._
- Patch or take offline anything affected by CVE-2025-30208 (Vite bypasses server\[.]fs\[.]deny with raw query). _537 attempts on 14 agents in this period._
- Patch or take offline anything affected by CVE-2021-44228 (Log4Shell). _370 attempts on 8 agents in this period, listed by CISA as exploited in the wild, known ransomware use._
- Patch or take offline anything affected by CVE-2026-65694 (Microweber CMS path traversal via ServeStaticFileController). _239 attempts on 10 agents in this period._
- Patch or take offline anything affected by CVE-2021-41773 (Apache httpd path traversal). _214 attempts on 15 agents in this period, listed by CISA as exploited in the wild, known ransomware use._
- Patch or take offline anything affected by CVE-2021-3129 (Laravel Ignition remote code execution). _128 attempts on 1 agents in this period, listed by CISA as exploited in the wild, known ransomware use._
- Patch or take offline anything affected by CVE-2025-31324 (SAP NetWeaver Visual Composer file upload). _123 attempts on 18 agents in this period, listed by CISA as exploited in the wild, known ransomware use._
- Patch or take offline anything affected by CVE-2018-10561 (GPON router authentication bypass). _104 attempts on 17 agents in this period, listed by CISA as exploited in the wild._
- Patch or take offline anything affected by CVE-2025-3248 (Langflow unauthenticated RCE via /api/v1/validate/code). _102 attempts on 17 agents in this period, listed by CISA as exploited in the wild, known ransomware use._

## Method and limits
- Source: decoy services (honeypots) on internet-facing servers. They have no legitimate users, so everything recorded is unsolicited.
- Coverage: untargeted, automated activity. The fleet does not see targeted attacks on your organisation, and it does not observe what happens after a successful break-in.
- Confidence: high = seen by at least half of a multi-agent fleet and by ten or more addresses; medium = several addresses or more than one agent; low = a single agent and few addresses.
- Change is measured against the average of the seven preceding periods of equal length.
- ATT&CK techniques describe what a request attempted. No technique succeeded: decoys never execute what they receive.
- CVE dates and scores: CVE Program. Exploited-in-the-wild status: CISA KEV. Origin countries are where a network is registered, not necessarily where an operator sits.
