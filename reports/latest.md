# Threat situation report
Period: last 7 days (2026-11-19 19:08 UTC to 2026-11-26 19:08 UTC) · 18 agents
## Key findings
- **High confidence.** Activity against redis is about 2 times its usual level. _(20691 events on 18 of 18 agents)_
- **High confidence.** Activity against iot-router is about 4 times its usual level. _(1812 events on 18 of 18 agents)_
- **High confidence.** Activity against java-spring is about 2 times its usual level. _(989 events on 18 of 18 agents)_
- **High confidence.** CVE-2025-55182 (React Server Components remote code execution (React2Shell)) is being attempted, a vulnerability CISA lists as exploited in the wild and used by ransomware groups. _(1221 attempts on 18 of 18 agents; first seen by the fleet 5 days ago)_
- **High confidence.** CVE-2017-9841 (PHPUnit eval-stdin remote code execution) is being attempted, a vulnerability CISA lists as exploited in the wild. _(744 attempts on 18 of 18 agents; first seen by the fleet 13 days ago)_
- **High confidence.** CVE-2025-30208 (Vite bypasses server\[.]fs\[.]deny with raw query) is being attempted. _(583 attempts on 14 of 18 agents; first seen by the fleet 13 days ago)_
- **High confidence.** CVE-2021-44228 (Log4Shell) is being attempted, a vulnerability CISA lists as exploited in the wild and used by ransomware groups. _(371 attempts on 9 of 18 agents; first seen by the fleet 12 days ago)_
- **High confidence.** 10 request patterns were seen for the first time; the most frequent is “GET /boaform/adminformlogout//boaform/admin/login\[.]asp”. _(1055 events from 497 addresses on 18 of 18 agents)_
- **High confidence.** The largest campaign uses 497 addresses with the same technique set (admin-panel, iot-router). _(1055 events on 18 of 18 agents)_

## Numbers
| Events | Attacking addresses | High severity | Blocked now | Language-model agents | New patterns |
|---|---|---|---|---|---|
| 9784388 | 38364 | 25425 | 1829 | 0 | 10 |

## Known exploits
| CVE | Name | CVSS | CISA | Events | Agents |
|---|---|---|---|---|---|
| CVE-2025-55182 | React Server Components remote code execution (React2Shell) | `n/a ` | exploited, ransomware | 1221 | 18 |
| CVE-2017-9841 | PHPUnit eval-stdin remote code execution | `9.8 ` | exploited | 744 | 18 |
| CVE-2025-30208 | `Vite bypasses server.fs.deny with raw query ` | `n/a ` | - | 583 | 14 |
| CVE-2021-44228 | Log4Shell | `10.0 ` | exploited, ransomware | 371 | 9 |
| CVE-2026-65694 | Microweber CMS path traversal via ServeStaticFileController | `n/a ` | - | 245 | 10 |
| CVE-2021-41773 | Apache httpd path traversal | `7.5 ` | exploited, ransomware | 219 | 15 |
| CVE-2025-31324 | SAP NetWeaver Visual Composer file upload | `10.0 ` | exploited, ransomware | 124 | 18 |
| CVE-2018-10561 | GPON router authentication bypass | `9.8 ` | exploited | 109 | 17 |
| CVE-2020-11547 | PRTG Network Monitor information disclosure | `n/a ` | - | 105 | 9 |
| CVE-2025-3248 | `Langflow unauthenticated RCE via /api/v1/validate/code ` | `n/a ` | exploited, ransomware | 104 | 17 |

## Technologies under attack
| Technology | Events | Change | Agents |
|---|---|---|---|
| ssh | 178633 | `1.23x ` | 18 |
| credential-attack | 177013 | `1.31x ` | 18 |
| ssh-shell | 61273 | `1.15x ` | 18 |
| smb | 55191 | `1.53x ` | 18 |
| telnet | 49507 | `1.05x ` | 18 |
| ssh-login | 46021 | `1.32x ` | 18 |
| mssql | 44826 | `1.51x ` | 18 |
| smb1 | 39026 | `1.65x ` | 18 |
| rdp | 33268 | `0.59x ` | 18 |
| shell-recon | 30609 | `1.16x ` | 18 |
| redis | 20702 | `2.05x ` | 18 |
| shell-download | 19413 | `1.22x ` | 18 |

## New request patterns
| Pattern | Events | Addresses | Confidence |
|---|---|---|---|
| `GET /boaform/adminformlogout//boaform/admin/login.asp ` | 1055 | 497 | high |
| `a591c4ddccc960a2da8099958270fc92 SSH-2.0-libssh_0.12.2 ` | 680 | 36 | high |
| `GET /etc/passwd ` | 664 | 32 | medium |
| `redis:6379 *2\x0d\x0a$4\x0d\x0aAUTH\x0d\x0a$0\x0d\x0a\x0d\x0a*1\x0d\x0a ` | 468 | 371 | high |
| `redis:6379 \x0d\x0aPING\x0d\x0a*2\x0d\x0a$4\x0d\x0aAUTH\x0d\x0a$6\x0d\x ` | 468 | 371 | high |
| `redis:6379 \x0d\x0a$6\x0d\x0a{n}\x0d\x0a*1\x0d\x0a$4\x0d\x0aPING\x0d ` | 462 | 367 | high |
| `redis:6379 3\x0d\x0a*1\x0d\x0a$4\x0d\x0aPING\x0d\x0a*2\x0d\x0a$4\x0d\x0 ` | 450 | 356 | high |
| `redis:6379 ost\x0d\x0a*1\x0d\x0a$4\x0d\x0aPING\x0d\x0a*2\x0d\x0a$4\x0d\ ` | 449 | 355 | high |

## Campaigns
| Techniques | Addresses | Events | Agents |
|---|---|---|---|
| admin-panel, iot-router | 497 | 1055 | 18 |
| admin-panel, iot-router | 132 | 135 | 18 |
| CVE-2025-31324 | 105 | 111 | 18 |
| env-secrets | 93 | 154 | 18 |
| llm-endpoint | 86 | 485 | 18 |

## Indicators (de-fanged, never fetch)
| Indicator | Attacking addresses |
|---|---|
| a8460f446be540410004b1a8db4083773fa46f7fe76fa84219c93daa1669f8f2 | 438 |
| 01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b | 181 |
| e150a1ec81e8e93e1eae2c3a77e66ec6dbd6a3b460f89c1d08aecf422ee401a0 | 114 |
| 2634c3097f98e36865f0c572009c4ffd73316bc8b88ccfe8d196af35f46e2394 | 113 |
| c05b56ab6d3d07ccca6778ebd799bf98dfa2b7f10dd43601f0938f04e5070878 | 113 |
| a883dafc480d466ee04e0d6da986bd78eb1fdd2178d04693723da3a8f95d42f4 | 112 |
| 5ecf8d2cc410094e8b82dd0bc178a57f3aa1e80916689beb00fe56148b1b1256 | 111 |
| 6d78392a5886177fe5b86e585a0b695a2bcd01a05504b3c4e38bc8eeb21e8326 | 110 |
| 6b3a55e0261b0304143f805a24924d0c1c44524821305f31d9277843b8a10f4e | 110 |
| cc10ba3e72e09f1e742e4155968aa081fd309c76b6acf28eea1e3046438f005e | 109 |
| f33ae3bc9a22cd7564990a794789954409977013966fb1a8f43c35776b833a95 | 107 |
| 3c56dd5ed61af7e7b20f54288947a89a4891d181b10fe04560b55c5e82de1fa2 | 107 |
| 53175bcc0524f37b47062fafdda28e3f8eb91d519ca0a184ca71bbebe72f969a | 105 |
| 3b5485dd0909db36922ecd8578f18da11954810e63582f302c10881ac5c47534 | 103 |
| 9d272f1f3e92f7c5efdcfdda0ab92facccd98c340be8be09064060503fd167e4 | 98 |

## ATT&CK techniques
| Tactic | Technique | Name | Events | Agents | Confidence |
|---|---|---|---|---|---|
| Reconnaissance | `T1595.001 ` | Scanning IP Blocks | 305306 | 18 | high |
| Reconnaissance | `T1595.002 ` | Vulnerability Scanning | 14805 | 18 | high |
| Reconnaissance | `T1595.003 ` | Wordlist Scanning | 12225 | 18 | high |
| Reconnaissance | T1594 | Search Victim-Owned Websites | 3158 | 18 | high |
| Initial Access | T1133 | External Remote Services | 127188 | 18 | high |
| Initial Access | T1078 | Valid Accounts | 46027 | 18 | high |
| Initial Access | T1190 | Exploit Public-Facing Application | 4308 | 18 | high |
| Execution | `T1059.004 ` | Unix Shell | 63019 | 18 | high |
| Persistence | `T1053.003 ` | Cron | 8491 | 18 | high |
| Persistence | T1098 | Account Manipulation | 632 | 18 | high |
| Persistence | `T1098.004 ` | SSH Authorized Keys | 453 | 17 | high |
| Stealth | `T1070.004 ` | File Deletion | 8993 | 18 | high |
| Stealth | `T1070.003 ` | Clear Command History | 197 | 18 | high |
| Defense Impairment | `T1222.002 ` | Linux and Mac Permissions | 665 | 18 | high |
| Credential Access | `T1110.001 ` | Password Guessing | 177013 | 18 | high |
| Credential Access | `T1552.001 ` | Credentials In Files | 3132 | 18 | high |
| Discovery | T1082 | System Information Discovery | 29393 | 18 | high |
| Discovery | T1057 | Process Discovery | 8721 | 18 | high |
| Discovery | T1033 | `System Owner/User Discovery ` | 2624 | 18 | high |
| Discovery | T1083 | File and Directory Discovery | 622 | 18 | high |
| Discovery | T1016 | System Network Configuration Discovery | 180 | 18 | high |
| Command and Control | T1105 | Ingress Tool Transfer | 21865 | 18 | high |
| Command and Control | T1090 | Proxy | 6798 | 18 | high |
| Impact | `T1496.001 ` | Compute Hijacking | 8277 | 18 | high |

## Recommendations
- Patch or take offline anything affected by CVE-2025-55182 (React Server Components remote code execution (React2Shell)). _1221 attempts on 18 agents in this period, listed by CISA as exploited in the wild, known ransomware use._
- Patch or take offline anything affected by CVE-2017-9841 (PHPUnit eval-stdin remote code execution). _744 attempts on 18 agents in this period, listed by CISA as exploited in the wild._
- Patch or take offline anything affected by CVE-2025-30208 (Vite bypasses server\[.]fs\[.]deny with raw query). _583 attempts on 14 agents in this period._
- Patch or take offline anything affected by CVE-2021-44228 (Log4Shell). _371 attempts on 9 agents in this period, listed by CISA as exploited in the wild, known ransomware use._
- Patch or take offline anything affected by CVE-2026-65694 (Microweber CMS path traversal via ServeStaticFileController). _245 attempts on 10 agents in this period._
- Patch or take offline anything affected by CVE-2021-41773 (Apache httpd path traversal). _219 attempts on 15 agents in this period, listed by CISA as exploited in the wild, known ransomware use._
- Patch or take offline anything affected by CVE-2025-31324 (SAP NetWeaver Visual Composer file upload). _124 attempts on 18 agents in this period, listed by CISA as exploited in the wild, known ransomware use._
- Patch or take offline anything affected by CVE-2018-10561 (GPON router authentication bypass). _109 attempts on 17 agents in this period, listed by CISA as exploited in the wild._
- Patch or take offline anything affected by CVE-2020-11547 (PRTG Network Monitor information disclosure). _105 attempts on 9 agents in this period._
- Patch or take offline anything affected by CVE-2025-3248 (Langflow unauthenticated RCE via /api/v1/validate/code). _104 attempts on 17 agents in this period, listed by CISA as exploited in the wild, known ransomware use._

## Method and limits
- Source: decoy services (honeypots) on internet-facing servers. They have no legitimate users, so everything recorded is unsolicited.
- Coverage: untargeted, automated activity. The fleet does not see targeted attacks on your organisation, and it does not observe what happens after a successful break-in.
- Confidence: high = seen by at least half of a multi-agent fleet and by ten or more addresses; medium = several addresses or more than one agent; low = a single agent and few addresses.
- Change is measured against the average of the seven preceding periods of equal length.
- ATT&CK techniques describe what a request attempted. No technique succeeded: decoys never execute what they receive.
- CVE dates and scores: CVE Program. Exploited-in-the-wild status: CISA KEV. Origin countries are where a network is registered, not necessarily where an operator sits.
