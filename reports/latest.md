# Threat situation report
Period: last 7 days (2026-11-20 02:17 UTC to 2026-11-27 02:17 UTC) · 18 agents
## Key findings
- **High confidence.** Activity against redis is about 2 times its usual level. _(21906 events on 18 of 18 agents)_
- **High confidence.** Activity against iot-router is about 4 times its usual level. _(1810 events on 18 of 18 agents)_
- **High confidence.** Activity against java-spring is about 2 times its usual level. _(1006 events on 18 of 18 agents)_
- **High confidence.** CVE-2025-55182 (React Server Components remote code execution (React2Shell)) is being attempted, a vulnerability CISA lists as exploited in the wild and used by ransomware groups. _(1284 attempts on 18 of 18 agents; first seen by the fleet 5 days ago)_
- **High confidence.** CVE-2017-9841 (PHPUnit eval-stdin remote code execution) is being attempted, a vulnerability CISA lists as exploited in the wild. _(863 attempts on 18 of 18 agents; first seen by the fleet 14 days ago)_
- **High confidence.** CVE-2025-30208 (Vite bypasses server\[.]fs\[.]deny with raw query) is being attempted. _(611 attempts on 16 of 18 agents; first seen by the fleet 13 days ago)_
- **High confidence.** CVE-2021-44228 (Log4Shell) is being attempted, a vulnerability CISA lists as exploited in the wild and used by ransomware groups. _(371 attempts on 9 of 18 agents; first seen by the fleet 13 days ago)_
- **High confidence.** 10 request patterns were seen for the first time; the most frequent is “a591c4ddccc960a2da8099958270fc92 SSH-2.0-libssh\_0.12.2”. _(717 events from 36 addresses on 10 of 18 agents)_
- **High confidence.** The largest campaign uses 503 addresses with the same technique set (admin-panel, iot-router). _(1065 events on 18 of 18 agents)_

## Numbers
| Events | Attacking addresses | High severity | Blocked now | Language-model agents | New patterns |
|---|---|---|---|---|---|
| 9907644 | 38225 | 25479 | 1936 | 0 | 10 |

## Known exploits
| CVE | Name | CVSS | CISA | Events | Agents |
|---|---|---|---|---|---|
| CVE-2025-55182 | React Server Components remote code execution (React2Shell) | `n/a ` | exploited, ransomware | 1284 | 18 |
| CVE-2017-9841 | PHPUnit eval-stdin remote code execution | `9.8 ` | exploited | 863 | 18 |
| CVE-2025-30208 | `Vite bypasses server.fs.deny with raw query ` | `n/a ` | - | 611 | 16 |
| CVE-2021-44228 | Log4Shell | `10.0 ` | exploited, ransomware | 371 | 9 |
| CVE-2026-65694 | Microweber CMS path traversal via ServeStaticFileController | `n/a ` | - | 245 | 10 |
| CVE-2021-41773 | Apache httpd path traversal | `7.5 ` | exploited, ransomware | 230 | 16 |
| CVE-2025-3248 | `Langflow unauthenticated RCE via /api/v1/validate/code ` | `n/a ` | exploited, ransomware | 134 | 18 |
| CVE-2025-31324 | SAP NetWeaver Visual Composer file upload | `10.0 ` | exploited, ransomware | 124 | 18 |
| CVE-2018-10561 | GPON router authentication bypass | `9.8 ` | exploited | 108 | 17 |
| CVE-2020-11547 | PRTG Network Monitor information disclosure | `n/a ` | - | 105 | 9 |

## Technologies under attack
| Technology | Events | Change | Agents |
|---|---|---|---|
| ssh | 189438 | `1.3x ` | 18 |
| credential-attack | 187399 | `1.39x ` | 18 |
| ssh-shell | 63211 | `1.2x ` | 18 |
| smb | 57559 | `1.58x ` | 18 |
| mssql | 49934 | `1.7x ` | 18 |
| telnet | 49328 | `1.05x ` | 18 |
| ssh-login | 47217 | `1.36x ` | 18 |
| smb1 | 41050 | `1.72x ` | 18 |
| rdp | 33476 | `0.6x ` | 18 |
| shell-recon | 30743 | `1.17x ` | 18 |
| redis | 21917 | `2.15x ` | 18 |
| shell-download | 19168 | `1.21x ` | 18 |

## New request patterns
| Pattern | Events | Addresses | Confidence |
|---|---|---|---|
| `a591c4ddccc960a2da8099958270fc92 SSH-2.0-libssh_0.12.2 ` | 717 | 36 | high |
| `GET /etc/passwd ` | 664 | 32 | medium |
| `redis:6379 *2\x0d\x0a$4\x0d\x0aAUTH\x0d\x0a$0\x0d\x0a\x0d\x0a*1\x0d\x0a ` | 594 | 449 | high |
| `redis:6379 \x0d\x0aPING\x0d\x0a*2\x0d\x0a$4\x0d\x0aAUTH\x0d\x0a$6\x0d\x ` | 594 | 449 | high |
| `redis:6379 \x0d\x0a$6\x0d\x0a{n}\x0d\x0a*1\x0d\x0a$4\x0d\x0aPING\x0d ` | 588 | 445 | high |
| `redis:6379 3\x0d\x0a*1\x0d\x0a$4\x0d\x0aPING\x0d\x0a*2\x0d\x0a$4\x0d\x0 ` | 573 | 432 | high |
| `redis:6379 ost\x0d\x0a*1\x0d\x0a$4\x0d\x0aPING\x0d\x0a*2\x0d\x0a$4\x0d\ ` | 572 | 431 | high |
| `redis:6379 9\x0d\x0anetcup{n}\x0d\x0a*1\x0d\x0a$4\x0d\x0aPING\x0d\x0a*2 ` | 572 | 431 | high |

## Campaigns
| Techniques | Addresses | Events | Agents |
|---|---|---|---|
| admin-panel, iot-router | 503 | 1065 | 18 |
| admin-panel, iot-router | 134 | 137 | 18 |
| CVE-2025-31324 | 105 | 111 | 18 |
| env-secrets | 96 | 160 | 18 |
| llm-endpoint | 85 | 493 | 18 |

## Indicators (de-fanged, never fetch)
| Indicator | Attacking addresses |
|---|---|
| a8460f446be540410004b1a8db4083773fa46f7fe76fa84219c93daa1669f8f2 | 455 |
| 01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b | 189 |
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
| Reconnaissance | `T1595.001 ` | Scanning IP Blocks | 317536 | 18 | high |
| Reconnaissance | `T1595.002 ` | Vulnerability Scanning | 14776 | 18 | high |
| Reconnaissance | `T1595.003 ` | Wordlist Scanning | 12340 | 18 | high |
| Reconnaissance | T1594 | Search Victim-Owned Websites | 3045 | 18 | high |
| Initial Access | T1133 | External Remote Services | 132555 | 18 | high |
| Initial Access | T1078 | Valid Accounts | 47223 | 18 | high |
| Initial Access | T1190 | Exploit Public-Facing Application | 4577 | 18 | high |
| Execution | `T1059.004 ` | Unix Shell | 64996 | 18 | high |
| Persistence | `T1053.003 ` | Cron | 8448 | 18 | high |
| Persistence | T1098 | Account Manipulation | 659 | 18 | high |
| Persistence | `T1098.004 ` | SSH Authorized Keys | 478 | 17 | high |
| Stealth | `T1070.004 ` | File Deletion | 8940 | 18 | high |
| Stealth | `T1070.003 ` | Clear Command History | 193 | 18 | high |
| Defense Impairment | `T1222.002 ` | Linux and Mac Permissions | 707 | 18 | high |
| Credential Access | `T1110.001 ` | Password Guessing | 187399 | 18 | high |
| Credential Access | `T1552.001 ` | Credentials In Files | 3203 | 18 | high |
| Discovery | T1082 | System Information Discovery | 29292 | 18 | high |
| Discovery | T1057 | Process Discovery | 8659 | 18 | high |
| Discovery | T1033 | `System Owner/User Discovery ` | 2902 | 18 | high |
| Discovery | T1083 | File and Directory Discovery | 630 | 18 | high |
| Discovery | T1016 | System Network Configuration Discovery | 138 | 18 | high |
| Command and Control | T1105 | Ingress Tool Transfer | 21669 | 18 | high |
| Command and Control | T1090 | Proxy | 6733 | 18 | high |
| Impact | `T1496.001 ` | Compute Hijacking | 8208 | 18 | high |

## Recommendations
- Patch or take offline anything affected by CVE-2025-55182 (React Server Components remote code execution (React2Shell)). _1284 attempts on 18 agents in this period, listed by CISA as exploited in the wild, known ransomware use._
- Patch or take offline anything affected by CVE-2017-9841 (PHPUnit eval-stdin remote code execution). _863 attempts on 18 agents in this period, listed by CISA as exploited in the wild._
- Patch or take offline anything affected by CVE-2025-30208 (Vite bypasses server\[.]fs\[.]deny with raw query). _611 attempts on 16 agents in this period._
- Patch or take offline anything affected by CVE-2021-44228 (Log4Shell). _371 attempts on 9 agents in this period, listed by CISA as exploited in the wild, known ransomware use._
- Patch or take offline anything affected by CVE-2026-65694 (Microweber CMS path traversal via ServeStaticFileController). _245 attempts on 10 agents in this period._
- Patch or take offline anything affected by CVE-2021-41773 (Apache httpd path traversal). _230 attempts on 16 agents in this period, listed by CISA as exploited in the wild, known ransomware use._
- Patch or take offline anything affected by CVE-2025-3248 (Langflow unauthenticated RCE via /api/v1/validate/code). _134 attempts on 18 agents in this period, listed by CISA as exploited in the wild, known ransomware use._
- Patch or take offline anything affected by CVE-2025-31324 (SAP NetWeaver Visual Composer file upload). _124 attempts on 18 agents in this period, listed by CISA as exploited in the wild, known ransomware use._
- Patch or take offline anything affected by CVE-2018-10561 (GPON router authentication bypass). _108 attempts on 17 agents in this period, listed by CISA as exploited in the wild._
- Patch or take offline anything affected by CVE-2020-11547 (PRTG Network Monitor information disclosure). _105 attempts on 9 agents in this period._

## Method and limits
- Source: decoy services (honeypots) on internet-facing servers. They have no legitimate users, so everything recorded is unsolicited.
- Coverage: untargeted, automated activity. The fleet does not see targeted attacks on your organisation, and it does not observe what happens after a successful break-in.
- Confidence: high = seen by at least half of a multi-agent fleet and by ten or more addresses; medium = several addresses or more than one agent; low = a single agent and few addresses.
- Change is measured against the average of the seven preceding periods of equal length.
- ATT&CK techniques describe what a request attempted. No technique succeeded: decoys never execute what they receive.
- CVE dates and scores: CVE Program. Exploited-in-the-wild status: CISA KEV. Origin countries are where a network is registered, not necessarily where an operator sits.
