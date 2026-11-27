# Threat situation report
Period: last 7 days (2026-11-20 10:59 UTC to 2026-11-27 10:59 UTC) · 18 agents
## Key findings
- **High confidence.** Activity against redis is about 2 times its usual level. _(23861 events on 18 of 18 agents)_
- **High confidence.** Activity against iot-router is about 3 times its usual level. _(1793 events on 18 of 18 agents)_
- **High confidence.** Activity against java-spring is about 2 times its usual level. _(998 events on 18 of 18 agents)_
- **High confidence.** CVE-2025-55182 (React Server Components remote code execution (React2Shell)) is being attempted, a vulnerability CISA lists as exploited in the wild and used by ransomware groups. _(1317 attempts on 18 of 18 agents; first seen by the fleet 6 days ago)_
- **High confidence.** CVE-2017-9841 (PHPUnit eval-stdin remote code execution) is being attempted, a vulnerability CISA lists as exploited in the wild. _(891 attempts on 18 of 18 agents; first seen by the fleet 14 days ago)_
- **High confidence.** CVE-2025-30208 (Vite bypasses server\[.]fs\[.]deny with raw query) is being attempted. _(636 attempts on 17 of 18 agents; first seen by the fleet 13 days ago)_
- **High confidence.** CVE-2021-44228 (Log4Shell) is being attempted, a vulnerability CISA lists as exploited in the wild and used by ransomware groups. _(371 attempts on 9 of 18 agents; first seen by the fleet 13 days ago)_
- **High confidence.** 10 request patterns were seen for the first time; the most frequent is “a591c4ddccc960a2da8099958270fc92 SSH-2.0-libssh\_0.12.2”. _(823 events from 36 addresses on 12 of 18 agents)_
- **High confidence.** The largest campaign uses 465 addresses with the same technique set (admin-panel, iot-router). _(987 events on 18 of 18 agents)_

## Numbers
| Events | Attacking addresses | High severity | Blocked now | Language-model agents | New patterns |
|---|---|---|---|---|---|
| 9996828 | 39139 | 25395 | 2052 | 0 | 10 |

## Known exploits
| CVE | Name | CVSS | CISA | Events | Agents |
|---|---|---|---|---|---|
| CVE-2025-55182 | React Server Components remote code execution (React2Shell) | `n/a ` | exploited, ransomware | 1317 | 18 |
| CVE-2017-9841 | PHPUnit eval-stdin remote code execution | `9.8 ` | exploited | 891 | 18 |
| CVE-2025-30208 | `Vite bypasses server.fs.deny with raw query ` | `n/a ` | - | 636 | 17 |
| CVE-2021-44228 | Log4Shell | `10.0 ` | exploited, ransomware | 371 | 9 |
| CVE-2026-65694 | Microweber CMS path traversal via ServeStaticFileController | `n/a ` | - | 245 | 10 |
| CVE-2021-41773 | Apache httpd path traversal | `7.5 ` | exploited, ransomware | 231 | 16 |
| CVE-2025-31324 | SAP NetWeaver Visual Composer file upload | `10.0 ` | exploited, ransomware | 142 | 18 |
| CVE-2025-3248 | `Langflow unauthenticated RCE via /api/v1/validate/code ` | `n/a ` | exploited, ransomware | 134 | 18 |
| CVE-2018-10561 | GPON router authentication bypass | `9.8 ` | exploited | 110 | 17 |
| CVE-2020-11547 | PRTG Network Monitor information disclosure | `n/a ` | - | 105 | 9 |

## Technologies under attack
| Technology | Events | Change | Agents |
|---|---|---|---|
| credential-attack | 199514 | `1.47x ` | 18 |
| ssh | 199078 | `1.36x ` | 18 |
| ssh-shell | 65994 | `1.25x ` | 18 |
| smb | 62404 | `1.67x ` | 18 |
| mssql | 56788 | `1.89x ` | 18 |
| telnet | 49434 | `1.05x ` | 18 |
| ssh-login | 49365 | `1.4x ` | 18 |
| smb1 | 45921 | `1.89x ` | 18 |
| rdp | 32571 | `0.59x ` | 18 |
| shell-recon | 30832 | `1.17x ` | 18 |
| redis | 23871 | `2.29x ` | 18 |
| shell-download | 18718 | `1.16x ` | 18 |

## New request patterns
| Pattern | Events | Addresses | Confidence |
|---|---|---|---|
| `a591c4ddccc960a2da8099958270fc92 SSH-2.0-libssh_0.12.2 ` | 823 | 36 | high |
| `redis:6379 *2\x0d\x0a$4\x0d\x0aAUTH\x0d\x0a$0\x0d\x0a\x0d\x0a*1\x0d\x0a ` | 773 | 549 | high |
| `redis:6379 \x0d\x0aPING\x0d\x0a*2\x0d\x0a$4\x0d\x0aAUTH\x0d\x0a$6\x0d\x ` | 773 | 549 | high |
| `redis:6379 \x0d\x0a$6\x0d\x0a{n}\x0d\x0a*1\x0d\x0a$4\x0d\x0aPING\x0d ` | 764 | 543 | high |
| `redis:6379 3\x0d\x0a*1\x0d\x0a$4\x0d\x0aPING\x0d\x0a*2\x0d\x0a$4\x0d\x0 ` | 743 | 525 | high |
| `redis:6379 ost\x0d\x0a*1\x0d\x0a$4\x0d\x0aPING\x0d\x0a*2\x0d\x0a$4\x0d\ ` | 742 | 524 | high |
| `redis:6379 9\x0d\x0anetcup{n}\x0d\x0a*1\x0d\x0a$4\x0d\x0aPING\x0d\x0a*2 ` | 742 | 524 | high |
| `redis:6379 AUTH\x0d\x0a$6\x0d\x0avpn{n}\x0d\x0a*1\x0d\x0a$4\x0d\x0aPING ` | 726 | 513 | high |

## Campaigns
| Techniques | Addresses | Events | Agents |
|---|---|---|---|
| admin-panel, iot-router | 465 | 987 | 18 |
| admin-panel, iot-router | 128 | 132 | 18 |
| CVE-2025-31324 | 106 | 111 | 18 |
| env-secrets | 97 | 163 | 18 |
| llm-endpoint | 93 | 488 | 18 |

## Indicators (de-fanged, never fetch)
| Indicator | Attacking addresses |
|---|---|
| a8460f446be540410004b1a8db4083773fa46f7fe76fa84219c93daa1669f8f2 | 467 |
| 01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b | 196 |
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
| 53175bcc0524f37b47062fafdda28e3f8eb91d519ca0a184ca71bbebe72f969a | 107 |
| 3b5485dd0909db36922ecd8578f18da11954810e63582f302c10881ac5c47534 | 104 |
| 9d272f1f3e92f7c5efdcfdda0ab92facccd98c340be8be09064060503fd167e4 | 98 |

## ATT&CK techniques
| Tactic | Technique | Name | Events | Agents | Confidence |
|---|---|---|---|---|---|
| Reconnaissance | `T1595.001 ` | Scanning IP Blocks | 333006 | 18 | high |
| Reconnaissance | `T1595.002 ` | Vulnerability Scanning | 14926 | 18 | high |
| Reconnaissance | `T1595.003 ` | Wordlist Scanning | 12692 | 18 | high |
| Reconnaissance | T1594 | Search Victim-Owned Websites | 3361 | 18 | high |
| Initial Access | T1133 | External Remote Services | 137936 | 18 | high |
| Initial Access | T1078 | Valid Accounts | 49372 | 18 | high |
| Initial Access | T1190 | Exploit Public-Facing Application | 4764 | 18 | high |
| Execution | `T1059.004 ` | Unix Shell | 67827 | 18 | high |
| Persistence | `T1053.003 ` | Cron | 8311 | 18 | high |
| Persistence | T1098 | Account Manipulation | 662 | 18 | high |
| Persistence | `T1098.004 ` | SSH Authorized Keys | 485 | 17 | high |
| Stealth | `T1070.004 ` | File Deletion | 8790 | 18 | high |
| Stealth | `T1070.003 ` | Clear Command History | 194 | 18 | high |
| Defense Impairment | `T1222.002 ` | Linux and Mac Permissions | 715 | 18 | high |
| Credential Access | `T1110.001 ` | Password Guessing | 199514 | 18 | high |
| Credential Access | `T1552.001 ` | Credentials In Files | 3439 | 18 | high |
| Discovery | T1082 | System Information Discovery | 29085 | 18 | high |
| Discovery | T1057 | Process Discovery | 8509 | 18 | high |
| Discovery | T1033 | `System Owner/User Discovery ` | 3314 | 18 | high |
| Discovery | T1083 | File and Directory Discovery | 626 | 18 | high |
| Discovery | T1016 | System Network Configuration Discovery | 130 | 18 | high |
| Command and Control | T1105 | Ingress Tool Transfer | 21245 | 18 | high |
| Command and Control | T1090 | Proxy | 6660 | 18 | high |
| Impact | `T1496.001 ` | Compute Hijacking | 8067 | 18 | high |

## Recommendations
- Patch or take offline anything affected by CVE-2025-55182 (React Server Components remote code execution (React2Shell)). _1317 attempts on 18 agents in this period, listed by CISA as exploited in the wild, known ransomware use._
- Patch or take offline anything affected by CVE-2017-9841 (PHPUnit eval-stdin remote code execution). _891 attempts on 18 agents in this period, listed by CISA as exploited in the wild._
- Patch or take offline anything affected by CVE-2025-30208 (Vite bypasses server\[.]fs\[.]deny with raw query). _636 attempts on 17 agents in this period._
- Patch or take offline anything affected by CVE-2021-44228 (Log4Shell). _371 attempts on 9 agents in this period, listed by CISA as exploited in the wild, known ransomware use._
- Patch or take offline anything affected by CVE-2026-65694 (Microweber CMS path traversal via ServeStaticFileController). _245 attempts on 10 agents in this period._
- Patch or take offline anything affected by CVE-2021-41773 (Apache httpd path traversal). _231 attempts on 16 agents in this period, listed by CISA as exploited in the wild, known ransomware use._
- Patch or take offline anything affected by CVE-2025-31324 (SAP NetWeaver Visual Composer file upload). _142 attempts on 18 agents in this period, listed by CISA as exploited in the wild, known ransomware use._
- Patch or take offline anything affected by CVE-2025-3248 (Langflow unauthenticated RCE via /api/v1/validate/code). _134 attempts on 18 agents in this period, listed by CISA as exploited in the wild, known ransomware use._
- Patch or take offline anything affected by CVE-2018-10561 (GPON router authentication bypass). _110 attempts on 17 agents in this period, listed by CISA as exploited in the wild._
- Patch or take offline anything affected by CVE-2020-11547 (PRTG Network Monitor information disclosure). _105 attempts on 9 agents in this period._

## Method and limits
- Source: decoy services (honeypots) on internet-facing servers. They have no legitimate users, so everything recorded is unsolicited.
- Coverage: untargeted, automated activity. The fleet does not see targeted attacks on your organisation, and it does not observe what happens after a successful break-in.
- Confidence: high = seen by at least half of a multi-agent fleet and by ten or more addresses; medium = several addresses or more than one agent; low = a single agent and few addresses.
- Change is measured against the average of the seven preceding periods of equal length.
- ATT&CK techniques describe what a request attempted. No technique succeeded: decoys never execute what they receive.
- CVE dates and scores: CVE Program. Exploited-in-the-wild status: CISA KEV. Origin countries are where a network is registered, not necessarily where an operator sits.
