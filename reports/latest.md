# Threat situation report
Period: last 7 days (2026-11-21 11:57 UTC to 2026-11-28 11:57 UTC) · 18 agents
## Key findings
- **High confidence.** Activity against smb1 is about 2 times its usual level. _(53247 events on 18 of 18 agents)_
- **High confidence.** Activity against redis is about 3 times its usual level. _(29025 events on 18 of 18 agents)_
- **High confidence.** Activity against iot-router is about 3 times its usual level. _(1729 events on 18 of 18 agents)_
- **High confidence.** CVE-2025-55182 (React Server Components remote code execution (React2Shell)) is being attempted, a vulnerability CISA lists as exploited in the wild and used by ransomware groups. _(1361 attempts on 18 of 18 agents; first seen by the fleet 7 days ago)_
- **High confidence.** CVE-2017-9841 (PHPUnit eval-stdin remote code execution) is being attempted, a vulnerability CISA lists as exploited in the wild. _(879 attempts on 18 of 18 agents; first seen by the fleet 15 days ago)_
- **High confidence.** CVE-2025-30208 (Vite bypasses server\[.]fs\[.]deny with raw query) is being attempted. _(695 attempts on 17 of 18 agents; first seen by the fleet 14 days ago)_
- **High confidence.** CVE-2021-44228 (Log4Shell) is being attempted, a vulnerability CISA lists as exploited in the wild and used by ransomware groups. _(371 attempts on 9 of 18 agents; first seen by the fleet 14 days ago)_
- **High confidence.** 10 request patterns were seen for the first time; the most frequent is “redis:6379 \*2\\x0d\\x0a$4\\x0d\\x0aAUTH\\x0d\\x0a$0\\x0d\\x0a\\x0d\\x0a\*1\\x0d\\x0a”. _(1243 events from 777 addresses on 18 of 18 agents)_
- **High confidence.** The largest campaign uses 400 addresses with the same technique set (admin-panel, iot-router). _(837 events on 18 of 18 agents)_

## Numbers
| Events | Attacking addresses | High severity | Blocked now | Language-model agents | New patterns |
|---|---|---|---|---|---|
| 10005489 | 40195 | 25883 | 1584 | 0 | 10 |

## Known exploits
| CVE | Name | CVSS | CISA | Events | Agents |
|---|---|---|---|---|---|
| CVE-2025-55182 | React Server Components remote code execution (React2Shell) | `n/a ` | exploited, ransomware | 1361 | 18 |
| CVE-2017-9841 | PHPUnit eval-stdin remote code execution | `9.8 ` | exploited | 879 | 18 |
| CVE-2025-30208 | `Vite bypasses server.fs.deny with raw query ` | `n/a ` | - | 695 | 17 |
| CVE-2021-44228 | Log4Shell | `10.0 ` | exploited, ransomware | 371 | 9 |
| CVE-2026-65694 | Microweber CMS path traversal via ServeStaticFileController | `n/a ` | - | 236 | 10 |
| CVE-2021-41773 | Apache httpd path traversal | `7.5 ` | exploited, ransomware | 231 | 17 |
| CVE-2025-3248 | `Langflow unauthenticated RCE via /api/v1/validate/code ` | `n/a ` | exploited, ransomware | 134 | 18 |
| CVE-2025-31324 | SAP NetWeaver Visual Composer file upload | `10.0 ` | exploited, ransomware | 125 | 18 |
| CVE-2018-10561 | GPON router authentication bypass | `9.8 ` | exploited | 111 | 17 |
| CVE-2020-11547 | PRTG Network Monitor information disclosure | `n/a ` | - | 102 | 8 |

## Technologies under attack
| Technology | Events | Change | Agents |
|---|---|---|---|
| credential-attack | 207072 | `1.46x ` | 18 |
| ssh | 201076 | `1.39x ` | 18 |
| smb | 69411 | `1.75x ` | 18 |
| mssql | 65510 | `1.95x ` | 18 |
| ssh-shell | 65061 | `1.22x ` | 18 |
| smb1 | 53247 | `2.06x ` | 18 |
| ssh-login | 48809 | `1.36x ` | 18 |
| telnet | 46193 | `0.94x ` | 18 |
| rdp | 33498 | `0.63x ` | 18 |
| shell-recon | 30426 | `1.13x ` | 18 |
| redis | 29046 | `2.68x ` | 18 |
| shell-download | 18262 | `1.08x ` | 18 |

## New request patterns
| Pattern | Events | Addresses | Confidence |
|---|---|---|---|
| `redis:6379 *2\x0d\x0a$4\x0d\x0aAUTH\x0d\x0a$0\x0d\x0a\x0d\x0a*1\x0d\x0a ` | 1243 | 777 | high |
| `redis:6379 \x0d\x0aPING\x0d\x0a*2\x0d\x0a$4\x0d\x0aAUTH\x0d\x0a$6\x0d\x ` | 1243 | 777 | high |
| `redis:6379 \x0d\x0a$6\x0d\x0a{n}\x0d\x0a*1\x0d\x0a$4\x0d\x0aPING\x0d ` | 1226 | 768 | high |
| `redis:6379 3\x0d\x0a*1\x0d\x0a$4\x0d\x0aPING\x0d\x0a*2\x0d\x0a$4\x0d\x0 ` | 1187 | 746 | high |
| `redis:6379 ost\x0d\x0a*1\x0d\x0a$4\x0d\x0aPING\x0d\x0a*2\x0d\x0a$4\x0d\ ` | 1186 | 745 | high |
| `redis:6379 9\x0d\x0anetcup{n}\x0d\x0a*1\x0d\x0a$4\x0d\x0aPING\x0d\x0a*2 ` | 1185 | 744 | high |
| `redis:6379 AUTH\x0d\x0a$6\x0d\x0avpn{n}\x0d\x0a*1\x0d\x0a$4\x0d\x0aPING ` | 1161 | 731 | high |
| `redis:6379 \x0d\x0a$6\x0d\x0aredis1\x0d\x0a*1\x0d\x0a$4\x0d\x0aPING\x0d ` | 1158 | 731 | high |

## Campaigns
| Techniques | Addresses | Events | Agents |
|---|---|---|---|
| admin-panel, iot-router | 400 | 837 | 18 |
| open-proxy-test | 203 | 234 | 1 |
| admin-panel, iot-router | 128 | 132 | 18 |
| CVE-2025-31324 | 108 | 112 | 18 |
| env-secrets | 101 | 204 | 18 |

## Indicators (de-fanged, never fetch)
| Indicator | Attacking addresses |
|---|---|
| a8460f446be540410004b1a8db4083773fa46f7fe76fa84219c93daa1669f8f2 | 478 |
| `hxxp://maxcdn[.]bootstrapcdn[.]com/font-awesome/4[.]3[.]0/css/font-awesome[.]min[.]css?ver=4[.]9[.]8 ` | 209 |
| 01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b | 200 |
| e150a1ec81e8e93e1eae2c3a77e66ec6dbd6a3b460f89c1d08aecf422ee401a0 | 114 |
| 2634c3097f98e36865f0c572009c4ffd73316bc8b88ccfe8d196af35f46e2394 | 114 |
| c05b56ab6d3d07ccca6778ebd799bf98dfa2b7f10dd43601f0938f04e5070878 | 114 |
| a883dafc480d466ee04e0d6da986bd78eb1fdd2178d04693723da3a8f95d42f4 | 113 |
| 6b3a55e0261b0304143f805a24924d0c1c44524821305f31d9277843b8a10f4e | 112 |
| 6d78392a5886177fe5b86e585a0b695a2bcd01a05504b3c4e38bc8eeb21e8326 | 111 |
| cc10ba3e72e09f1e742e4155968aa081fd309c76b6acf28eea1e3046438f005e | 111 |
| 5ecf8d2cc410094e8b82dd0bc178a57f3aa1e80916689beb00fe56148b1b1256 | 111 |
| f33ae3bc9a22cd7564990a794789954409977013966fb1a8f43c35776b833a95 | 110 |
| 3c56dd5ed61af7e7b20f54288947a89a4891d181b10fe04560b55c5e82de1fa2 | 109 |
| 53175bcc0524f37b47062fafdda28e3f8eb91d519ca0a184ca71bbebe72f969a | 107 |
| 3b5485dd0909db36922ecd8578f18da11954810e63582f302c10881ac5c47534 | 105 |

## ATT&CK techniques
| Tactic | Technique | Name | Events | Agents | Confidence |
|---|---|---|---|---|---|
| Reconnaissance | `T1595.001 ` | Scanning IP Blocks | 344259 | 18 | high |
| Reconnaissance | `T1595.002 ` | Vulnerability Scanning | 17188 | 18 | high |
| Reconnaissance | `T1595.003 ` | Wordlist Scanning | 16057 | 18 | high |
| Reconnaissance | T1594 | Search Victim-Owned Websites | 3819 | 18 | high |
| Initial Access | T1133 | External Remote Services | 136412 | 18 | high |
| Initial Access | T1078 | Valid Accounts | 48845 | 18 | high |
| Initial Access | T1190 | Exploit Public-Facing Application | 4938 | 18 | high |
| Execution | `T1059.004 ` | Unix Shell | 66901 | 18 | high |
| Persistence | `T1053.003 ` | Cron | 8175 | 18 | high |
| Persistence | T1098 | Account Manipulation | 653 | 18 | high |
| Persistence | `T1098.004 ` | SSH Authorized Keys | 480 | 17 | high |
| Stealth | `T1070.004 ` | File Deletion | 8632 | 18 | high |
| Stealth | `T1070.003 ` | Clear Command History | 178 | 18 | high |
| Defense Impairment | `T1222.002 ` | Linux and Mac Permissions | 704 | 18 | high |
| Credential Access | `T1110.001 ` | Password Guessing | 207072 | 18 | high |
| Credential Access | `T1552.001 ` | Credentials In Files | 6461 | 18 | high |
| Discovery | T1082 | System Information Discovery | 28890 | 18 | high |
| Discovery | T1057 | Process Discovery | 8360 | 18 | high |
| Discovery | T1033 | `System Owner/User Discovery ` | 3272 | 18 | high |
| Discovery | T1083 | File and Directory Discovery | 603 | 18 | high |
| Discovery | T1016 | System Network Configuration Discovery | 112 | 18 | high |
| Command and Control | T1105 | Ingress Tool Transfer | 20634 | 18 | high |
| Command and Control | T1090 | Proxy | 7327 | 18 | high |
| Impact | `T1496.001 ` | Compute Hijacking | 7939 | 18 | high |

## Recommendations
- Patch or take offline anything affected by CVE-2025-55182 (React Server Components remote code execution (React2Shell)). _1361 attempts on 18 agents in this period, listed by CISA as exploited in the wild, known ransomware use._
- Patch or take offline anything affected by CVE-2017-9841 (PHPUnit eval-stdin remote code execution). _879 attempts on 18 agents in this period, listed by CISA as exploited in the wild._
- Patch or take offline anything affected by CVE-2025-30208 (Vite bypasses server\[.]fs\[.]deny with raw query). _695 attempts on 17 agents in this period._
- Patch or take offline anything affected by CVE-2021-44228 (Log4Shell). _371 attempts on 9 agents in this period, listed by CISA as exploited in the wild, known ransomware use._
- Patch or take offline anything affected by CVE-2026-65694 (Microweber CMS path traversal via ServeStaticFileController). _236 attempts on 10 agents in this period._
- Patch or take offline anything affected by CVE-2021-41773 (Apache httpd path traversal). _231 attempts on 17 agents in this period, listed by CISA as exploited in the wild, known ransomware use._
- Patch or take offline anything affected by CVE-2025-3248 (Langflow unauthenticated RCE via /api/v1/validate/code). _134 attempts on 18 agents in this period, listed by CISA as exploited in the wild, known ransomware use._
- Patch or take offline anything affected by CVE-2025-31324 (SAP NetWeaver Visual Composer file upload). _125 attempts on 18 agents in this period, listed by CISA as exploited in the wild, known ransomware use._
- Patch or take offline anything affected by CVE-2018-10561 (GPON router authentication bypass). _111 attempts on 17 agents in this period, listed by CISA as exploited in the wild._
- Patch or take offline anything affected by CVE-2020-11547 (PRTG Network Monitor information disclosure). _102 attempts on 8 agents in this period._

## Method and limits
- Source: decoy services (honeypots) on internet-facing servers. They have no legitimate users, so everything recorded is unsolicited.
- Coverage: untargeted, automated activity. The fleet does not see targeted attacks on your organisation, and it does not observe what happens after a successful break-in.
- Confidence: high = seen by at least half of a multi-agent fleet and by ten or more addresses; medium = several addresses or more than one agent; low = a single agent and few addresses.
- Change is measured against the average of the seven preceding periods of equal length.
- ATT&CK techniques describe what a request attempted. No technique succeeded: decoys never execute what they receive.
- CVE dates and scores: CVE Program. Exploited-in-the-wild status: CISA KEV. Origin countries are where a network is registered, not necessarily where an operator sits.
