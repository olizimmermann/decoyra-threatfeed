# Threat situation report
Period: last 7 days (2026-11-17 21:21 UTC to 2026-11-24 21:21 UTC) · 18 agents
## Key findings
- **High confidence.** The fleet has less history than this period, so there is no usual level yet: nothing here is called new or rising. _(comparisons start once the fleet has run for 336 hours)_
- **High confidence.** CVE-2017-9841 (PHPUnit eval-stdin remote code execution) is being attempted, a vulnerability CISA lists as exploited in the wild. _(1884 attempts on 18 of 18 agents; first seen by the fleet 11 days ago)_
- **High confidence.** CVE-2025-55182 (React Server Components remote code execution (React2Shell)) is being attempted, a vulnerability CISA lists as exploited in the wild and used by ransomware groups. _(708 attempts on 18 of 18 agents; first seen by the fleet 3 days ago)_
- **High confidence.** CVE-2025-30208 (Vite bypasses server\[.]fs\[.]deny with raw query) is being attempted. _(501 attempts on 14 of 18 agents; first seen by the fleet 11 days ago)_
- **Medium confidence.** CVE-2021-44228 (Log4Shell) is being attempted, a vulnerability CISA lists as exploited in the wild and used by ransomware groups. _(370 attempts on 8 of 18 agents; first seen by the fleet 10 days ago)_
- **High confidence.** The largest campaign uses 444 addresses with the same technique set (admin-panel, iot-router). _(953 events on 18 of 18 agents)_

## Numbers
| Events | Attacking addresses | High severity | Blocked now | Language-model agents | New patterns |
|---|---|---|---|---|---|
| 9235320 | 38812 | 28569 | 725 | 0 | 10 |

## Known exploits
| CVE | Name | CVSS | CISA | Events | Agents |
|---|---|---|---|---|---|
| CVE-2017-9841 | PHPUnit eval-stdin remote code execution | `9.8 ` | exploited | 1884 | 18 |
| CVE-2025-55182 | React Server Components remote code execution (React2Shell) | `n/a ` | exploited, ransomware | 708 | 18 |
| CVE-2025-30208 | `Vite bypasses server.fs.deny with raw query ` | `n/a ` | - | 501 | 14 |
| CVE-2021-44228 | Log4Shell | `10.0 ` | exploited, ransomware | 370 | 8 |
| CVE-2020-11547 | PRTG Network Monitor information disclosure | `n/a ` | - | 214 | 13 |
| CVE-2021-41773 | Apache httpd path traversal | `7.5 ` | exploited, ransomware | 211 | 15 |
| CVE-2026-65694 | Microweber CMS path traversal via ServeStaticFileController | `n/a ` | - | 201 | 10 |
| CVE-2021-3129 | Laravel Ignition remote code execution | `9.8 ` | exploited, ransomware | 136 | 1 |
| CVE-2025-31324 | SAP NetWeaver Visual Composer file upload | `10.0 ` | exploited, ransomware | 122 | 18 |
| CVE-2025-3248 | `Langflow unauthenticated RCE via /api/v1/validate/code ` | `n/a ` | exploited, ransomware | 102 | 17 |

## Technologies under attack
| Technology | Events | Change | Agents |
|---|---|---|---|
| credential-attack | 146962 | no history yet | 18 |
| ssh | 132783 | no history yet | 18 |
| telnet | 51964 | no history yet | 18 |
| smb | 48537 | no history yet | 18 |
| ssh-shell | 48230 | no history yet | 18 |
| mssql | 39102 | no history yet | 18 |
| ssh-login | 36852 | no history yet | 18 |
| rdp | 35763 | no history yet | 18 |
| smb1 | 32679 | no history yet | 18 |
| shell-recon | 25494 | no history yet | 18 |
| shell-download | 17833 | no history yet | 18 |
| redis | 15392 | no history yet | 18 |

## New request patterns
| Pattern | Events | Addresses | Confidence |
|---|---|---|---|
| telnet chinadsl-net | 2604 | 4 | medium |
| telnet router | 2597 | 7 | medium |
| `GET /boaform/adminformlogout//boaform/admin/login.asp ` | 953 | 444 | high |
| `GET /etc/passwd ` | 640 | 32 | medium |
| `GET /elfinder/php/connector.minimal.php ` | 583 | 8 | medium |
| `GET /elfinder/php/connector.php ` | 444 | 6 | medium |
| `a591c4ddccc960a2da8099958270fc92 SSH-2.0-libssh_0.12.2 ` | 427 | 27 | medium |
| `POST /api/kernels ` | 330 | 4 | medium |

## Campaigns
| Techniques | Addresses | Events | Agents |
|---|---|---|---|
| admin-panel, iot-router | 444 | 953 | 18 |
| admin-panel, iot-router | 119 | 122 | 18 |
| CVE-2025-31324 | 110 | 115 | 18 |
| env-secrets | 79 | 112 | 18 |
| java-spring | 76 | 79 | 18 |

## Indicators (de-fanged, never fetch)
| Indicator | Attacking addresses |
|---|---|
| a8460f446be540410004b1a8db4083773fa46f7fe76fa84219c93daa1669f8f2 | 331 |
| 01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b | 143 |
| e150a1ec81e8e93e1eae2c3a77e66ec6dbd6a3b460f89c1d08aecf422ee401a0 | 114 |
| 2634c3097f98e36865f0c572009c4ffd73316bc8b88ccfe8d196af35f46e2394 | 113 |
| c05b56ab6d3d07ccca6778ebd799bf98dfa2b7f10dd43601f0938f04e5070878 | 113 |
| a883dafc480d466ee04e0d6da986bd78eb1fdd2178d04693723da3a8f95d42f4 | 112 |
| 6b3a55e0261b0304143f805a24924d0c1c44524821305f31d9277843b8a10f4e | 110 |
| 6d78392a5886177fe5b86e585a0b695a2bcd01a05504b3c4e38bc8eeb21e8326 | 109 |
| 5ecf8d2cc410094e8b82dd0bc178a57f3aa1e80916689beb00fe56148b1b1256 | 108 |
| f33ae3bc9a22cd7564990a794789954409977013966fb1a8f43c35776b833a95 | 106 |
| cc10ba3e72e09f1e742e4155968aa081fd309c76b6acf28eea1e3046438f005e | 106 |
| 3c56dd5ed61af7e7b20f54288947a89a4891d181b10fe04560b55c5e82de1fa2 | 105 |
| 53175bcc0524f37b47062fafdda28e3f8eb91d519ca0a184ca71bbebe72f969a | 102 |
| 3b5485dd0909db36922ecd8578f18da11954810e63582f302c10881ac5c47534 | 96 |
| 9d272f1f3e92f7c5efdcfdda0ab92facccd98c340be8be09064060503fd167e4 | 94 |

## ATT&CK techniques
| Tactic | Technique | Name | Events | Agents | Confidence |
|---|---|---|---|---|---|
| Reconnaissance | `T1595.001 ` | Scanning IP Blocks | 269744 | 18 | high |
| Reconnaissance | `T1595.002 ` | Vulnerability Scanning | 18168 | 18 | high |
| Reconnaissance | `T1595.003 ` | Wordlist Scanning | 14142 | 18 | high |
| Reconnaissance | T1594 | Search Victim-Owned Websites | 5317 | 18 | high |
| Initial Access | T1133 | External Remote Services | 103974 | 18 | high |
| Initial Access | T1078 | Valid Accounts | 36861 | 18 | high |
| Initial Access | T1190 | Exploit Public-Facing Application | 4955 | 18 | high |
| Execution | `T1059.004 ` | Unix Shell | 49579 | 18 | high |
| Persistence | `T1053.003 ` | Cron | 7868 | 18 | high |
| Persistence | T1098 | Account Manipulation | 435 | 14 | high |
| Persistence | `T1098.004 ` | SSH Authorized Keys | 216 | 10 | high |
| Stealth | `T1070.004 ` | File Deletion | 8243 | 18 | high |
| Stealth | `T1070.003 ` | Clear Command History | 202 | 18 | high |
| Defense Impairment | `T1222.002 ` | Linux and Mac Permissions | 476 | 18 | high |
| Credential Access | `T1110.001 ` | Password Guessing | 146962 | 18 | high |
| Credential Access | `T1552.001 ` | Credentials In Files | 4627 | 18 | high |
| Discovery | T1082 | System Information Discovery | 26097 | 18 | high |
| Discovery | T1057 | Process Discovery | 8006 | 18 | high |
| Discovery | T1033 | `System Owner/User Discovery ` | 458 | 18 | high |
| Discovery | T1083 | File and Directory Discovery | 328 | 17 | high |
| Discovery | T1016 | System Network Configuration Discovery | 153 | 16 | high |
| Command and Control | T1105 | Ingress Tool Transfer | 20036 | 18 | high |
| Command and Control | T1090 | Proxy | 8422 | 18 | high |
| Impact | `T1496.001 ` | Compute Hijacking | 7729 | 18 | high |

## Recommendations
- Patch or take offline anything affected by CVE-2017-9841 (PHPUnit eval-stdin remote code execution). _1884 attempts on 18 agents in this period, listed by CISA as exploited in the wild._
- Patch or take offline anything affected by CVE-2025-55182 (React Server Components remote code execution (React2Shell)). _708 attempts on 18 agents in this period, listed by CISA as exploited in the wild, known ransomware use._
- Patch or take offline anything affected by CVE-2025-30208 (Vite bypasses server\[.]fs\[.]deny with raw query). _501 attempts on 14 agents in this period._
- Patch or take offline anything affected by CVE-2021-44228 (Log4Shell). _370 attempts on 8 agents in this period, listed by CISA as exploited in the wild, known ransomware use._
- Patch or take offline anything affected by CVE-2020-11547 (PRTG Network Monitor information disclosure). _214 attempts on 13 agents in this period._
- Patch or take offline anything affected by CVE-2021-41773 (Apache httpd path traversal). _211 attempts on 15 agents in this period, listed by CISA as exploited in the wild, known ransomware use._
- Patch or take offline anything affected by CVE-2026-65694 (Microweber CMS path traversal via ServeStaticFileController). _201 attempts on 10 agents in this period._
- Patch or take offline anything affected by CVE-2021-3129 (Laravel Ignition remote code execution). _136 attempts on 1 agents in this period, listed by CISA as exploited in the wild, known ransomware use._
- Patch or take offline anything affected by CVE-2025-31324 (SAP NetWeaver Visual Composer file upload). _122 attempts on 18 agents in this period, listed by CISA as exploited in the wild, known ransomware use._
- Patch or take offline anything affected by CVE-2025-3248 (Langflow unauthenticated RCE via /api/v1/validate/code). _102 attempts on 17 agents in this period, listed by CISA as exploited in the wild, known ransomware use._

## Method and limits
- Source: decoy services (honeypots) on internet-facing servers. They have no legitimate users, so everything recorded is unsolicited.
- Coverage: untargeted, automated activity. The fleet does not see targeted attacks on your organisation, and it does not observe what happens after a successful break-in.
- Confidence: high = seen by at least half of a multi-agent fleet and by ten or more addresses; medium = several addresses or more than one agent; low = a single agent and few addresses.
- Change is measured against the average of the seven preceding periods of equal length.
- ATT&CK techniques describe what a request attempted. No technique succeeded: decoys never execute what they receive.
- CVE dates and scores: CVE Program. Exploited-in-the-wild status: CISA KEV. Origin countries are where a network is registered, not necessarily where an operator sits.
