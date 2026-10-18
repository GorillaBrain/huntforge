# HuntForge — Defensive Threat-Hunting Workbench

[![Workbench Version](https://img.shields.io/badge/HuntForge-v2.0_Enterprise-0284c7.svg)](#)
[![Analysis Mode](https://img.shields.io/badge/Execution-100%25_Browser--Local-10b981.svg)](#)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE_ATT%26CK-v15.1_Enterprise-f43f5e.svg)](#)
[![CTI Standard](https://img.shields.io/badge/Threat_Intel-STIX_2.1-8b5cf6.svg)](#)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](#)

**HuntForge** is an offline-capable, browser-local defensive threat hunting workbench designed for SOC analysts, incident responders, and detection engineers. It enables deep log ingestion, canonical normalization, tactical querying with the **Hunt Query Language (HQL)**, deterministic rule execution, multi-event attack correlation, interactive topology graphing, and standardized STIX 2.1 intelligence generation — with **zero server dependencies and 100% memory-local privacy**.

---

## Key Capabilities & Features

### 1. 100% In-Memory Local Analysis & Epistemic Hierarchy
- **Complete Data Sovereignty:** Ingest, parse, normalize, and analyze gigabytes of security telemetry directly in browser memory without sending customer or incident data to third-party clouds.
- **Epistemic Distinction Banner:** Explicitly enforces the boundary between **Raw Observed Telemetry**, **Canonical Fields**, **Rule Matches**, **Correlated Sequences**, **Hypotheses**, and **Confirmed Facts**.

### 2. Advanced Hunt Query Language (HQL) Engine
- **Recursive-Descent AST Evaluator:** Supports boolean logic (`AND`, `OR`, `NOT`), grouping `()`, comparison operators (`==`, `!=`, `>`, `<`, `>=`, `<=`), substring matching (`contains`, `startswith`, `endswith`), regex patterns (`matches`), collection inclusion (`in [...]`), existence checks (`exists`, `is null`).
- **Splunk/KQL-Style Pipeline Commands (`|`):**
  - `| stats count by <field>`
  - `| stats count, distinct(<field>) by <field>`
  - `| sort <field> [asc|desc]`
  - `| head <n>` and `| tail <n>`
  - `| fields <col1>, <col2>`
  - `| where <additional_condition>`
- **Visual Analytics:** Real-time proportional aggregation bar charts and an interactive **Investigation Time-Density Histogram** displaying event frequency across the hunting window.

### 3. Interactive SVG Attack Graph & Entity Topology
- Dynamic vector node-link graph mapping directional relationships across **Adversary Source IPs**, **Target Accounts**, **Compromised Hosts**, **Executed Processes**, and **C2/Exfiltration Endpoints**.
- Node click interaction dynamically filters the chronological investigation timeline.

### 4. Deterministic Detection Rule Engine & Live Builder
- Curated baseline rules covering:
  - Repeated Failed Authentication Bursts
  - Horizontal Password Spraying
  - Privileged Account Guessing
  - Living-off-the-Land (LOLBAS) Process Execution (Office spawning shells, encoded PowerShell)
  - Execution from Staging/Temp Paths
  - Unauthorized Local Account Creation & Privilege Escalation
  - Internal Network Port Sweeps
  - High-Volume Data Exfiltration
- Interactive Rule Builder with baseline false-positive verification against clean enterprise datasets.

### 5. Multi-Event Correlation Engine
- Correlates multi-stage adversary tradecraft using entity linking and temporal sliding windows:
  - `CORR-001`: Failed Authentication Burst (Account + Source IP)
  - `CORR-002`: Password Spraying Burst Across Multiple Accounts
  - `CORR-003`: Failed Login Burst Followed by Successful Authentication
  - `CORR-004`: Process Creation Followed by Related Network/DNS Activity
  - `CORR-005`: Account Creation Followed by Privileged Group Assignment
  - `CORR-006`: Multi-Stage Progression on Single Host

### 6. Indicators of Compromise (IOC) Hub & STIX 2.1
- Automated deduplication and classification across IPv4, Domains, URLs, SHA-256 Hashes, and Email Addresses.
- **Defanging Utility:** 1-click toggle to defang active indicators (`hxxp://`, `[.]`, `[at]`) for safe reporting and clipboard sharing.
- **STIX 2.1 Export:** Generates standardized STIX 2.1 JSON bundles ready for ingestion into OpenCTI, MISP, or Microsoft Sentinel.

### 7. MITRE ATT&CK® Enterprise v15.1 Coverage Matrix
- Mapped across 11 tactics and key enterprise techniques.
- Interactive filtering by MITRE Tactic and status (**Observed in Evidence**, **Rule Covered**, or **Telemetry Unavailable**).

### 8. Interactive Guided Exercises (6 Scenarios)
- **Exercise 1:** Password Spraying & Brute-Force Follow-Through (Dataset B)
- **Exercise 2:** Suspicious Office-to-PowerShell Process Chain (Dataset C)
- **Exercise 3:** Multi-Stage Attack Timeline & Persistence (Dataset D)
- **Exercise 4:** Internal Network Discovery & Outbound Exfiltration (Dataset D)
- **Exercise 5:** Baseline False-Positive Validation & Rule Tuning (Dataset A)
- **Exercise 6:** Multi-Stage Attack Graph Analysis & STIX 2.1 Threat Intel Production (Dataset D)

### 9. Case Management, Reports & Evidence Redaction
- Interactive Case Builder organizing evidence IDs, pinned timeline events, saved HQL queries, and analyst conclusions.
- **Redaction Engine:** Automatically masks internal hostnames, usernames, and IPv4 addresses for external disclosure.
- **Export Options:** Printable Executive HTML Report, JSON Case File, and GitHub Flavored Markdown (`.md`) incident summary.

---

## Synthetic Datasets Included

| Dataset | Telemetry Records | Primary Scenario |
| :--- | :---: | :--- |
| **Dataset A** | 60 | Clean enterprise baseline (routine logins, standard Office/browsers, IT scripts) |
| **Dataset B** | 70 | Horizontal password spray across 8 accounts + brute-force success from `198.51.100.44` |
| **Dataset C** | 64 | Malicious document macro (`WINWORD.EXE` -> `cmd.exe` -> obfuscated PowerShell -> C2) |
| **Dataset D** | 80 | Full multi-stage intrusion: RDP brute-force, discovery scanning, persistence, and 48.5MB exfil |
| **Sample CSV** | 20 | Sample Windows Security Event Log CSV export demonstrating custom column mapping |

---

## Local Setup & Development

HuntForge is a zero-dependency static application. You can run it with any static web server:

```bash
# Clone the repository
git clone https://github.com/GorillaBrain/huntforge.git
cd huntforge

# Serve with any lightweight static server
npx serve .
# or
python -m http.server 8000
```

Navigate to `http://localhost:8000` to begin your investigation.

---

## Telemetry Field Mapping Reference

| Canonical Field | Type | Common Aliases |
| :--- | :--- | :--- |
| `event.id` | string | `event_id`, `record_id`, `id` |
| `timestamp` | ISO-8601 | `@timestamp`, `time`, `EventTime`, `TimeCreated` |
| `host.name` | string | `host`, `hostname`, `ComputerName`, `dhost` |
| `event.category` | string | `category`, `log_type`, `Channel` |
| `event.code` | integer | `EventCode`, `EventID`, `code`, `id` |
| `user.name` | string | `user`, `username`, `TargetUserName`, `Account` |
| `source.ip` | IPv4 | `src_ip`, `IpAddress`, `source_ip` |
| `destination.ip`| IPv4 | `dest_ip`, `DestinationIp`, `target_ip` |
| `process.name` | string | `process`, `NewProcessName`, `Image` |
| `process.command_line` | string | `command_line`, `CommandLine`, `cmd` |
| `bytes_out` | integer | `bytes_out`, `BytesSent`, `out_bytes` |

---

## License & Attribution

- **License:** MIT License.
- **MITRE ATT&CK:** MITRE ATT&CK® is a registered trademark of The MITRE Corporation. Curated subset used for educational and defensive threat-hunting workflows.
