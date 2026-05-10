# SB Network Assessment

A read-only PowerShell network and domain assessment starter tool for authorised MSP prospecting, onboarding, and client infrastructure reviews.

The goal is to turn a messy client environment into a clear, practical report showing:

- What devices and services were discovered
- What Active Directory hygiene issues were found
- What basic Windows health/security checks are visible
- What risks should be fixed first
- What remediation opportunities can be proposed to the client

> **Important:** This is an assessment and reporting tool, not an exploitation tool. It does not collect passwords, brute-force credentials, attempt default logins, exploit vulnerabilities, or make remediation changes.

---

## Current version

**Version:** `0.1.0`  
**Status:** Early starter / proof-of-concept  
**Primary platform:** Windows PowerShell 5.1+ on a domain-joined Windows machine or domain controller  
**Recommended use:** Run from an elevated PowerShell session with written client authorisation.

---

## What it checks

### Lite mode

Lite mode is intended for safe, low-impact prospecting and initial client discovery.

It can collect:

- Local Windows health for the machine running the script
- Local network interface and route information
- ARP table entries
- Optional scoped ping sweep across approved CIDR ranges
- Common TCP port availability on discovered devices
- Device type guesses based on ports and names
- DHCP scope summary if the DHCP PowerShell module is available
- Active Directory summary if the AD PowerShell module is available
- Stale AD user accounts
- Stale AD computer accounts
- Users with `PasswordNeverExpires`
- Privileged AD group membership counts
- CSV, JSON, log, and HTML report output

### Deep mode

Deep mode adds authenticated Windows health collection from discovered/domain devices using PowerShell Remoting.

Deep mode can collect, where permissions and WinRM allow:

- Manufacturer and model
- Domain membership
- OS version/build
- Serial number
- Last boot time and uptime
- Fixed disk free space
- Windows Firewall profile status
- Microsoft Defender status
- BitLocker status
- Local Administrators group membership
- Basic LAPS/Windows LAPS presence hints

Deep mode should only be used when the client has explicitly authorised authenticated endpoint checks.

---

## What it does **not** do

This tool intentionally avoids high-risk or legally sensitive actions.

It does **not**:

- Try default usernames or passwords
- Attempt password spraying
- Attempt brute forcing
- Exploit vulnerabilities
- Capture credentials
- Dump hashes
- Modify AD, endpoint, firewall, or network settings
- Install agents
- Disable services
- Exfiltrate data
- Perform destructive remediation

If you want to validate default credentials, external exposure, vulnerability exploitability, or password weakness, that should be handled separately under a clearly authorised penetration test or security assessment scope.

---

## Folder structure

```text
SB-NetworkAssessment/
  Invoke-SBNetworkAssessment.ps1
  README.md
  CHANGELOG.md
  .gitignore
  config/
    audit-config.example.json
    risk-rules.example.json
  modules/
    SBNA.Common.psm1
    SBNA.AD.psm1
    SBNA.Network.psm1
    SBNA.Windows.psm1
    SBNA.Report.psm1
  output/
    .gitkeep
```

---

## Requirements

### Minimum

- Windows PowerShell 5.1 or newer
- A Windows machine connected to the client network
- Permission to run PowerShell scripts
- Written authorisation from the client
- A defined assessment scope

### Recommended

- Run as Administrator
- Run from a domain controller or admin workstation
- Active Directory PowerShell module installed
- DHCP Server PowerShell module installed if DHCP scope collection is required
- PowerShell Remoting enabled for Deep mode checks
- Domain admin or delegated read/admin permissions for deeper endpoint checks

---

## Quick start

Open PowerShell as Administrator.

From the project folder:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

Run a Lite assessment:

```powershell
.\Invoke-SBNetworkAssessment.ps1 `
  -ClientName "Contoso" `
  -Mode Lite `
  -Subnets "192.168.1.0/24" `
  -AcceptScope
```

Run a Deep assessment:

```powershell
.\Invoke-SBNetworkAssessment.ps1 `
  -ClientName "Contoso" `
  -Mode Deep `
  -Subnets "192.168.1.0/24" `
  -AcceptScope
```

Run without a ping sweep, using only AD and ARP-discovered devices:

```powershell
.\Invoke-SBNetworkAssessment.ps1 `
  -ClientName "Contoso" `
  -Mode Lite `
  -AcceptScope
```

Limit the ports checked:

```powershell
.\Invoke-SBNetworkAssessment.ps1 `
  -ClientName "Contoso" `
  -Mode Lite `
  -Subnets "192.168.10.0/24" `
  -Ports 80,443,445,3389,5985 `
  -AcceptScope
```

Skip Active Directory checks:

```powershell
.\Invoke-SBNetworkAssessment.ps1 `
  -ClientName "Contoso" `
  -Mode Lite `
  -Subnets "192.168.1.0/24" `
  -SkipAD `
  -AcceptScope
```

---

## Parameters

| Parameter | Required | Default | Description |
|---|---:|---|---|
| `ClientName` | Yes | None | Client or site name used in report titles and output folder names. |
| `Mode` | No | `Lite` | `Lite` or `Deep`. Deep adds authenticated Windows health checks. |
| `Subnets` | No | Empty | CIDR ranges to ping sweep, for example `192.168.1.0/24`. |
| `Ports` | No | Common port list | TCP ports to check on discovered devices. |
| `OutputRoot` | No | `.\output` | Root folder where assessment output is saved. |
| `MaxHostsPerSubnet` | No | `512` | Safety limit to avoid accidentally sweeping very large networks. |
| `PortTimeoutMs` | No | `400` | TCP connection timeout per port. Increase on slow networks. |
| `StaleDays` | No | `90` | Age threshold for stale AD user/computer checks. |
| `SkipAD` | No | False | Skips AD checks. |
| `SkipNetwork` | No | False | Skips network discovery and port checks. |
| `SkipLocalWindows` | No | False | Skips local Windows health checks. |
| `AcceptScope` | Yes | False | Required acknowledgement that the assessment is authorised and scoped. |

---

## Output files

Every run creates a timestamped folder under `output/`.

Example:

```text
output/Contoso-20260510-143011/
  assessment-report.html
  assessment.log
  csv/
    devices.csv
    open-ports.csv
    findings.csv
    ad-computers.csv
    arp-table.csv
    windows-health-summary.csv
  raw/
    assessment-full.json
    active-directory-summary.json
    local-network.json
    local-windows-health.json
    remote-windows-health.json
    dhcp-summary.json
```

### `assessment-report.html`

Client-facing HTML summary with:

- Executive summary
- Finding counts by severity
- Key findings
- Active Directory overview
- Device overview
- Open common ports
- Suggested remediation roadmap

### `csv/findings.csv`

Engineer-friendly findings list. Useful for building quotes, tickets, remediation plans, or client follow-up tasks.

### `raw/assessment-full.json`

Full machine-readable output. Useful for future dashboards, Power BI, automated reporting, or comparison between assessment runs.

---

## Finding severity model

The current version uses a simple severity model:

| Severity | Meaning |
|---|---|
| Critical | Immediate risk or outage-level issue. Not heavily used yet in v0.1.0. |
| High | Should be addressed quickly. Examples: stale enabled users, firewall disabled, very low disk space, Telnet open. |
| Medium | Should be planned. Examples: stale computers, BitLocker not enabled, LAPS not detected, disk warning. |
| Low | Hygiene issue. Reserved for future rules. |
| Info | Useful discovery item or context. |

Each finding also includes:

- Category
- Affected asset
- Description
- Evidence
- Recommendation
- Impact
- Likelihood
- Effort
- Risk score

---

## Suggested client workflow

1. Get written authorisation and define scope.
2. Run Lite mode first.
3. Review the generated findings internally.
4. Remove or redact anything too technical or sensitive before sharing externally.
5. Convert findings into a client-friendly remediation roadmap.
6. Offer project work or managed services based on the risk areas found.
7. Run Deep mode only after the client has approved deeper authenticated checks.

---

## Prospecting pitch angle

This tool is designed to support a conversation like:

> We performed a read-only assessment of your environment and found several areas where the business could reduce risk, improve reliability, and get better visibility. The highest-value improvements are Active Directory cleanup, endpoint hardening, local admin password management, backup validation, and ongoing monitoring.

Strong remediation packages could include:

- AD cleanup and access review
- Endpoint security baseline
- Windows LAPS deployment
- Firewall and Defender policy standardisation
- Backup and disaster recovery review
- Server storage and patching cleanup
- Network documentation and asset register
- RMM onboarding
- Microsoft 365 security review

---

## Safety and authorisation notes

Before running the tool, confirm:

- The client has authorised the assessment in writing
- The subnet ranges are correct
- The time window is appropriate
- The scan will not interfere with production systems
- The output will be stored securely
- Sensitive raw data will not be shared unnecessarily

Suggested authorisation wording:

> Client authorises Silicon Beach to perform a read-only internal IT infrastructure assessment across the agreed scope for the purpose of documenting assets, identifying configuration risks, and preparing remediation recommendations. This assessment will not include exploitation, password testing, denial-of-service testing, or configuration changes.

---

## Known limitations

- Network mapping is currently basic and inferred from IP/ports rather than switch topology.
- Device type detection is heuristic and should be engineer-reviewed.
- SNMP checks are not implemented yet.
- Microsoft 365 checks are not implemented yet.
- PDF export is not implemented yet; use browser print-to-PDF from the HTML report.
- Deep mode requires PowerShell Remoting and sufficient permissions.
- Some endpoint checks may fail due to firewall, WinRM, permissions, OS version, or endpoint protection controls.

---

## Roadmap ideas

Potential future versions:

- SNMP discovery for switches, printers, NAS devices, UPS units, and firewalls
- Better network map generation using Graphviz/Mermaid
- HTML report branding/customisation
- PDF export
- Microsoft 365/Entra ID module
- Intune/Defender module
- Backup software detection rules
- External exposure module using approved public IPs only
- Warranty lookup fields/manual import
- Device owner/location enrichment
- Comparison between two assessment runs
- JSON-driven risk rules
- Client-ready remediation estimate generator
- Power BI dashboard template
- Signed release build

---

## Development notes

The project is deliberately modular:

- `SBNA.Common.psm1` contains shared helpers
- `SBNA.AD.psm1` handles Active Directory checks
- `SBNA.Network.psm1` handles discovery and port inventory
- `SBNA.Windows.psm1` handles local and remote Windows health checks
- `SBNA.Report.psm1` generates HTML output

Keep new features read-only by default. Add new checks as separate functions and return structured objects rather than writing directly to the console.

---

## Disclaimer

This project is provided as a starter assessment tool. Validate findings manually before making recommendations. The user running this tool is responsible for ensuring they have authorisation and that the assessment is appropriate for the client environment.
