# Changelog

All notable changes to this project will be documented in this file.

This project loosely follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) style and uses semantic versioning while it matures.

---

## [0.1.0] - 2026-05-10

### Added

- Initial GitHub-ready project structure.
- Main entry script: `Invoke-SBNetworkAssessment.ps1`.
- Required `-AcceptScope` flag to prevent accidental unauthorised runs.
- Lite and Deep assessment modes.
- Local Windows health collection:
  - OS version/build
  - Manufacturer/model
  - Serial number
  - Uptime
  - Disk free space
  - Windows Firewall profile status
  - Microsoft Defender status
  - BitLocker status
  - Local Administrators group membership
  - Basic Windows LAPS / legacy LAPS hints
- Active Directory summary module:
  - Domain summary
  - Domain controllers
  - AD computer count
  - AD user count
  - Enabled/disabled user counts
  - Stale enabled computers
  - Stale enabled users
  - Users with passwords set to never expire
  - Privileged group membership summaries
- Network discovery module:
  - Local interface and route snapshot
  - ARP table collection
  - Optional CIDR ping sweep
  - Common TCP port checks
  - Basic device type guessing
  - DHCP scope summary where the DHCP module is available
- Finding generation for:
  - Stale AD users
  - Stale AD computers
  - Password-never-expires accounts
  - RDP exposure
  - Telnet exposure
  - SMB visibility
  - Web administration interfaces
  - Low disk space
  - Disabled Windows Firewall profiles
  - Disabled Defender Antivirus
  - BitLocker not enabled on OS drive
  - LAPS not detected locally
- Structured output:
  - HTML report
  - CSV files
  - Raw JSON files
  - Assessment log
- Initial README documentation.
- Example config files.
- Git ignore file.

### Security

- Tool is read-only by design.
- No credential attacks.
- No default password attempts.
- No brute forcing.
- No exploitation.
- No password collection.
- No automatic remediation.

### Known limitations

- SNMP discovery is not yet implemented.
- Microsoft 365/Entra ID checks are not yet implemented.
- Network mapping is inferred and basic.
- Device type identification is heuristic.
- PDF export is not yet implemented.
- Deep mode depends on PowerShell Remoting, permissions, endpoint firewall policy, and target OS support.

---

## Planned future versions

### [0.2.0] - Proposed

- Add JSON-driven risk rule loading.
- Add SNMP availability checks without credential guessing.
- Add optional SNMP collection when community strings are explicitly provided by the client.
- Add Mermaid/Graphviz network map output.
- Add report branding configuration.
- Add improved NAS/printer/network-device classification.

### [0.3.0] - Proposed

- Add Microsoft 365/Entra ID assessment module.
- Add MFA/admin role/licence/stale user summary.
- Add Intune/Defender device posture summary.
- Add Secure Score summary import.

### [0.4.0] - Proposed

- Add remediation estimate generator.
- Add executive-only report mode.
- Add comparison between assessment runs.
- Add Power BI-ready summary output.

### [1.0.0] - Proposed

- Stable release with signed scripts, tested modules, mature reporting, configurable rules, and documented support boundaries.
