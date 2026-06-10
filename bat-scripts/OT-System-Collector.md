# OT-System-Collector

## Overview

OT-System-Collector is a portable, agentless Windows asset inventory and forensic data collection tool designed for Industrial Control Systems (ICS), Operational Technology (OT), SCADA, HMI, and engineering workstations.

The project was created to provide a safe and practical way to collect system, network, software, security, and forensic artifacts from industrial environments without installing additional software.

The collector is implemented as a single Windows Batch script and collected data can be analyzed manually or imported into Python, Jupyter Notebook, SIEM platforms, asset management systems, vulnerability management platforms, and CMDB solutions.

## Supported Operating Systems

The collector is designed to support the following Microsoft Windows operating systems:

| Operating System | Support Status |
| ------------------ | --------------- |
| Windows XP | ✅ Tested |
| Windows XP Embedded | ⚠️ Expected to work, not fully tested |
| Windows Server 2003 | ⚠️ Expected to work, not tested |
| Windows 7 | ⚠️ Expected to work, not fully tested |
| Windows 8 / 8.1 | ⚠️ Expected to work, not tested |
| Windows 10 | ⚠️ Expected to work, not fully tested |
| Windows 11 | ✅ Tested |
| Windows Server 2008–2022 | ⚠️ Expected to work, not tested |

### Support Status Definitions

- ✅ **Tested** — Successfully executed in a real environment.
- ⚠️ **Expected to work** — Supported by design and command compatibility, but not yet validated in a production or lab environment.
- ⚠️ **Limited testing performed** — Basic functionality has been verified, but comprehensive testing has not been completed.

Community feedback, bug reports, and compatibility test results are welcome.

## Key Features

### Agentless Operation

No installation required.

The collector executes native Windows commands and stores the results locally.

### OT / ICS Focus

The tool is specifically designed for industrial environments and collects:

* Hardware inventory
* Software inventory
* Network configuration
* User accounts and privileges
* Services and drivers
* Persistence mechanisms
* USB history
* Firewall configuration
* Event log information
* COM/DCOM configuration
* Remote access tools
* OT-related registry artifacts

### Legacy System Support

Special attention was given to compatibility with:

* Windows XP
* Windows XP Embedded
* Legacy HMI systems
* SCADA workstations
* Industrial engineering stations

### Forensic-Oriented Collection

The collector gathers artifacts useful for:

* Incident response
* Threat hunting
* Asset discovery
* Security assessments
* Compliance audits
* Network mapping
* Baseline generation

---

## Typical Use Cases

### Asset Inventory

Identify:

* Hardware platforms
* BIOS information
* Serial numbers
* Network interfaces
* Installed software
* Connected peripherals

### OT Security Assessments

Discover:

* Remote access software
* Unauthorized services
* Local accounts
* Firewall rules
* USB usage history

### Incident Response

Collect:

* Running processes
* Active network connections
* Service configurations
* Persistence mechanisms
* Event log information

### Compliance Audits

Verify:

* Security policies
* Patch levels
* User account configuration
* System configuration baselines

---

## Data Collection Phases

### Phase 1 – System Identity

Collects:

* Computer name
* Operating system
* Service pack level
* Build information
* BIOS information
* CPU information
* Memory inventory
* Serial numbers
* System environment variables

Purpose:

Provides unique identification of the asset.

---

### Phase 2 – Storage Inventory

Collects:

* Physical disks
* Logical disks
* Partitions
* Mounted volumes

Purpose:

Storage inventory and capacity analysis.

---

### Phase 3 – Network Inventory

Collects:

* IP configuration
* Routing tables
* ARP cache
* DNS cache
* Active network connections
* MAC addresses
* Network shares
* NIC inventory
* TCP/IP registry settings
* HOSTS file

Purpose:

Network topology reconstruction and communication analysis.

---

### Phase 4 – Users and Access

Collects:

* Local users
* Local groups
* Password policy
* User account details

Purpose:

Privilege analysis and account inventory.

---

### Phase 5 – Runtime Environment

Collects:

* Running processes
* Services
* Service configurations
* Drivers
* Kernel drivers

Purpose:

Runtime visibility and persistence detection.

---

### Phase 6 – Software Inventory

Collects:

* Installed applications
* Hotfixes
* .NET versions
* Antivirus information
* Certificates

Purpose:

Software asset management and vulnerability assessment.

---

### Phase 7 – Persistence and Security

Collects:

* Scheduled tasks
* Run keys
* RunOnce keys
* Group Policy data
* Local security policy
* Firewall rules

Purpose:

Persistence and security posture analysis.

---

### Phase 8 – OT-Specific Inventory

Collects:

* PnP devices
* COM ports
* Serial interfaces
* USB controllers
* Industrial communication hardware

Purpose:

Industrial asset discovery.

---

### Phase 9 – Forensic Artifacts

Collects:

* Event log inventory
* USB device history
* Registry artifacts

Purpose:

Incident response and forensic investigations.

---

### Phase 10+ – Advanced Forensic Collection

Depending on version:

* Prefetch artifacts
* UserAssist data
* ShimCache information
* Remote access tools
* DCOM configuration
* OPC-related settings
* OT vendor artifacts

Purpose:

Advanced threat hunting and forensic analysis.

---

## Output Structure

```text
report_HOSTNAME/
│
├── metadata.json
├── manifest.txt
├── collection_log.txt
│
├── 1_identity/
├── 2_storage/
├── 3_network/
├── 4_access/
├── 5_runtime/
├── 6_software/
├── 7_persistence/
├── 8_ot_specific/
├── 9_forensics/
└── ...
```

---

## Using the Data in Jupyter

The collector was designed with post-processing in mind.

Typical workflow:

```python
import pandas as pd

df = pd.read_csv("3_network/nic_config.csv")
```

Examples:

### Asset Inventory Dashboard

Build inventories of:

* Systems
* Network adapters
* Software
* Users

### Network Mapping

Use:

* ARP cache
* Routing tables
* IP configuration

to reconstruct OT network topology.

### Software Analysis

Identify:

* Unsupported software
* Legacy applications
* Missing patches

### Threat Hunting

Search for:

* Remote access tools
* Unknown services
* Suspicious autoruns
* USB activity

### Baseline Comparison

Compare multiple collections to identify:

* Configuration drift
* New software
* New services
* New user accounts

---

## Safety Considerations

The collector is intended to be non-invasive.

However:

* Some WMI queries may be slow on older systems.
* `wmic product` may take significant time on systems with many installed applications.
* Always test the collector in a representative environment before large-scale deployment.

The collector does not intentionally modify system configuration and primarily performs read-only operations.

---

## Disclaimer

This tool is provided for educational, administrative, defensive security, incident response, and asset management purposes.

The user is responsible for ensuring that execution complies with organizational policies, regulations, and operational requirements.

---

## References and Alignment

OT-System-Collector Collector was designed to support asset inventory, system assessment, incident response, and security baseline activities commonly recommended by industrial cybersecurity standards, frameworks, and best practices.

The project is not a certified compliance tool and does not claim formal compliance with any standard. However, the collected data can assist organizations in implementing controls and assessment activities described in the following documents.

### Industrial Cybersecurity Standards

#### IEC 62443 Series

The IEC 62443 family of standards emphasizes:

* Asset identification and inventory
* System assessment
* Security baseline development
* Security monitoring
* Vulnerability management

OT-System-Collector assists these activities by collecting host, software, network, and configuration data from industrial assets.

Reference:
https://www.iec.ch

---

#### NIST SP 800-82 Rev. 3

**Guide to Operational Technology (OT) Security**

OT-System-Collector supports several activities described in NIST SP 800-82, including:

* Asset discovery
* System inventory
* Network documentation
* Security assessment
* Incident response preparation
* Forensic data collection

Reference:
https://csrc.nist.gov/publications/detail/sp/800-82/rev-3/final

---

### Cybersecurity Frameworks

#### NIST Cybersecurity Framework (CSF) 2.0

The collected data can support activities within:

* Identify (ID)
* Protect (PR)
* Detect (DE)
* Respond (RS)

Particularly:

* Asset Management (ID.AM)
* Risk Assessment (ID.RA)
* Security Monitoring (DE.CM)

Reference:
https://www.nist.gov/cyberframework

---

#### MITRE ATT&CK for ICS

The collected artifacts can be useful for:

* Asset visibility
* Threat hunting
* Investigation of persistence mechanisms
* Remote access discovery
* USB device tracking
* Network connection analysis

Reference:
https://attack.mitre.org/matrices/ics/

---

### Incident Response and Forensics

#### NIST SP 800-61 Rev. 2

**Computer Security Incident Handling Guide**

OT-System-Collector supports incident response preparation and evidence collection activities by gathering:

* Running processes
* Services
* User accounts
* Network connections
* USB history
* Event log information
* Persistence mechanisms

Reference:
https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final

---

### Asset Management Guidance

#### CIS Controls v8

The collector can assist organizations implementing:

* Control 1 – Inventory and Control of Enterprise Assets
* Control 2 – Inventory and Control of Software Assets
* Control 4 – Secure Configuration of Enterprise Assets and Software
* Control 13 – Network Monitoring and Defense

Reference:
https://www.cisecurity.org/controls

---

### Important Note

OT-System-Collector is a data collection utility.

The tool does not perform vulnerability scanning, active network discovery, exploitation, security validation, or compliance auditing.

Instead, it provides structured host-based data that can be used as input for inventory management, security assessments, incident response investigations, threat hunting, and compliance activities.

