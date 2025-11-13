# 🐳 Docker Security Audit Guide

Welcome to the **Docker Security Audit** section of the [Security Operations Toolkit](https://github.com/maxzaikin/SecOps) repository.  
This guide documents a **methodical approach to auditing the security posture** of a commercial product built on a **microservices architecture running in Docker containers**.

---

## 🧭 About This Project

Over the past few weeks, I have worked on assessing the security of a large-scale, commercially deployed microservice-based product.  
While I cannot disclose the product name or its technical specifics for confidentiality reasons, this document describes a **generalized methodology** I applied during my investigation.  

It can be reused by anyone performing **Docker or microservice infrastructure security assessments** in enterprise environments.

---

## ⚙️ Audit Workflow Overview

The process focuses on systematically collecting, analyzing, and correlating container-level information to understand:

- Inter-container communication patterns  
- Network exposure and port mappings  
- Installed software and potential vulnerabilities  
- Privilege escalation vectors  
- Misconfigurations in environment variables or filesystem permissions  

---

## 🧩 Step-by-Step Analysis

### 1️⃣ Enumerate All Running Containers

Collect a full JSON inventory of active containers:

```bash
docker ps --no-trunc --format "{{json .}}" > containers.json
```

This output includes container IDs, names, image versions, ports, and statuses.

---

### 2️⃣ Analyze Network Architecture

List all Docker networks:

```bash
docker network ls --format '{{json .}}' > networks.json
```

Inspect each network in detail:

```bash
docker network inspect <network_id> > network_<id>.json
```

This helps map which services communicate internally versus which are exposed externally.

---

### 3️⃣ Aggregate Data for Central Analysis

Combine all collected JSON files into a single dataset for easier cross-reference and visualization.  
[docker-audit.ipynb](https://github.com/maxzaikin/SecOps/tree/main/docker-audit/docker-audit.ipynb)

---

### 4️⃣ Inspect Exposed Ports

Generate a quick overview of port mappings:

```bash
docker ps --format '{{.Names}}  --->  {{.Ports}}'
```

This reveals which services are reachable from outside and which are internal-only. Pay attention to the ports marked as 0.0.0.0:port_number

---

### 5️⃣ Container-Level Security Inspection

#### 5.1 Enter Each Container

```bash
docker exec -it <container_id> /bin/bash
```

#### 5.2 Identify OS and Version

```bash
cat /etc/os-release
```

#### 5.3 Review Environment Variables

```bash
env
```

> ⚠️ Look for secrets, credentials, API keys, and tokens exposed in environment variables.

#### 5.4 Enumerate Installed Packages

```bash
dpkg-query -W -f='${Package}-${Version}\n' \
| sed 's/"/\\\"/g' \
| sed ':a;N;$!ba;s/\n/","/g;s/^/["/;s/$/"]/; s/\[\"\\"\]/[]/;' \
| sed '1s/^/{ "Installed packages": /; $s/$/ }/' > packages.json
```

This produces a JSON-compatible list of all installed software for vulnerability scanning.

---

## 🧠 Additional Security Checks

To perform a **comprehensive security audit**, include the following:

| Category | Description | Example Commands |
|-----------|--------------|------------------|
| 🔒 **Running Processes** | Identify potentially risky daemons or background services | `ps aux` |
| 🧑‍💻 **User Privileges** | Check which users exist and their privileges | `cat /etc/passwd`, `id` |
| 🧩 **SUID/SGID Files** | Detect privilege escalation vectors | `find / -perm /6000 -type f 2>/dev/null` |
| 📦 **Installed Libraries** | Review third-party dependencies | `ldd /usr/bin/*` |
| 🧰 **Dockerfile Review** | If available, check for best practices (no root user, minimal base image) | manual review |
| 🔑 **Secrets Audit** | Scan for secrets inside environment or config files | `grep -R "password" /etc 2>/dev/null` |
| 🔗 **Inter-Container Communication** | Ensure no unnecessary open links between sensitive and non-sensitive services | cross-reference network JSON |
| 🧱 **Firewall / IPTables Rules** | Review internal firewall configuration | `iptables -L -n` |

---

## 🧾 Output and Reporting

After collecting all information:

- Summarize findings in an **inventory spreadsheet or JSON**.
- Highlight risky ports, outdated libraries, or services running as root.
- Correlate network and package data to build a risk matrix.

---

## 🧰 Recommended Tools

- 🚀 **Terminal** - best old-scholl tool
- 🕵️ **Trivy** — container vulnerability scanner  
- 🧰 **Dockle** — Docker image best practices linter  
- 📊 **VSCode** — for JSON parsing and analysis

---

## 🤝 Contributions

Contributions are always welcome!  
If you have additional methods, scripts, or automation tools for container auditing, feel free to open an issue or pull request.

---

## ⚠️ Disclaimer

This documentation is provided for **educational and security research purposes only**.  
Always conduct audits in authorized environments and comply with company policies.

---

## 😊 Best Regards  

**Maks Zaikin**  
*CyberSec Specialist*
