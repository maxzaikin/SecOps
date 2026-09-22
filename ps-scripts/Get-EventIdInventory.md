# Get-EventIdInventory PowerShell Script

## Overview
The **`Get-EventIdInventory`** function builds a full inventory of what actually shows up in a workstation's Windows Event Logs: every unique combination of **log name + EventID** it can find, together with a sample description, the provider, a hit count, first/last seen timestamps, and (where the provider records it) the Windows account the event fired under. It is meant to answer a simple but often-unanswered question in an IS/SIEM program: *"what event types are our endpoints actually producing, and are we ingesting all of them?"*

---

## Features
- Enumerates every non-empty event log on the machine by default, or a specific list you pass in.
- Groups events into a single unique row per `(LogName, EventID)` pair instead of dumping raw events.
- Resolves the event's SID (`UserId`) to an account name via `.Translate([NTAccount])`, falling back to the raw SID when it can't be resolved.
- Supports `-WhatIf` to preview exactly which logs would be read and where the CSV would land, without touching disk.
- Shows live progress (`Write-Progress`, two levels: per-log and per-event) and timestamped, color-coded status messages in the console.
- Accepts log names via pipeline (`'Security','System' | Get-EventIdInventory`).
- Writes the result as CSV **and** emits the same objects to the pipeline, so it composes with the rest of PowerShell (`Get-EventIdInventory | Where-Object Count -gt 1000`).
- CSV is always written as UTF-8 **with BOM** via raw .NET (`[System.Text.UTF8Encoding]::new($true)` + `[System.IO.File]::WriteAllLines`), not the `-Encoding UTF8` cmdlet switch — that switch means "with BOM" on Windows PowerShell 5.1 but "without BOM" on PowerShell 7/Core, and without a BOM, Excel frequently mangles Cyrillic usernames/descriptions on a plain double-click open.

---

## Parameters
| Parameter         | Description                                                                                   | Mandatory |
|--------------------|-----------------------------------------------------------------------------------------------|-----------|
| `LogNames`         | One or more log names to process. Also accepts pipeline input. If omitted (no argument, no pipeline input), every log with `RecordCount -gt 0` is enumerated automatically. | No        |
| `MaxEventsPerLog`  | Caps how many events are read from a single log (guards against a multi-hour pass over a Security log with millions of records). `0` = no limit, read the log in full. Default: `50000`. | No        |
| `OutputCsv`        | Path to the resulting CSV. Defaults to a timestamped file named after the computer, in the current directory. | No        |

`Get-EventIdInventory` also supports the common `-WhatIf` and `-Confirm` parameters (`[CmdletBinding(SupportsShouldProcess = $true)]`).

---

## Loading the function
This file defines a single function, not a module — it is not auto-loaded. Dot-source it once per session before calling it:

```powershell
. .\Get-EventIdInventory.ps1
Get-EventIdInventory -WhatIf
```

---

## Examples

### Example 1: Full inventory, default limits
```powershell
Get-EventIdInventory
```
- Enumerates every non-empty log on the machine.
- Reads up to 50000 events per log.
- Saves `EventIdInventory_<COMPUTERNAME>_<timestamp>.csv` in the current directory.

### Example 2: Specific logs, no cap
```powershell
Get-EventIdInventory -LogNames 'Security','System','Application' -MaxEventsPerLog 0
```
- Reads only the three named logs, in full (no per-log cap).

### Example 3: Preview only
```powershell
Get-EventIdInventory -WhatIf
```
- Lists every log that would be read and the CSV path that would be written.
- Reads no events and writes no file.

### Example 4: Pipe log names in, filter the result
```powershell
'Security','System' | Get-EventIdInventory | Where-Object Count -gt 1000 | Format-Table
```
- Processes just those two logs and filters the returned objects for high-frequency EventIDs.

---

## How It Works

1. **Initialization (`begin`):**
   - Sets up the UTF-8-with-BOM encoding used for the CSV.
   - Defines the internal `Write-Info` (timestamped, color-coded console logging) and `Resolve-UserName` (SID → account name) helpers.
   - If no `-LogNames` was supplied and nothing is coming through the pipeline, enumerates all logs with `RecordCount -gt 0`.

2. **Collection (`process`):**
   - For each log (subject to `-WhatIf`/`-Confirm` via `ShouldProcess`), calls `Get-WinEvent` and walks its events.
   - Groups events by `(LogName, EventID)`, keeping the first message line as a description, a running count, first/last-seen timestamps, and the set of resolved usernames seen for that EventID.
   - Logs that error out (most often a permissions problem) are recorded and reported at the end rather than aborting the whole run.

3. **Export (`end`):**
   - Builds one row per unique `(LogName, EventID)` pair, sorted by log then EventID.
   - Writes it to `-OutputCsv` as UTF-8 with BOM.
   - Emits the same objects to the pipeline.
   - Reports how many logs (if any) could not be processed.

---

## ⚠️ Which Account To Run This As

1. **The Security log** is not readable by a plain standard user. Membership in the built-in local group **"Event Log Readers"** (SID `S-1-5-32-573`) is enough for read access — full local-administrator rights are not required just for that.

2. **Several `Microsoft-Windows-*/Operational` channels**, and in particular the hidden **Analytic/Debug** channels, are ACL'd to Administrators/SYSTEM only; Event Log Readers membership will not open those. Reading them requires local-administrator rights (and, for Analytic/Debug channels, enabling them first with `wevtutil sl <channel> /e:true`), or a channel ACL explicitly widened with `wevtutil sl <channel> /ca:<SDDL>`.

3. **For fleet-wide rollout via GPO/RMM**, the simplest option is a scheduled task running as `NT AUTHORITY\SYSTEM` — SYSTEM has full read access to every log, including Security and the hidden Analytic/Debug channels, with no extra group membership needed.

**Summary:** for a one-off manual run on a single machine, membership in "Event Log Readers" covers Security + Application + System + most Operational logs. For full coverage (including hidden Analytic/Debug) and/or fleet deployment, use SYSTEM (via a scheduled task) or a local administrator account.

> **Note:** this version assumes an interactive human running it in a PowerShell 7 console — all status/progress output goes to `Write-Host`/`Write-Progress` only, there is no log-file fallback. If you deploy this unattended (e.g. as a SYSTEM-run scheduled task), that console output will not be visible anywhere; re-introduce a log-file sink before doing that.

---

## Handling the Output

The resulting CSV can contain Windows account names (including domain accounts) and localized event text pulled straight from the endpoint. Treat it like any other collected audit artifact:
- Store it under access-controlled paths, not general-purpose shares.
- Don't email it unencrypted if the workstation belongs to a regulated scope.
- If you aggregate CSVs from many workstations for the fleet-wide view, apply the same handling to the aggregate.

---

## Known Limitations

- **`UserId` is not always populated.** Many system, driver, and a good share of Application-log events never carry a SID at all — for those, the `Users` column is simply empty. This is a property of the event source, not a script defect.
- **`Description` is a sample, not the full template.** It is the first line of one actual occurrence's `Message`, not the generic, unparameterized message template — for parameterized messages it may read slightly differently than what you see in Event Viewer's own description field.
- **`MaxEventsPerLog` truncation.** With the default cap (50000), a very large log (e.g. Security with millions of records) may not surface every rare EventID present in its full history — rerun with `-MaxEventsPerLog 0` for a complete pass if that matters.
- **Windows-only.** `Get-WinEvent` (and the whole `Microsoft.PowerShell.Diagnostics` module it lives in) is only available on Windows, including under PowerShell 7 — there is no Linux/macOS equivalent to fall back to.

---

## Requirements
- Windows PowerShell 5.1 or PowerShell 7+ (developed and tested against PowerShell 7).
- Windows OS (workstation or server) with the standard Event Log service running.

---

## ⚠️ Disclaimer

All scripts are provided as-is with no implicit warranty or support.

- Always test scripts in a DEV/TEST environment before using them in production.
- Use at your own risk!