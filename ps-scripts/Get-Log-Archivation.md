# Get-Log-Archivation PowerShell Script

## Overview
The **`Get-Log-Archivation`** function automates the archiving of old log files and maintains folder hygiene by compressing and removing outdated files. It is designed to ensure efficient log file management in IT infrastructure.

---

## Features
- Archives old log files based on their age.
- Deletes outdated archive files (`*.zip`).
- Maintains a detailed log of performed actions in a specified log file.
- User-configurable parameters for flexibility.

---

## Parameters
| Parameter       | Description                                                                 | Mandatory |
|-----------------|-----------------------------------------------------------------------------|-----------|
| `OldFilesAge`   | Filters log files for archiving based on the specified age (in days).       | Yes       |
| `OldCabsAge`    | Removes archive files (`*.zip`) older than the specified age (in days).     | Yes       |
| `LogFilePath`   | Specifies the path to the log file for saving all actions and statuses.     | Yes       |

---

## Examples

### Example 1: Archive Logs and Remove Old Archives
```powershell
Get-Log-Archivation -OldFilesAge 7 -OldCabsAge 30 -LogFilePath 'C:\Temp\log.log'
```

- Archives log files older than 7 days.
- Deletes archive files (`*.zip`) older than 30 days.
- Logs all actions to the file `C:\Temp\log.log`.

### Example 2: A Immediate Archiving and Deletion
```powershell
Get-Log-Archivation -OldFilesAge 0 -OldCabsAge 0 -LogFilePath 'C:\Temp\log.log'
```

- Archives all log files regardless of age.
- Deletes all archive files (*.zip) regardless of age.
- Logs all actions to C:\Temp\log.log.

### How It Works

1. Initialization:
  - The script initializes with a set of predefined paths for monitoring.
  - It writes a start message to the specified log file.

2. Archiving Process:
  - Identifies log files older than OldFilesAge and compresses them into .zip archives.
  - Removes the original log files after successful archiving.

3. Cleanup:
  - Deletes archive files (*.zip) older than OldCabsAge.

4. Error Handling:
  - Catches and logs any errors that occur during the process.

5. Completion:
  - Writes an end message to the log file upon successful execution.

### ⚠️ Disclaimer

 All scripts are provided as-is with no implicit warranty or support.

- Always test scripts in a DEV/TEST environment before using them in production.
- Use at your own risk!