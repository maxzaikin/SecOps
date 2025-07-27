# 🕵️‍♂️ AD ShadowAdmin Analysis PS Toolkit

## 📘 Overview

The [**`Get-ShadowAdmin-Analysis-Ext`**](https://github.com/maxzaikin/SecOps/blob/main/ps-scripts/Get-ShadowAdmin-Analysis-Ext.ps1) and [**`Get-ShadowAdmin-Analysis`**](https://github.com/maxzaikin/SecOps/blob/main/ps-scripts/Get-ShadowAdmin-Analysis.ps1)PowerShell scripts performs an in-depth audit of a specified Active Directory (AD) user to detect **shadow administrator** access paths. These are indirect privilege paths that result from **nested group memberships**.

This extended version enhances the original functionality by:

- Displaying detailed user attributes.
- Reporting the queried Domain Controller.
- Printing all group membership chains leading to privileged groups.

---

## ✨ Features

- 🔁 Recursively explores all nested AD group memberships.
- 🛡️ Detects inheritance paths to high-privilege groups (e.g., `Domain Admins`).
- 🧑‍💼 Prints extended user information (e.g., `DisplayName`, `Mail`, `Manager`, `SID`, `Account Status`).
- 🖥️ Displays the name of the queried Domain Controller.
- 📊 Outputs all group membership chains, with privileged ones highlighted.
- 🧾 Generates a clear, readable security summary.

---

## ⚙️ Parameters

| Parameter         | Description                                                             | Required |
|-------------------|-------------------------------------------------------------------------|----------|
| `SamAccountName`  | The `SamAccountName` of the user to audit for shadow admin privileges. | ✅ Yes   |

---

## 🚀 Examples

### 🔹 Example 1: Basic audit

```powershell
Get-ShadowAdmin-Analysis-Ext -SamAccountName jdoe
```

- Performs recursive analysis of the user jdoe’s group memberships.
- Detects any inherited membership in privileged groups.
- Displays a full access path report with user attributes.

## 🧠 How It Works

- 🔧 Initialization

  - Sets a list of high-privilege AD groups to look for.
  - Tracks shadow admin path count.

- 🔍 User Lookup
  - Uses Get-ADUser to retrieve user info and attributes:
  - DisplayName, SID, Mail, Manager, Enabled, LockedOut, etc.

- 🧱 Group Processing

  - Iterates over each direct group the user belongs to.
  - Uses recursive logic (MemberOf) to trace upward to privileged groups.
  - Highlights paths with inherited privileges.

- 📑 Final Report

  - Displays:
            Queried Domain Controller  
            All direct group names  
            All group membership chains  
            Shadow access warning (if applicable)  

## 🔐 Privileged Groups List

Default high-privilege groups included in the script:  

```powershell
$PrivilegedGroups = @(
    'Administrators',
    'Domain Admins',
    'Enterprise Admins',
    'Schema Admins',
    'Server Operators',
    'Backup Operators',
    'Account Operators',
    'Print Operators',
    'list_your_AD_specific_groups...'
)
```

Make sure you  adjusted this list to match your organization’s specific environment, Yes you have to know your AD priv. realm.

## ⚠️ Disclaimer

- This script is provided as-is without any warranty.
- Use in production environments at your own risk.
- Always test in a lab or DEV environment before deployment.
