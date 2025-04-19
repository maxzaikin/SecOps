# 🔐 Protect‑FolderContent.ps1

A PowerShell function to **encrypt all files** in a folder (recursively), save them into a sibling `<folder>.enc` directory, and generate a **CSV log** with SHA‑256 hashes. Supports **SecureString** passphrase input to reduce key leakage risk.

---

## 🚀 Features

- 🔏 **AES‑256 Encryption** of file contents  
- 🗂️ **Preserves directory structure** under `<SourceFolder>.enc`  
- 🛡️ **SecureString** support for passphrase input  
- 📊 **Generates CSV** with original/encrypted paths & SHA‑256 hashes  
- ⚙️ **WhatIf** support for dry‑runs  

---

## 📥 Installation

1. **Download** `Protect-FolderContent.ps1` to your scripts folder.  
2. **Dot‑source** in your session or profile:
   ```powershell
   . "C:\Path\To\Protect-FolderContent.ps1"
