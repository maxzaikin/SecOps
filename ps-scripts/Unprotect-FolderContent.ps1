function Unprotect-FolderContent {
    <#
        .SYNOPSIS
            Decrypts encrypted files from a .enc folder and restores them to a .dec folder.

        .PARAMETER SourceEncPath
            Path to the encrypted folder (e.g., C:\Data.enc).

        .PARAMETER Passphrase
            The same passphrase used for encryption.

        .EXAMPLE
            Unprotect-FolderContent2 -SourceEncPath "C:\Data.enc" -Passphrase "SecretSalt"
            Protect-FolderContent -SourcePath "C:\Data" -OutputCSV "C:\hashes.csv" -Passphrase (ConvertTo-SecureString -String "SecretSalt" -AsPlainText -Force)

        .NOTES
            Version: 1.0
            Author: M. Zaikin
            Date: 19-Apr-2025
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param (
        [Parameter(Mandatory = $true)]
        [string]$SourceEncPath,

        [Parameter(Mandatory = $true)]
        [SecureString]$Passphrase
    )

    BEGIN {
        if (-not (Test-Path $SourceEncPath)) {
            Write-Error "Encrypted path '$SourceEncPath' does not exist."
            return
        }

        $aes = [System.Security.Cryptography.Aes]::Create()
        $key = [System.Text.Encoding]::UTF8.GetBytes((ConvertFrom-SecureString $Passphrase | Out-String).Trim().PadRight(32)[0..31] -join '')
        $iv = $key[0..15]
        $aes.Key = $key
        $aes.IV = $iv

        $parentDir = Split-Path -Path $SourceEncPath -Parent
        $encFolderName = Split-Path -Path $SourceEncPath -Leaf
        $baseFolderName = $encFolderName -replace '\.enc$', ''
        $decryptedRoot = Join-Path -Path $parentDir -ChildPath "${baseFolderName}.dec"

        if (-not (Test-Path $decryptedRoot)) {
            if ($PSCmdlet.ShouldProcess($decryptedRoot, "Create decrypted root directory")) {
                New-Item -ItemType Directory -Path $decryptedRoot -Force | Out-Null
            }
        }
    }

    PROCESS {
        # Воссоздание структуры директорий
        Get-ChildItem -Path $SourceEncPath -Recurse -Directory | ForEach-Object {
            $relativePath = $_.FullName.Substring($SourceEncPath.Length).TrimStart('\')
            $decDirPath = Join-Path -Path $decryptedRoot -ChildPath $relativePath

            if (-not (Test-Path $decDirPath)) {
                if ($PSCmdlet.ShouldProcess($decDirPath, "Create directory")) {
                    New-Item -ItemType Directory -Path $decDirPath -Force | Out-Null
                }
            }
        }

        # Дешифрование файлов
        Get-ChildItem -Path $SourceEncPath -Recurse -File | Where-Object { $_.Name -like '*.enc' } | ForEach-Object {
            $encFile = $_
            $relativePath = $encFile.FullName.Substring($SourceEncPath.Length).TrimStart('\')
            $decRelativePath = $relativePath -replace '\.enc$', ''
            $decFullPath = Join-Path -Path $decryptedRoot -ChildPath $decRelativePath

            $encBytes = [System.IO.File]::ReadAllBytes($encFile.FullName)
            $decryptor = $aes.CreateDecryptor()
            try {
                $plainBytes = $decryptor.TransformFinalBlock($encBytes, 0, $encBytes.Length)

                if ($PSCmdlet.ShouldProcess($decFullPath, "Write decrypted file")) {
                    [System.IO.File]::WriteAllBytes($decFullPath, $plainBytes)
                     Write-Host "Successfully decrypt file: $($decFullPath)" -ForegroundColor Green
                }               
            }
            catch {
                Write-Warning "Failed to decrypt file: $($encFile.FullName)"
            }
        }
    }

    END {
        $aes.Dispose()
        Write-Verbose "Decryption complete. Decrypted content saved in: $decryptedRoot"
    }
}
