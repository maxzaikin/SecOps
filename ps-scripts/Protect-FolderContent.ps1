function Protect-FolderContent {
    <#
        .SYNOPSIS
            Encrypts files in a folder and generates a CSV file with SHA256 hashes.

        .PARAMETER SourcePath
            Path to the folder whose files will be encrypted.

        .PARAMETER OutputCSV
            Path to the resulting CSV file with hashes.

        .PARAMETER Passphrase
            Passphrase used for encryption (salt), provided as a SecureString.

        .EXAMPLE
            Protect-FolderContent -SourcePath "C:\Data" -OutputCSV "C:\hashes.csv" -Passphrase (ConvertTo-SecureString -String "SecretSalt" -AsPlainText -Force)

        .NOTES
            Version: 1.1
            Author: M. Zaikin
            Date: 19-Apr-2025
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param (
        [Parameter(Mandatory = $true)]
        [string]$SourcePath,

        [Parameter(Mandatory = $true)]
        [string]$OutputCSV,

        [Parameter(Mandatory = $true)]
        [SecureString]$Passphrase
    )

    BEGIN {
        $results = @()
        $aes = [System.Security.Cryptography.Aes]::Create()

        # Convert SecureString to plain text for encryption key
        $key = [System.Text.Encoding]::UTF8.GetBytes((ConvertFrom-SecureString $Passphrase | Out-String).Trim())
        $key = $key[0..31]  # Ensure key is 32 bytes

        $iv = $key[0..15]  # IV is the first 16 bytes of the key
        $aes.Key = $key
        $aes.IV = $iv

        $parentDir = Split-Path -Path $SourcePath -Parent
        $sourceFolderName = Split-Path -Path $SourcePath -Leaf
        $encryptedRoot = Join-Path -Path $parentDir -ChildPath "${sourceFolderName}.enc"

        if (-not (Test-Path $encryptedRoot)) {
            if ($PSCmdlet.ShouldProcess($encryptedRoot, "Create encrypted root directory")) {
                New-Item -ItemType Directory -Path $encryptedRoot -Force | Out-Null
            }
        }
    }

    PROCESS {
        
        Get-ChildItem -Path $SourcePath -Recurse -Directory | ForEach-Object {
            $relativeDir = $_.FullName.Substring($SourcePath.Length).TrimStart('\')
            $encDirPath = Join-Path -Path $encryptedRoot -ChildPath $relativeDir

            if (-not (Test-Path $encDirPath)) {
                if ($PSCmdlet.ShouldProcess($encDirPath, "Create directory")) {
                    New-Item -ItemType Directory -Path $encDirPath -Force | Out-Null
                }
            }
        }

        # Encrypt data
        Get-ChildItem -Path $SourcePath -Recurse -File | ForEach-Object {
            $file = $_
            $relativePath = $file.FullName.Substring($SourcePath.Length).TrimStart('\')
            $encTargetPath = Join-Path $encryptedRoot $relativePath
            $encTargetPath += ".enc"

            $bytes = [System.IO.File]::ReadAllBytes($file.FullName)

            $sha256 = [System.BitConverter]::ToString(
                [System.Security.Cryptography.SHA256]::Create().ComputeHash($bytes)
            ) -replace '-', ''

            $encryptor = $aes.CreateEncryptor()
            $encrypted = $encryptor.TransformFinalBlock($bytes, 0, $bytes.Length)

            if ($PSCmdlet.ShouldProcess($encTargetPath, "Write encrypted file")) {
                [System.IO.File]::WriteAllBytes($encTargetPath, $encrypted)
                Write-Host "🔖 Successfully encrypted file: $($encTargetPath)" -ForegroundColor Green
            }

            $results += [PSCustomObject]@{
                OriginalPath    = $file.FullName
                EncryptedPath   = $encTargetPath
                OriginalName    = $file.Name
                EncryptedName   = [System.IO.Path]::GetFileName($encTargetPath)
                FileHash_SHA256 = $sha256
            }
        }

        if ($PSCmdlet.ShouldProcess($OutputCSV, "Write CSV log")) {
            $results | Export-Csv -Path $OutputCSV -NoTypeInformation -Encoding UTF8
        }
    }

    END {
        $aes.Dispose()
        Write-Verbose "📤 Encryption completed and saved in: $encryptedRoot"
    }
}
