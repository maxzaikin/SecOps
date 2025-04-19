function Get-RandomPassphrase {
    <#
    .SYNOPSIS
        Generates a random passphrase and returns its SHA-512 hash in hex.

    .PARAMETER ByteLength
        Number of random bytes to generate (default 32). 

    .EXAMPLE
        # Generate 32‑bytes random passphrase and show SHA-512
        Get-RandomPassphrase

    .EXAMPLE
        # Generate 64‑bytes random passphrase and show SHA-512
        New-RandomPassphrase -ByteLength 64

    .NOTES
        Version: 1.0
        Author:  M. Zaikin
        Date:    2025-04-19
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [int]$ByteLength = 32
    )

    BEGIN {
        # Build random numbers generator SHA-512
        $rng    = [System.Security.Cryptography.RandomNumberGenerator]::Create()
        $sha512 = [System.Security.Cryptography.SHA512]::Create()
    }

    PROCESS {
        # Genearet ranodm bytes seq
        $bytes = New-Object byte[] $ByteLength
        $rng.GetBytes($bytes)

        # Compute SHA-512
        $hashBytes = $sha512.ComputeHash($bytes)

        # Convert to string
        $hex = ([System.BitConverter]::ToString($hashBytes)).Replace('-', '')

        Write-Output "🔐: $($hex)"
    }

    END {
        $rng.Dispose()
        $sha512.Dispose()
    }
}
