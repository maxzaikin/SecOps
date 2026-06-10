function Get-ConvertFstecIoCToSiem {
    <#
        .SYNOPSIS
            Converts FSTEC IoC files (Legacy TXT and New CSV) into optimized CSV files for MaxPatrol SIEM.

        .DESCRIPTION
            This script parses Threat Intelligence data provided by FSTEC. It supports:
            1. Legacy (.txt): Line-based parsing with section headers.
            2. New (.csv): Column-based parsing using a strictly validated semicolon-delimited structure.

            Logic features:
            - Automatic Doc ID: If FstecDoc is not provided, it is extracted from the filename.
            - Header Validation: Prevents data loss by stopping on unknown CSV columns.
            - Progress Tracking: Real-time progress bar for both large CSV and TXT files.
            - Resume ID Logic: Scans existing files to continue ID numbering.
            - WhatIf Support: Generates a ready-to-run command with pre-calculated starting IDs.

        .PARAMETER InputPath
            Full path to the source FSTEC IoC file (.txt or .csv).

        .PARAMETER FstecDoc
            Optional. Directive or Letter ID. If omitted, extracted from filename (strips 'FSTEC-IOC-' prefix).

        .PARAMETER OutDir
            Directory for output CSVs. The script appends to existing files if found.

        .PARAMETER StartIpId, StartUrlId, StartHashId, StartFileId, StartEmailId
            Optional. Overrides auto-detected starting IDs.

        .EXAMPLE
            Get-ConvertFstecIoCToSiem -InputPath "C:\IoC\FSTEC-IOC-240-93-1581.csv" -OutDir "C:\SIEM"
            Processes the CSV and automatically sets FstecDoc to "240-93-1581".

        .NOTES
            Version: 3.1
            Author: Maks V. Zaikin
            Language: English (Code/Docs), Russian (Support)

        [-------------------------------------DISCLAIMER-------------------------------------]
        This script is provided "AS IS". Always verify CSV headers before processing.
        [-------------------------------------DISCLAIMER-------------------------------------]
    #>

    [CmdletBinding(SupportsShouldProcess = $true)]
    param (
        [Parameter(Mandatory = $true, Position = 0)][string]$InputPath,
        [Parameter(Mandatory = $false, Position = 1)][string]$FstecDoc,
        [Parameter(Mandatory = $false)][string]$OutDir = "C:\SIEM_Import",
        [int]$StartIpId,
        [int]$StartUrlId,
        [int]$StartHashId,
        [int]$StartFileId,
        [int]$StartEmailId
    )

    BEGIN {
        $StopWatch = [System.Diagnostics.Stopwatch]::StartNew()
        
        # Determine FstecDoc from filename if not provided
        if ([string]::IsNullOrWhiteSpace($FstecDoc)) {
            $FstecDoc = [System.IO.Path]::GetFileNameWithoutExtension($InputPath) -replace '^FSTEC-IOC-', ''
            Write-Host "[*] Derived FstecDoc from filename: $FstecDoc" -ForegroundColor Gray
        }

        # Categories mapping
        $Paths = @{
            IP    = Join-Path $OutDir "FSTEC_IOC_IP.csv"
            URL   = Join-Path $OutDir "FSTEC_IOC_URL.csv"
            HASH  = Join-Path $OutDir "FSTEC_IOC_HASH.csv"
            FILE  = Join-Path $OutDir "FSTEC_IOC_FILE.csv"
            EMAIL = Join-Path $OutDir "FSTEC_IOC_EMAIL.csv"
        }

        $KnownHeaders = @(
            "IP АДРЕСА", "URL (URI) ССЫЛКИ", "ДОМЕННЫЕ ИМЕНА", "АДРЕСА E-MAIL",
            "ХЭШ СУММЫ MD5 (НЕДОВЕРЕННЫЕ)", "ХЭШ СУММЫ SHA1 (НЕДОВЕРЕННЫЕ)", "ХЭШ СУММЫ SHA256 (НЕДОВЕРЕННЫЕ)",
            "ХЭШ СУММЫ MD5 (ДОВЕРЕННЫЕ, НЕОПРЕДЕЛЕННЫЕ, Н/Д)", 
            "ХЭШ СУММЫ SHA1 (ДОВЕРЕННЫЕ, НЕОПРЕДЕЛЕННЫЕ, Н/Д)", 
            "ХЭШ СУММЫ SHA256 (ДОВЕРЕННЫЕ, НЕОПРЕДЕЛЕННЫЕ, Н/Д)"
        )

        $Counters = @{ IP = 0; URL = 0; HASH = 0; FILE = 0; EMAIL = 0 }
        $Stats = [ordered]@{ "IP" = 0; "URL" = 0; "HASH" = 0; "FILE" = 0; "EMAIL" = 0 }

        # Helper: Defanging and trimming
        function Get-CleanValue {
            param([string]$Val)
            if ([string]::IsNullOrWhiteSpace($Val)) { return $null }
            return $Val.Trim().Replace("[.]", ".").Replace("[:]", ":").Replace("[://]", "://") `
                       -replace "hxxps", "https" -replace "hxxp", "http"
        }

        # Helper: Repository Resume Logic
        function Get-LastIdFromRepo {
            param([string]$Path)
            if (Test-Path $Path) {
                $lastLine = Get-Content $Path -Tail 1
                if ($lastLine -match '"(\d+)";"') { return [int]$matches[1] }
            }
            return 0
        }

        # Initialize Counters
        foreach ($key in $Paths.Keys) {
            $Counters.$key = Get-LastIdFromRepo -Path $Paths.$key
        }

        # Manual Overrides
        if ($PSBoundParameters.ContainsKey('StartIpId'))    { $Counters.IP    = $StartIpId }
        if ($PSBoundParameters.ContainsKey('StartUrlId'))   { $Counters.URL   = $StartUrlId }
        if ($PSBoundParameters.ContainsKey('StartHashId'))  { $Counters.HASH  = $StartHashId }
        if ($PSBoundParameters.ContainsKey('StartFileId'))  { $Counters.FILE  = $StartFileId }
        if ($PSBoundParameters.ContainsKey('StartEmailId')) { $Counters.EMAIL = $StartEmailId }

        $Tables = @{
            IP    = [System.Collections.Generic.List[PSObject]]::new()
            URL   = [System.Collections.Generic.List[PSObject]]::new()
            HASH  = [System.Collections.Generic.List[PSObject]]::new()
            FILE  = [System.Collections.Generic.List[PSObject]]::new()
            EMAIL = [System.Collections.Generic.List[PSObject]]::new()
        }

        Write-Host "[*] Processing File: $(Split-Path $InputPath -Leaf)" -ForegroundColor Cyan
    }

    PROCESS {
        try {
            $Extension = [System.IO.Path]::GetExtension($InputPath).ToLower()

            switch ($Extension) {
                ".csv" {
                    # --- NEW CSV PROCESSING ---
                    $CsvData = Import-Csv -Path $InputPath -Delimiter ";" -Encoding UTF8
                    $TotalRows = $CsvData.Count
                    
                    # Header Validation
                    $CurrentHeaders = $CsvData[0].PSObject.Properties.Name
                    foreach ($Header in $CurrentHeaders) {
                        if ($Header -notin $KnownHeaders -and ![string]::IsNullOrWhiteSpace($Header)) {
                            throw "CRITICAL: Unknown CSV column detected: '$Header'. Logic update required."
                        }
                    }

                    for ($i = 0; $i -lt $TotalRows; $i++) {
                        $Row = $CsvData[$i]
                        Write-Progress -Activity "Parsing CSV Rows" -Status "Row $($i+1) of $TotalRows" -PercentComplete (($i / $TotalRows) * 100)

                        # IP
                        if ($Val = Get-CleanValue $Row.'IP АДРЕСА') {
                            $Counters.IP++; $Stats.IP++
                            $Tables.IP.Add([PSCustomObject]@{ id = $Counters.IP; fstec_doc = $FstecDoc; ioc_type = "IP"; ioc_val = $Val.Split(':')[0]; original_val = $Val })
                        }

                        # URL/Domains
                        foreach ($Col in @('URL (URI) ССЫЛКИ', 'ДОМЕННЫЕ ИМЕНА')) {
                            if ($RawUrl = Get-CleanValue $Row.$Col) {
                                $Counters.URL++; $Stats.URL++
                                $RegexVal = ".*" + [Regex]::Escape(($RawUrl -replace '^(https?|hxxps?)://', '' -replace '/[^/]+\.[^/.]+$', '/')) + ".*"
                                $Tables.URL.Add([PSCustomObject]@{ id = $Counters.URL; fstec_doc = $FstecDoc; ioc_type = "URL"; ioc_val = $RegexVal; original_val = $RawUrl })
                            }
                        }

                        # Hashes (Unconditional import)
                        $HashMapping = @{
                            'ХЭШ СУММЫ MD5 (НЕДОВЕРЕННЫЕ)'                      = 'MD5'
                            'ХЭШ СУММЫ SHA1 (НЕДОВЕРЕННЫЕ)'                     = 'SHA1'
                            'ХЭШ СУММЫ SHA256 (НЕДОВЕРЕННЫЕ)'                   = 'SHA256'
                            'ХЭШ СУММЫ MD5 (ДОВЕРЕННЫЕ, НЕОПРЕДЕЛЕННЫЕ, Н/Д)'    = 'MD5'
                            'ХЭШ СУММЫ SHA1 (ДОВЕРЕННЫЕ, НЕОПРЕДЕЛЕННЫЕ, Н/Д)'   = 'SHA1'
                            'ХЭШ СУММЫ SHA256 (ДОВЕРЕННЫЕ, НЕОПРЕДЕЛЕННЫЕ, Н/Д)' = 'SHA256'
                        }
                        foreach ($Col in $HashMapping.Keys) {
                            if ($RawHash = $Row.$Col) {
                                $Counters.HASH++; $Stats.HASH++
                                $Tables.HASH.Add([PSCustomObject]@{ id = $Counters.HASH; fstec_doc = $FstecDoc; ioc_type = $HashMapping[$Col]; ioc_val = $RawHash.Trim().ToLower() })
                            }
                        }

                        # Emails
                        if ($Email = Get-CleanValue $Row.'АДРЕСА E-MAIL') {
                            $Counters.EMAIL++; $Stats.EMAIL++
                            $Tables.EMAIL.Add([PSCustomObject]@{ id = $Counters.EMAIL; fstec_doc = $FstecDoc; ioc_type = "EMAIL"; ioc_val = $Email.ToLower(); original_val = $Email })
                        }
                    }
                }

                ".txt" {
                    # --- LEGACY TXT PROCESSING ---
                    $Lines = [System.IO.File]::ReadAllLines($InputPath, [System.Text.Encoding]::UTF8)
                    $TotalLines = $Lines.Count
                    $CurrentSection = ""

                    for ($i = 0; $i -lt $TotalLines; $i++) {
                        $Line = $Lines[$i].Trim()
                        Write-Progress -Activity "Parsing TXT Lines" -Status "Line $($i+1) of $TotalLines" -PercentComplete (($i / $TotalLines) * 100)

                        if ([string]::IsNullOrWhiteSpace($Line)) { continue }

                        switch -Regex ($Line.ToUpper()) {                    
                            "^URI.*:$|^URL.*:$"               { $CurrentSection = "URL"; continue }
                            "^IP-.*:$"                        { $CurrentSection = "IP"; continue }
                            "^ДОМЕНЫ.*:$|^DOMAIN.*:$"         { $CurrentSection = "URL"; continue }
                            "^SHA.*:$|^MD.*:$"                { $CurrentSection = "HASH"; continue }
                            "^ФАЙЛЫ.*:$"                      { $CurrentSection = "FILE"; continue }
                            ".*ПОЧТ.*:$|.*MAIL.*:$|EMAIL.*:$" { $CurrentSection = "EMAIL"; continue }
                        }
                        if ($Line.EndsWith(":")) { continue }

                        $Clean = Get-CleanValue $Line
                        switch ($CurrentSection) {
                            "IP" {
                                $Counters.IP++; $Stats.IP++
                                $Tables.IP.Add([PSCustomObject]@{ id = $Counters.IP; fstec_doc = $FstecDoc; ioc_type = "IP"; ioc_val = $Clean.Split(':')[0]; original_val = $Clean })
                            }
                            "URL" {
                                $Counters.URL++; $Stats.URL++
                                $RegexVal = ".*" + [Regex]::Escape(($Clean -replace '^(https?|hxxps?)://', '' -replace '/[^/]+\.[^/.]+$', '/')) + ".*"
                                $Tables.URL.Add([PSCustomObject]@{ id = $Counters.URL; fstec_doc = $FstecDoc; ioc_type = "URL"; ioc_val = $RegexVal; original_val = $Clean })
                            }
                            "HASH" {
                                $Counters.HASH++; $Stats.HASH++
                                $Type = if ($Clean.Length -eq 64) { "SHA256" } elseif ($Clean.Length -eq 32) { "MD5" } else { "SHA1" }
                                $Tables.HASH.Add([PSCustomObject]@{ id = $Counters.HASH; fstec_doc = $FstecDoc; ioc_type = $Type; ioc_val = $Clean.ToLower() })
                            }
                            "FILE" {
                                $Counters.FILE++; $Stats.FILE++
                                $Tables.FILE.Add([PSCustomObject]@{ id = $Counters.FILE; fstec_doc = $FstecDoc; ioc_type = "FILE"; ioc_val = $Clean.ToLower(); original_val = $Clean })
                            }
                            "EMAIL" {
                                $Counters.EMAIL++; $Stats.EMAIL++
                                $Tables.EMAIL.Add([PSCustomObject]@{ id = $Counters.EMAIL; fstec_doc = $FstecDoc; ioc_type = "EMAIL"; ioc_val = $Clean.ToLower(); original_val = $Clean })
                            }
                        }
                    }
                }

                default {
                    throw "Unsupported file extension '$Extension'. Please provide a .csv or .txt file."
                }
            }
        }
        catch {
            Write-Error "Execution Failed: $($_.Exception.Message)"
        }
        finally {
            Write-Progress -Activity "Parsing File" -Completed
        }
    }

    END {
        # Finalization and Export
        foreach ($Key in $Tables.Keys) {
            if ($Tables.$Key.Count -gt 0) {
                if ($PSCmdlet.ShouldProcess($Paths.$Key, "Exporting $($Tables.$Key.Count) records")) {
                    $Tables.$Key | Export-Csv -Path $Paths.$Key -Delimiter ";" -NoTypeInformation -Encoding UTF8 -Append
                    Write-Host "[+] Data appended to $($Paths.$Key)" -ForegroundColor Green
                }
            }
        }

        # WhatIf Command Hint
        if ($PSBoundParameters.ContainsKey('WhatIf') -and $PSBoundParameters['WhatIf']) {
            $Cmd = "Get-ConvertFstecIoCToSiem -InputPath `"$InputPath`" -FstecDoc `"$FstecDoc`" -OutDir `"$OutDir`""
            if ($Counters.IP -gt 0)    { $Cmd += " -StartIpId $($Counters.IP)" }
            if ($Counters.URL -gt 0)   { $Cmd += " -StartUrlId $($Counters.URL)" }
            if ($Counters.HASH -gt 0)  { $Cmd += " -StartHashId $($Counters.HASH)" }
            if ($Counters.FILE -gt 0)  { $Cmd += " -StartFileId $($Counters.FILE)" }
            if ($Counters.EMAIL -gt 0) { $Cmd += " -StartEmailId $($Counters.EMAIL)" }
            
            Write-Host "`n[WHATIF] Re-run command with pre-calculated IDs:" -ForegroundColor Yellow
            Write-Host $Cmd -ForegroundColor Cyan
        }

        # Summary
        Write-Host "`n---------------- PROCESSING SUMMARY ----------------" -ForegroundColor Cyan
        $Stats.GetEnumerator() | ForEach-Object { Write-Host "$($_.Name.PadRight(10)) : $($_.Value) items processed" }
        Write-Host "Duration   : $($StopWatch.Elapsed.ToString())" -ForegroundColor Cyan
        Write-Host "----------------------------------------------------`n" -ForegroundColor Cyan
        $StopWatch.Stop()
    }
}