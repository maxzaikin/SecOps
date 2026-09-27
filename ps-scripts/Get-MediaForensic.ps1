#Requires -Version 7.0

function Get-MediaForensic {
    <#
    .SYNOPSIS
        Forensic snapshot of removable media, a folder or selected files: hashes, NTFS streams, links, verdicts.

    .DESCRIPTION
        Read-only. Builds a snapshot of every input path:
          - one row per file, folder, link (reparse point) and alternate data stream;
          - SHA-256 of file content and of every alternate stream;
          - attributes and UTC timestamps;
          - Zone.Identifier (Mark of the Web) parsed: ZoneId and host domain only;
          - links are recorded with their target and never followed;
          - volume and device details: file system, cluster size, volume serial,
            disk model, serial number, bus type, partitions, unallocated space.

        Every row gets a Verdict (None / Info / Review / Alert) and a Reason
        (scanner-rules\ads.md, scanner-rules\motw.md).

        With -Baseline the snapshot is compared with a previous CSV by relative
        path: Added / Removed / Changed / Unchanged.

        Output: CSV (data, for comparison), HTML (human-readable report with
        findings only), log file, console summary. The SHA-256 of the CSV is
        written to the log and to the HTML report.

    .PARAMETER Path
        Files and/or folders to inspect: a drive root (E:\), a folder or single
        files. Accepts pipeline input (strings or objects with FullName).
        Default: current folder.

    .PARAMETER NoRecurse
        For folders: inspect direct children only.

    .PARAMETER StreamsOnly
        Fast mode: do not hash file content, only find and hash alternate streams.

    .PARAMETER Baseline
        Previous CSV produced by this tool. Enables Added / Removed / Changed.

    .PARAMETER OutputPath
        CSV result file. Default:
        .\MediaForensic_<COMPUTERNAME>_<yyyyMMdd_HHmmss>.csv

    .PARAMETER HtmlPath
        HTML report. Default: same as OutputPath with the .html extension.

    .PARAMETER LogPath
        Log file. Default: same as OutputPath with the .log extension.

    .PARAMETER CsvDelimiter
        CSV delimiter for output and for reading -Baseline. Default: ';'
        (opens correctly in Excel with Russian regional settings).

    .PARAMETER KnownStreams
        Stream names treated as legitimate (Verdict Info). Default:
        Zone.Identifier, SmartScreen, AFP_AfpInfo, AFP_Resource.

    .PARAMETER LargeStreamThresholdBytes
        An alternate stream larger than this gets Verdict Alert. Default: 65536.

    .PARAMETER UnallocatedThresholdBytes
        Unpartitioned space on the disk above this is reported for review.
        Default: 16777216 (16 MB; partition alignment normally leaves ~1 MB).

    .PARAMETER ProgressIntervalMs
        Minimum interval between progress bar updates, in milliseconds.
        Default: 250.

    .PARAMETER PassThru
        Also emit result rows to the pipeline.

    .EXAMPLE
        . .\scripts\ps7-only\Get-MediaForensic.ps1
        Get-MediaForensic -Path E:\

    .EXAMPLE
        Get-MediaForensic -Path E:\docs\report.pdf -StreamsOnly

    .EXAMPLE
        Get-ChildItem E:\docs -Filter *.pdf | Get-MediaForensic -OutputPath .\pdf.csv

    .EXAMPLE
        Get-MediaForensic -Path E:\ -Baseline .\MediaForensic_PC_20260101_120000.csv

    .NOTES
        Compatibility : PowerShell 7 only (stream hashing and folder streams need 7)
        CLM           : yes (cmdlets and operators only; simulated CLM tested)
        Admin rights  : not required
        Reads         : file content (hash), stream content (hash), Zone.Identifier text
        Writes        : OutputPath (CSV), HtmlPath (HTML), LogPath (log) only
        Never follows : junctions, symbolic links, mount points

   
        Version: 1.0
        Author: M. Zaikin
        Date: 27-Sep-2026
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Low')]
    [OutputType([object[]])]
    param(
        [Parameter(ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
        [Alias('FullName')]
        [string[]]$Path = (Get-Location).Path,

        [switch]$NoRecurse,

        [switch]$StreamsOnly,

        [string]$Baseline,

        [string]$OutputPath = ".\MediaForensic_$($env:COMPUTERNAME)_$(Get-Date -Format yyyyMMdd_HHmmss).csv",

        [string]$HtmlPath,

        [string]$LogPath,

        [ValidateLength(1, 1)]
        [string]$CsvDelimiter = ';',

        [string[]]$KnownStreams = @('Zone.Identifier', 'SmartScreen', 'AFP_AfpInfo', 'AFP_Resource'),

        [ValidateRange(0, 1099511627776)]
        [long]$LargeStreamThresholdBytes = 65536,

        [ValidateRange(0, 1099511627776)]
        [long]$UnallocatedThresholdBytes = 16777216,

        [ValidateRange(0, 60000)]
        [int]$ProgressIntervalMs = 250,

        [switch]$PassThru
    )

    BEGIN {
        $startTime = Get-Date
        $fatal     = $false
        # Mutable state shared with nested helpers (a hashtable is passed by reference).
        $state     = @{
            Files        = 0
            Folders      = 0
            Links        = 0
            Bytes        = [long]0
            Errors       = 0
            LastProgress = $startTime.AddDays(-1)
        }
        $work      = @()
        $volumes   = @{}

        # Resolve default and relative output paths against the current location.
        if (-not (Split-Path -Path $OutputPath -IsAbsolute)) {
            $OutputPath = Join-Path -Path (Get-Location).Path -ChildPath ($OutputPath -replace '^\.[\\/]', '')
        }
        $outputBase = $OutputPath -replace '\.csv$', ''
        foreach ($name in @('HtmlPath', 'LogPath')) {
            $value = Get-Variable -Name $name -ValueOnly
            if (-not $value) {
                $ext   = if ($name -eq 'HtmlPath') { '.html' } else { '.log' }
                $value = "$outputBase$ext"
            }
            elseif (-not (Split-Path -Path $value -IsAbsolute)) {
                $value = Join-Path -Path (Get-Location).Path -ChildPath ($value -replace '^\.[\\/]', '')
            }
            Set-Variable -Name $name -Value $value
        }

        # No log file under -WhatIf: console only.
        $logToFile = -not $WhatIfPreference

        # In Constrained Language Mode method calls on $PSCmdlet are blocked,
        # so ShouldProcess falls back to honoring -WhatIf only (-Confirm unsupported).
        $languageMode = "$($ExecutionContext.SessionState.LanguageMode)"
        $fullLanguage = ($languageMode -eq 'FullLanguage')
        $cmdlet       = $PSCmdlet

        function Test-ShouldProcess {
            <#
            .SYNOPSIS
                ShouldProcess wrapper that also works in Constrained Language Mode.
            .DESCRIPTION
                FullLanguage: calls the outer function's ShouldProcess (-WhatIf and -Confirm).
                ConstrainedLanguage: honors -WhatIf only.
            #>
            [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
            param(
                [Parameter(Mandatory = $true)][string]$Target,
                [Parameter(Mandatory = $true)][string]$Action
            )
            if ($fullLanguage) { return $cmdlet.ShouldProcess($Target, $Action) }
            if ($WhatIfPreference) {
                Write-Host "What if: Performing the operation `"$Action`" on target `"$Target`"."
                return $false
            }
            return $true
        }

        function Write-Log {
            <#
            .SYNOPSIS
                Writes one timestamped line to the console (colored by level) and to the log file.
            #>
            # Nested helper, not exported: shadowing a same-named command from other modules is intended.
            [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidOverwritingBuiltInCmdlets', '')]
            param(
                [Parameter(Mandatory = $true)][string]$Message,
                [ValidateSet('INFO', 'OK', 'WARN', 'ERROR', 'DEBUG')][string]$Level = 'INFO'
            )
            $line  = '{0} [{1,-5}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff'), $Level, $Message
            $color = switch ($Level) {
                'OK' { 'Green' }
                'WARN' { 'Yellow' }
                'ERROR' { 'Red' }
                'DEBUG' { 'DarkGray' }
                default { 'Gray' }
            }
            Write-Host $line -ForegroundColor $color
            if ($logToFile) {
                Add-Content -LiteralPath $LogPath -Value $line -Encoding utf8 -WhatIf:$false -Confirm:$false
            }
        }

        function Format-Size {
            <#
            .SYNOPSIS
                Human-readable size: B, KB, MB, GB, TB.
            #>
            param([long]$Bytes)
            if ($Bytes -ge 1TB) { return '{0:N1} TB' -f ($Bytes / 1TB) }
            if ($Bytes -ge 1GB) { return '{0:N1} GB' -f ($Bytes / 1GB) }
            if ($Bytes -ge 1MB) { return '{0:N1} MB' -f ($Bytes / 1MB) }
            if ($Bytes -ge 1KB) { return '{0:N1} KB' -f ($Bytes / 1KB) }
            return "$Bytes B"
        }

        function ConvertTo-CsvSafe {
            <#
            .SYNOPSIS
                Neutralizes CSV/formula injection: text starting with = + - @ tab CR gets a leading apostrophe.
            #>
            param([string]$Text)
            if ($Text -match '^[=+\-@\t\r]') { return "'$Text" }
            return $Text
        }

        function ConvertTo-HtmlText {
            <#
            .SYNOPSIS
                Escapes text for HTML (ConvertTo-Html escapes table cells itself; this is for free text).
            #>
            param([string]$Text)
            return ($Text -replace '&', '&amp;' -replace '<', '&lt;' -replace '>', '&gt;' -replace '"', '&quot;')
        }

        function Get-ErrorReason {
            <#
            .SYNOPSIS
                Short English reason for an ErrorRecord: category plus message.
            #>
            param($ErrorRecord)
            $category = "$($ErrorRecord.CategoryInfo.Category)"
            $message  = "$($ErrorRecord.Exception.Message)" -replace '\s+', ' '
            if ($message -match 'denied') { return "Access denied: $message" }
            if ($message -match 'too long') { return "Path too long: $message" }
            if ($message -match 'being used by another process') { return "File in use: $message" }
            return "${category}: $message"
        }

        function ConvertTo-ReportRow {
            <#
            .SYNOPSIS
                Creates one result row with a fixed column set (CLM-safe, no [pscustomobject]).
            #>
            param([hashtable]$Values)
            $row = [ordered]@{
                Root             = ''
                Type             = ''
                RelativePath     = ''
                Stream           = ''
                Size             = ''
                SHA256           = ''
                Attributes       = ''
                CreationTimeUtc  = ''
                LastWriteTimeUtc = ''
                LinkTarget       = ''
                ZoneId           = ''
                HostDomain       = ''
                Verdict          = 'None'
                Reason           = ''
                Change           = ''
                ChangeDetail     = ''
            }
            foreach ($key in $Values.Keys) { $row[$key] = $Values[$key] }
            foreach ($key in @('RelativePath', 'Stream', 'LinkTarget', 'HostDomain', 'Reason')) {
                $row[$key] = ConvertTo-CsvSafe -Text "$($row[$key])"
            }
            New-Object -TypeName PSObject -Property $row
        }

        function Get-VolumeInfo {
            <#
            .SYNOPSIS
                Volume and device details for the volume that holds a path (works for folder mount points).
            #>
            param([Parameter(Mandatory = $true)][string]$LiteralPath)
            $info = [ordered]@{
                Key              = $LiteralPath
                Label            = ''
                FileSystem       = ''
                VolumeSize       = [long]0
                ClusterSize      = ''
                VolumeSerial     = ''
                DiskNumber       = ''
                DiskModel        = ''
                DiskSerial       = ''
                BusType          = ''
                DiskSize         = [long]0
                PartitionStyle   = ''
                Partitions       = ''
                UnallocatedBytes = ''
                StreamsSupported = $true
                Note             = ''
            }

            # Volume: Win32_Volume whose mount path (Name) is the longest prefix of the item path.
            # Works for drive letters and folder mount points, and in CLM (the Storage module may not load).
            $pathKey = "$($LiteralPath.TrimEnd('\'))\".ToLower()
            $w32     = $null
            foreach ($v in @(Get-CimInstance -ClassName Win32_Volume -ErrorAction SilentlyContinue)) {
                $name = "$($v.Name)".ToLower()
                if ($name -and $pathKey.StartsWith($name) -and
                    ((-not $w32) -or $name.Length -gt "$($w32.Name)".Length)) {
                    $w32 = $v
                }
            }
            if ($w32) {
                $info.Key          = "$($w32.DeviceID)"
                $info.Label        = "$($w32.Label)"
                $info.FileSystem   = "$($w32.FileSystem)"
                $info.VolumeSize   = [long]$w32.Capacity
                $info.ClusterSize  = "$($w32.BlockSize)"
                $info.VolumeSerial = '{0:X8}' -f [long]$w32.SerialNumber
            }
            else {
                $info.Note = 'Volume not identified. '
            }
            # Fail-safe: skip the stream check only on file systems known to have no streams.
            $info.StreamsSupported = -not ($info.FileSystem -in @('FAT', 'FAT32', 'exFAT', 'CDFS', 'UDF'))

            # Disk details: Storage module (may be unavailable, e.g. in Constrained Language Mode).
            try {
                $vol  = Get-Volume -FilePath $LiteralPath -ErrorAction Stop
                $part = $vol | Get-Partition -ErrorAction SilentlyContinue | Select-Object -First 1
                $disk = if ($part) { $part | Get-Disk -ErrorAction SilentlyContinue }
                if ($disk) {
                    $info.DiskNumber     = "$($disk.Number)"
                    $info.DiskModel      = "$($disk.FriendlyName)"
                    $info.DiskSerial     = "$($disk.SerialNumber)".Trim()
                    $info.BusType        = "$($disk.BusType)"
                    $info.DiskSize       = [long]$disk.Size
                    $info.PartitionStyle = "$($disk.PartitionStyle)"
                    $parts = @(Get-Partition -DiskNumber $disk.Number -ErrorAction SilentlyContinue)
                    $used  = [long]0
                    foreach ($p in $parts) { $used += [long]$p.Size }
                    $info.Partitions       = "$($parts.Count)"
                    $info.UnallocatedBytes = "$($info.DiskSize - $used)"
                }
                else {
                    $info.Note += 'Disk details unavailable.'
                }
                if (-not $info.DiskSerial) { $info.DiskSerial = '(none reported)' }
            }
            catch {
                $info.Note += "Disk details unavailable: $(Get-ErrorReason -ErrorRecord $_)"
            }
            New-Object -TypeName PSObject -Property $info
        }

        function Get-TreeItem {
            <#
            .SYNOPSIS
                Recursively emits the children of a folder; never descends into reparse points (links, mounts).
            #>
            param(
                [Parameter(Mandatory = $true)][string]$LiteralPath,
                [switch]$Recurse
            )
            $enumErrors = $null
            $children   = @(Get-ChildItem -LiteralPath $LiteralPath -Force `
                    -ErrorAction SilentlyContinue -ErrorVariable enumErrors)
            foreach ($e in $enumErrors) {
                $state.Errors++
                Write-Log "Enumeration error in ${LiteralPath}: $(Get-ErrorReason -ErrorRecord $e)" -Level WARN
            }
            foreach ($child in $children) {
                $isLink = ("$($child.Attributes)" -match 'ReparsePoint')
                if ($isLink) { $state.Links++ }
                elseif ($child.PSIsContainer) { $state.Folders++ }
                else {
                    $state.Files++
                    $state.Bytes += [long]$child.Length
                }

                $now = Get-Date
                if (($now - $state.LastProgress).TotalMilliseconds -ge $ProgressIntervalMs) {
                    Write-Progress -Id 1 -Activity 'Enumerating items' `
                        -Status ('{0} files, {1} folders, {2} links, {3}' -f `
                            $state.Files, $state.Folders, $state.Links, (Format-Size -Bytes $state.Bytes)) `
                        -CurrentOperation $child.FullName
                    $state.LastProgress = $now
                }

                $child
                if ($Recurse -and $child.PSIsContainer -and -not $isLink) {
                    Get-TreeItem -LiteralPath $child.FullName -Recurse
                }
            }
        }

        # Make sure the output folders exist before the first log line.
        if ($logToFile) {
            foreach ($file in @($LogPath, $OutputPath, $HtmlPath)) {
                $dir = Split-Path -Path $file -Parent
                if ($dir -and -not (Test-Path -LiteralPath $dir)) {
                    New-Item -ItemType Directory -Path $dir -Force -WhatIf:$false -Confirm:$false | Out-Null
                }
            }
        }

        $scriptFile = "$($MyInvocation.MyCommand.ScriptBlock.File)"
        $scriptHash = ''
        if ($scriptFile) { $scriptHash = (Get-FileHash -LiteralPath $scriptFile -Algorithm SHA256).Hash }

        Write-Log ('Get-MediaForensic started. PowerShell {0} ({1}), language mode: {2}' -f `
                $PSVersionTable.PSVersion, $PSVersionTable.PSEdition, $languageMode)
        if (-not $fullLanguage) {
            Write-Log 'Constrained language: -WhatIf is honored, -Confirm is not supported.' -Level WARN
        }
        Write-Log "Script     : $scriptFile (SHA-256 $scriptHash)"
        Write-Log "Operator   : $($env:USERDOMAIN)\$($env:USERNAME) on $($env:COMPUTERNAME)"
        Write-Log ('Parameters : NoRecurse={0}, StreamsOnly={1}, LargeStreamThresholdBytes={2}, KnownStreams={3}' -f `
                $NoRecurse.IsPresent, $StreamsOnly.IsPresent, $LargeStreamThresholdBytes, ($KnownStreams -join ','))
        Write-Log "Output CSV : $OutputPath"
        Write-Log "HTML report: $HtmlPath"
        if ($logToFile) { Write-Log "Log file   : $LogPath" }
        else { Write-Log 'Log file   : disabled (-WhatIf)' -Level DEBUG }

        $baselineRows = @()
        if ($Baseline) {
            if (-not (Test-Path -LiteralPath $Baseline -PathType Leaf)) {
                Write-Log "Baseline not found: $Baseline" -Level ERROR
                $fatal = $true
            }
            else {
                $baselineRows = @(Import-Csv -LiteralPath $Baseline -Delimiter $CsvDelimiter)
                $columns      = @($baselineRows | Select-Object -First 1 |
                        ForEach-Object { $_.PSObject.Properties.Name })
                if (-not ($columns -contains 'RelativePath' -and $columns -contains 'Type')) {
                    Write-Log "Not a Get-MediaForensic CSV (delimiter '$CsvDelimiter'?): $Baseline" -Level ERROR
                    $fatal = $true
                }
                else {
                    $baselineHash = (Get-FileHash -LiteralPath $Baseline -Algorithm SHA256).Hash
                    Write-Log "Baseline   : $Baseline ($($baselineRows.Count) rows, SHA-256 $baselineHash)"
                }
            }
        }
    }

    PROCESS {
        if ($fatal) { return }

        foreach ($inputPath in $Path) {
            if (-not (Test-Path -LiteralPath $inputPath)) {
                Write-Log "Path not found: $inputPath" -Level ERROR
                $state.Errors++
                continue
            }
            if (-not (Test-ShouldProcess -Target $inputPath -Action 'Enumerate and read (hash) items')) {
                continue
            }

            $top = Get-Item -LiteralPath $inputPath -Force
            if ($top.PSIsContainer) {
                $root  = $top.FullName.TrimEnd('\')
                $items = @($top) + @(Get-TreeItem -LiteralPath $top.FullName -Recurse:(-not $NoRecurse))
            }
            else {
                $root  = (Split-Path -Path $top.FullName -Parent).TrimEnd('\')
                $items = @($top)
                $state.Files++
                $state.Bytes += [long]$top.Length
            }
            Write-Progress -Id 1 -Activity 'Enumerating items' -Completed

            # Volume details once per volume (folder mount points resolve to their own volume).
            $vol = Get-VolumeInfo -LiteralPath $top.FullName
            if (-not $volumes.ContainsKey($vol.Key)) {
                $volumes[$vol.Key] = $vol
                $unallocated = [long]("0$($vol.UnallocatedBytes)")
                if ($vol.DiskModel) {
                    Write-Log ('Device     : {0}, S/N {1}, {2}, {3}' -f `
                            $vol.DiskModel, $vol.DiskSerial, $vol.BusType, (Format-Size -Bytes $vol.DiskSize))
                }
                else { Write-Log 'Device     : unavailable' -Level WARN }
                Write-Log ('Volume     : {0} [{1}] {2}, cluster {3} B, serial {4}' -f `
                        $root, $vol.Label, $vol.FileSystem, $vol.ClusterSize, $vol.VolumeSerial)
                Write-Log ('Partitions : {0}, unallocated {1}' -f $vol.Partitions, (Format-Size -Bytes $unallocated))
                if ($vol.Note) { Write-Log "Volume note: $($vol.Note)" -Level WARN }
                if (-not $vol.StreamsSupported) {
                    Write-Log "No alternate streams on $($vol.FileSystem): stream check skipped." -Level WARN
                }
                if ($unallocated -gt $UnallocatedThresholdBytes) {
                    $unallocText = Format-Size -Bytes $unallocated
                    Write-Log "Review: $unallocText of unpartitioned space on the disk" -Level WARN
                }
            }

            # One += per input path (collecting inside a loop with += would be quadratic).
            $work += @(foreach ($item in $items) {
                    New-Object -TypeName PSObject -Property ([ordered]@{
                            Item    = $item
                            Root    = $root
                            Streams = $vol.StreamsSupported
                            IsLink  = ("$($item.Attributes)" -match 'ReparsePoint')
                        })
                })
            Write-Log "Enumerated : $inputPath ($($items.Count) items)"
        }
    }

    END {
        if ($fatal) {
            Write-Log 'Stopped: fatal error, nothing scanned.' -Level ERROR
            return
        }

        # ---------------- Phase 2: hash and classify ----------------
        $totalItems  = $work.Count
        $totalBytes  = if ($StreamsOnly) { [long]0 } else { $state.Bytes }
        $doneBytes   = [long]0
        $findings    = 0
        $phaseStart  = Get-Date
        $lastUpdate  = $phaseStart.AddDays(-1)
        $i           = 0
        $activity    = if ($StreamsOnly) { 'Searching alternate streams' } else { 'Hashing items and streams' }

        $rows = @(foreach ($w in $work) {
                $i++
                $item = $w.Item

                # Throttled progress: by bytes when hashing content, by items in -StreamsOnly mode.
                $now = Get-Date
                if ((($now - $lastUpdate).TotalMilliseconds -ge $ProgressIntervalMs) -or ($i -eq $totalItems)) {
                    $elapsed = ($now - $phaseStart).TotalSeconds
                    if ($totalBytes -gt 0) {
                        $ratio  = [double]$doneBytes / $totalBytes
                        $status = '{0} / {1} items, {2} / {3}, findings: {4}, errors: {5}' -f `
                            $i, $totalItems, (Format-Size -Bytes $doneBytes), (Format-Size -Bytes $totalBytes), `
                            $findings, $state.Errors
                    }
                    else {
                        $ratio  = [double]$i / $totalItems
                        $status = '{0} / {1} items, findings: {2}, errors: {3}' -f `
                            $i, $totalItems, $findings, $state.Errors
                    }
                    $remain   = if ($ratio -gt 0) { [int](($elapsed / $ratio) - $elapsed) } else { -1 }
                    $percent  = [int]($ratio * 100)
                    if ($percent -gt 100) { $percent = 100 }
                    $sizeText = if ($item.PSIsContainer) { 'folder' } else { Format-Size -Bytes $item.Length }
                    Write-Progress -Id 2 -Activity $activity -Status $status `
                        -CurrentOperation "$($item.FullName) ($sizeText)" `
                        -PercentComplete $percent -SecondsRemaining $remain
                    $lastUpdate = $now
                }

                $relative = $item.FullName.Substring($w.Root.Length)
                if (-not $relative) { $relative = '\' }
                $attrs  = "$($item.Attributes)"
                $common = @{
                    Root             = $w.Root
                    RelativePath     = $relative
                    Attributes       = $attrs
                    CreationTimeUtc  = '{0:yyyy-MM-ddTHH:mm:ss.fffZ}' -f $item.CreationTimeUtc
                    LastWriteTimeUtc = '{0:yyyy-MM-ddTHH:mm:ss.fffZ}' -f $item.LastWriteTimeUtc
                }

                # ---- Main row: file, folder or link ----
                $main = $common.Clone()
                if ($w.IsLink) {
                    $target            = "$($item.LinkTarget)"
                    $main.Type         = 'Link'
                    $main.LinkTarget   = $target
                    $main.Verdict      = 'Review'
                    $main.Reason       = "Reparse point (link/mount) to '$target'; not followed"
                }
                elseif ($item.PSIsContainer) {
                    $main.Type = 'Dir'
                }
                else {
                    $main.Type = 'File'
                    $main.Size = "$($item.Length)"
                    if (-not $StreamsOnly) {
                        try {
                            $main.SHA256 = (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256 `
                                    -ErrorAction Stop).Hash
                        }
                        catch {
                            $state.Errors++
                            $main.Verdict = 'Review'
                            $main.Reason  = "Hash failed: $(Get-ErrorReason -ErrorRecord $_)"
                            Write-Log "$($item.FullName): $($main.Reason)" -Level WARN
                        }
                        $doneBytes += [long]$item.Length
                    }
                }
                if ((-not $main.Reason) -and ($attrs -match 'Hidden|System')) {
                    $main.Verdict = 'Info'
                    $main.Reason  = 'Hidden or system attribute'
                }
                if ($main.Verdict -ne 'None') { $findings++ }
                ConvertTo-ReportRow -Values $main

                # ---- Alternate data streams (NTFS/ReFS only; files and folders) ----
                if (-not $w.Streams) { continue }
                $streamErrors = $null
                $streams = @(Get-Item -LiteralPath $item.FullName -Stream * -Force `
                        -ErrorAction SilentlyContinue -ErrorVariable streamErrors |
                        Where-Object { $_.Stream -ne ':$DATA' })
                foreach ($e in $streamErrors) {
                    $state.Errors++
                    $reason = Get-ErrorReason -ErrorRecord $e
                    Write-Log "$($item.FullName): stream enumeration failed: $reason" -Level WARN
                }

                foreach ($s in $streams) {
                    $row        = $common.Clone()
                    $row.Type   = 'Stream'
                    $row.Stream = $s.Stream
                    $row.Size   = "$($s.Length)"
                    $row.Attributes       = ''
                    $row.CreationTimeUtc  = ''
                    $row.LastWriteTimeUtc = ''
                    try {
                        $row.SHA256 = (Get-FileHash -LiteralPath "$($item.FullName):$($s.Stream)" `
                                -Algorithm SHA256 -ErrorAction Stop).Hash
                    }
                    catch {
                        $state.Errors++
                        $row.Reason = "Stream hash failed: $(Get-ErrorReason -ErrorRecord $_). "
                    }

                    # Classification: scanner-rules\ads.md and scanner-rules\motw.md.
                    if ($s.Stream -eq 'Zone.Identifier') {
                        $text = ''
                        if ($s.Length -le 4096) {
                            $text = Get-Content -LiteralPath $item.FullName -Stream Zone.Identifier -Raw `
                                -ErrorAction SilentlyContinue
                        }
                        if ("$text" -match '(?im)^\s*ZoneId\s*=\s*(\d+)') { $row.ZoneId = $Matches[1] }
                        if ("$text" -match '(?im)^\s*HostUrl\s*=\s*[a-z][a-z0-9+.\-]*://([^/\s:?#]+)') {
                            $row.HostDomain = $Matches[1]
                        }
                        if ("$text" -match '(?i)^\s*\[ZoneTransfer\]') {
                            $row.Verdict = 'Info'
                            $row.Reason += "Mark of the Web, ZoneId=$($row.ZoneId)"
                            if ($row.HostDomain) { $row.Reason += ", host $($row.HostDomain)" }
                        }
                        else {
                            $row.Verdict = 'Review'
                            $row.Reason += 'Zone.Identifier with unexpected format or size'
                        }
                    }
                    elseif ([long]$s.Length -gt $LargeStreamThresholdBytes) {
                        $row.Verdict = 'Alert'
                        $limitText   = Format-Size -Bytes $LargeStreamThresholdBytes
                        $row.Reason += "Stream $(Format-Size -Bytes $s.Length) > threshold $limitText"
                    }
                    elseif ($item.PSIsContainer) {
                        $row.Verdict = 'Review'
                        $row.Reason += 'Stream on a folder'
                    }
                    elseif ($KnownStreams -contains $s.Stream) {
                        $row.Verdict = 'Info'
                        $row.Reason += 'Known stream name'
                    }
                    else {
                        $row.Verdict = 'Review'
                        $row.Reason += 'Unknown stream name'
                    }
                    $findings++
                    if ($row.Verdict -ne 'Info') {
                        Write-Log "$($row.Verdict): $($item.FullName):$($s.Stream) - $($row.Reason)" -Level WARN
                    }
                    ConvertTo-ReportRow -Values $row
                }
            })
        Write-Progress -Id 2 -Activity $activity -Completed

        # ---------------- Phase 3: compare with baseline ----------------
        $changeCount = @{ Added = 0; Removed = 0; Changed = 0; Unchanged = 0 }
        if ($Baseline) {
            $old = @{}
            foreach ($r in $baselineRows) { $old["$($r.Type)|$($r.RelativePath)|$($r.Stream)"] = $r }
            foreach ($r in $rows) {
                $key = "$($r.Type)|$($r.RelativePath)|$($r.Stream)"
                if (-not $old.ContainsKey($key)) {
                    $r.Change = 'Added'
                }
                else {
                    $o    = $old[$key]
                    $diff = @()
                    foreach ($field in @('Size', 'SHA256', 'Attributes', 'LastWriteTimeUtc', 'LinkTarget')) {
                        # Compare only when both snapshots have the value (e.g. -StreamsOnly has no content hash).
                        if ("$($r.$field)" -and "$($o.$field)" -and ("$($r.$field)" -ne "$($o.$field)")) {
                            $diff += $field
                        }
                    }
                    if ($diff.Count) {
                        $r.Change       = 'Changed'
                        $r.ChangeDetail = $diff -join ', '
                    }
                    else { $r.Change = 'Unchanged' }
                    $old.Remove($key)
                }
                $changeCount[$r.Change]++
            }
            $removed = @(foreach ($o in $old.Values) {
                    $values = @{}
                    foreach ($p in $o.PSObject.Properties) { $values[$p.Name] = "$($p.Value)" }
                    $values.Change       = 'Removed'
                    $values.ChangeDetail = ''
                    ConvertTo-ReportRow -Values $values
                })
            $changeCount.Removed = $removed.Count
            $rows += $removed
            foreach ($r in $rows) {
                if ($r.Change -in @('Added', 'Removed', 'Changed')) {
                    Write-Log "$($r.Change): $($r.Type) $($r.RelativePath) $($r.Stream) $($r.ChangeDetail)" -Level WARN
                }
            }
        }

        # ---------------- Phase 4: reports ----------------
        $csvHash = ''
        $exportAction = "Export $($rows.Count) rows to CSV"
        if ($rows.Count -gt 0 -and (Test-ShouldProcess -Target $OutputPath -Action $exportAction)) {
            $rows | Export-Csv -LiteralPath $OutputPath -NoTypeInformation -Encoding utf8BOM `
                -Delimiter $CsvDelimiter -WhatIf:$false -Confirm:$false
            $csvHash = (Get-FileHash -LiteralPath $OutputPath -Algorithm SHA256).Hash
            Write-Log "CSV written: $OutputPath" -Level OK
        }

        $count = @{}
        foreach ($v in @('Alert', 'Review', 'Info')) {
            $count[$v] = @($rows | Where-Object { $_.Verdict -eq $v }).Count
        }
        $streamRows = @($rows | Where-Object { $_.Type -eq 'Stream' })
        $motwCount  = @($streamRows | Where-Object { $_.Stream -eq 'Zone.Identifier' }).Count
        $duration   = (Get-Date) - $startTime

        if ($rows.Count -gt 0 -and (Test-ShouldProcess -Target $HtmlPath -Action 'Write HTML report')) {
            $css = @'
<style>
body { font-family: Segoe UI, Arial, sans-serif; margin: 24px; color: #1f2328; }
h1 { font-size: 22px; margin-bottom: 4px; } h2 { font-size: 17px; margin-top: 28px; }
table { border-collapse: collapse; margin-top: 8px; font-size: 13px; }
th, td { border: 1px solid #d0d7de; padding: 4px 8px; text-align: left; vertical-align: top; }
th { background: #f6f8fa; }
td.alert { background: #ffebe9; font-weight: 600; } td.review { background: #fff8c5; }
td.info { background: #ddf4ff; } .muted { color: #656d76; font-size: 12px; }
</style>
'@
            $modeText     = if ($StreamsOnly) { 'Streams only (content not hashed)' } else { 'Full' }
            $baselineText = if ($Baseline) { "$Baseline (SHA-256 $baselineHash)" } else { '-' }
            $changesText  = '-'
            if ($Baseline) {
                $changesText = 'added {0}, removed {1}, changed {2}, unchanged {3}' -f `
                    $changeCount.Added, $changeCount.Removed, $changeCount.Changed, $changeCount.Unchanged
            }
            $meta = New-Object -TypeName PSObject -Property ([ordered]@{
                    'Generated (UTC)' = '{0:yyyy-MM-dd HH:mm:ss}' -f (Get-Date).ToUniversalTime()
                    'Operator'        = "$($env:USERDOMAIN)\$($env:USERNAME)"
                    'Computer'        = $env:COMPUTERNAME
                    'PowerShell'      = "$($PSVersionTable.PSVersion) ($languageMode)"
                    'Script'          = $scriptFile
                    'Script SHA-256'  = $scriptHash
                    'Input paths'     = ($Path -join '; ')
                    'Mode'            = $modeText
                    'CSV'             = $OutputPath
                    'CSV SHA-256'     = $csvHash
                    'Baseline'        = $baselineText
                })
            $summary = New-Object -TypeName PSObject -Property ([ordered]@{
                    'Files'                 = $state.Files
                    'Folders'               = $state.Folders
                    'Links (not followed)'  = $state.Links
                    'Content size'          = Format-Size -Bytes $state.Bytes
                    'Alternate streams'     = "$($streamRows.Count) (Zone.Identifier: $motwCount)"
                    'Alert / Review / Info' = '{0} / {1} / {2}' -f $count.Alert, $count.Review, $count.Info
                    'Errors'                = $state.Errors
                    'Changes vs baseline'   = $changesText
                    'Duration'              = '{0:hh\:mm\:ss}' -f $duration
                })
            $order    = @{ Alert = 0; Review = 1; Info = 2 }
            $findRows = @($rows | Where-Object { $_.Verdict -ne 'None' } |
                    Sort-Object -Property @{ Expression = { $order[$_.Verdict] } }, RelativePath, Stream)
            $diffRows = @($rows | Where-Object { $_.Change -in @('Added', 'Removed', 'Changed') })
            $diskSize = @{ n = 'DiskSize'; e = { Format-Size -Bytes $_.DiskSize } }
            $unalloc  = @{ n = 'Unallocated'; e = { Format-Size -Bytes ([long]("0$($_.UnallocatedBytes)")) } }
            $volCols  = @('Label', 'FileSystem', 'ClusterSize', 'VolumeSerial', 'DiskModel', 'DiskSerial', 'BusType',
                $diskSize, 'PartitionStyle', 'Partitions', $unalloc, 'StreamsSupported', 'Note')
            $volRows  = @($volumes.Values | Select-Object -Property $volCols)
            $findCols = @('Verdict', 'Type', 'RelativePath', 'Stream', 'Size', 'ZoneId', 'HostDomain', 'Reason')

            $body = @(
                '<h1>Media forensic report</h1>'
                '<p class="muted">Read-only snapshot. Verdicts: Alert &gt; Review &gt; Info. ' +
                'Links are recorded, never followed.</p>'
                '<h2>Report</h2>'
                ($meta | ConvertTo-Html -As List -Fragment)
                '<h2>Device and volume</h2>'
                ($volRows | ConvertTo-Html -Fragment)
                '<h2>Summary</h2>'
                ($summary | ConvertTo-Html -As List -Fragment)
                "<h2>Findings ($($findRows.Count))</h2>"
                $(if ($findRows.Count) {
                        $findRows | Select-Object -Property $findCols | ConvertTo-Html -Fragment
                    }
                    else { '<p>No findings.</p>' })
            )
            if ($Baseline) {
                $body += "<h2>Changes vs baseline ($($diffRows.Count))</h2>"
                $body += if ($diffRows.Count) {
                    $diffRows | Select-Object Change, ChangeDetail, Type, RelativePath, Stream, Size, SHA256 |
                        ConvertTo-Html -Fragment
                }
                else { '<p>No changes.</p>' }
            }
            $html = ConvertTo-Html -Title 'Media forensic report' -Head $css -Body ($body -join "`n") | Out-String
            $html = $html -replace '<td>Alert</td>', '<td class="alert">Alert</td>' `
                -replace '<td>Review</td>', '<td class="review">Review</td>' `
                -replace '<td>Info</td>', '<td class="info">Info</td>'
            Set-Content -LiteralPath $HtmlPath -Value $html -Encoding utf8 -WhatIf:$false -Confirm:$false
            Write-Log "HTML written: $HtmlPath" -Level OK
        }

        # ---------------- Console summary ----------------
        Write-Log '---------------- Summary ----------------'
        Write-Log ('Items      : {0} files, {1} folders, {2} links (not followed), {3}' -f `
                $state.Files, $state.Folders, $state.Links, (Format-Size -Bytes $state.Bytes))
        $otherStreams = $streamRows.Count - $motwCount
        Write-Log "Streams    : $($streamRows.Count) (Zone.Identifier: $motwCount, other: $otherStreams)" `
            -Level $(if ($otherStreams) { 'WARN' } else { 'INFO' })
        Write-Log ('Verdicts   : Alert {0}, Review {1}, Info {2}' -f $count.Alert, $count.Review, $count.Info) `
            -Level $(if ($count.Alert) { 'ERROR' } elseif ($count.Review) { 'WARN' } else { 'INFO' })
        if ($Baseline) {
            $changed = $changeCount.Added + $changeCount.Removed + $changeCount.Changed
            Write-Log ('Changes    : added {0}, removed {1}, changed {2}, unchanged {3}' -f `
                    $changeCount.Added, $changeCount.Removed, $changeCount.Changed, $changeCount.Unchanged) `
                -Level $(if ($changed) { 'WARN' } else { 'OK' })
        }
        Write-Log "Errors     : $($state.Errors)" -Level $(if ($state.Errors) { 'ERROR' } else { 'INFO' })
        Write-Log ('Duration   : {0:hh\:mm\:ss\.fff}' -f $duration)
        if ($csvHash) { Write-Log "CSV SHA-256: $csvHash (store it separately to detect report tampering)" -Level OK }

        if ($PassThru) { $rows }
    }
}
