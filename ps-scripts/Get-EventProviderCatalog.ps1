function Get-EventProviderCatalog {
    <#
    .SYNOPSIS
        Exports the event catalog of Windows event providers (every EventID the
        provider can write, with its message template, level, task, opcode,
        keywords and channel) to a flat CSV - one row per (Provider, EventID,
        Version).

    .DESCRIPTION
        "Get-WinEvent -ListProvider *" returns ProviderMetadata objects whose
        interesting parts (Events, Tasks, Opcodes, LogLinks, ...) are nested
        collections, printed on screen as "{...}" and unusable for analysis.
        This function reads the same metadata through the underlying .NET
        class System.Diagnostics.Eventing.Reader.ProviderMetadata, expands the
        Events collection, and writes a flat CSV.

        The message template is requested in the culture given by -Culture
        (en-US by default). If the language resources for that culture are
        not installed on the machine, Windows silently returns the text in the
        system UI language (e.g. Russian) - this is a property of the OS, not
        of the script. Run it on a machine with the English UI / en-US
        language pack if English texts are required.

        LIMITATION: classic ("legacy") event sources that use a message table
        instead of an instrumentation manifest (e.g. MsiInstaller, ESENT,
        EventLog, many third-party services) expose NO event list through this
        API - their Events collection is empty. For such providers one row with
        an empty EventID and HasEvents = False is written (unless
        -SkipProvidersWithoutEvents), together with MessageFilePath, so the
        message DLL can be identified.

        The function does NOT emit objects to the pipeline: it writes the CSV
        and prints a short run summary. To get the data back as objects in the
        same session use Import-Csv on the printed path.

    .PARAMETER ProviderName
        One or more provider names or wildcard patterns. Accepts pipeline input.
        Default '*' = every provider registered on the machine.

    .PARAMETER Culture
        Culture in which message templates and display names are requested.
        Default 'en-US'. Falls back to the system UI language if resources for
        this culture are not installed.

    .PARAMETER MaxTextLength
        Maximum length of the Description and Template columns (longer text is
        truncated with '...'). Default 4000 - long enough for the biggest
        Security-audit templates, short enough to keep the CSV usable in Excel
        (Excel's cell limit is 32767 characters).

    .PARAMETER SkipProvidersWithoutEvents
        Do not write the placeholder row for providers that expose no events
        (legacy message-table sources and providers whose metadata could not
        be read).

    .PARAMETER OutputCsv
        Path of the resulting CSV. Defaults to a timestamped file named after
        the computer, in the current directory.

    .EXAMPLE
        . .\Export-EventProviderCatalog.ps1
        Export-EventProviderCatalog
        Full catalog of every provider on the machine, English templates where
        available.

    .EXAMPLE
        Export-EventProviderCatalog -ProviderName 'Microsoft-Windows-TaskScheduler','Microsoft-Windows-Security-*' -OutputCsv .\catalog_security.csv
        Only the listed providers / patterns.

    .EXAMPLE
        Import-Csv .\EventIdInventory_COMP1.csv | Select-Object -ExpandProperty Provider -Unique | Export-EventProviderCatalog
        Only the providers that actually appear in an inventory CSV
        (pipeline input).

    .EXAMPLE
        Export-EventProviderCatalog -WhatIf
        Shows which providers would be read and where the CSV would be written.

    .NOTES
        Version: 1.0
        Author : M. Zaikin
        Date   : 28-Sep-2026

        v1.0 - initial version. Purpose: obtain the official message template
        of every EventID found by Get-EventIdInventory, including providers not
        documented anywhere on the web, as input for the EventID interpretation
        work in the MaxPatrol SIEM project.

        Columns:
          Provider, ProviderGuid, HasEvents, EventId (short, 0-65535),
          EventIdRaw (full 32-bit value incl. qualifiers), Qualifiers, Version,
          LogName, Level, LevelValue, Task, TaskValue, Opcode, OpcodeValue,
          Keywords, KeywordsValue (hex), Description (message template,
          newlines flattened to " | "), Template (XML list of event fields),
          ProviderLogLinks, MessageFilePath, ResourceFilePath, ReadError.

        WHICH ACCOUNT TO RUN THIS AS: a normal user can read the metadata of
        almost all providers. A few providers (e.g. Security-Auditing on some
        builds) require local administrator rights - they will be reported in
        ReadError / in the ERROR lines of the console, the run continues.
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Low')]
    param(
        [Parameter(ValueFromPipeline = $true)]
        [string[]]$ProviderName = '*',

        [string]$Culture = 'en-US',

        [int]$MaxTextLength = 4000,

        [switch]$SkipProvidersWithoutEvents,

        [string]$OutputCsv = ".\EventProviderCatalog_$($env:COMPUTERNAME)_$(Get-Date -Format yyyyMMdd_HHmmss).csv"
    )

    BEGIN {
        $ErrorActionPreference = 'Stop'
        $ScriptStartTime  = Get-Date
        $Utf8BomEncoding  = [System.Text.UTF8Encoding]::new($true)
        $Session          = [System.Diagnostics.Eventing.Reader.EventLogSession]::GlobalSession
        $TargetCulture    = [System.Globalization.CultureInfo]::GetCultureInfo($Culture)
        $rows             = New-Object System.Collections.Generic.List[object]
        $errors           = New-Object System.Collections.Generic.List[string]
        $seen             = New-Object System.Collections.Generic.HashSet[string]
        $providersOk      = 0
        $providersTried   = 0

        function Write-Info {
            param(
                [Parameter(Mandatory)][string]$Message,
                [ValidateSet('INFO', 'WARN', 'ERROR')][string]$Level = 'INFO'
            )
            $line = "[{0}] [{1}] {2}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
            switch ($Level) {
                'WARN'  { Write-Host $line -ForegroundColor Yellow }
                'ERROR' { Write-Host $line -ForegroundColor Red }
                default { Write-Host $line -ForegroundColor Gray }
            }
        }

        function Get-Safe {
            # A provider with broken/missing resources can throw on ANY display
            # property - one such property must not kill the whole provider.
            param([Parameter(Mandatory)][scriptblock]$Getter)
            try { & $Getter } catch { $null }
        }

        function Format-Text {
            param([string]$Text)
            if ([string]::IsNullOrEmpty($Text)) { return $null }
            $t = ($Text -replace "(`r`n|`r|`n)", ' | ') -replace "`t", ' '
            $t = ($t -replace '\s{2,}', ' ').Trim()
            if ($t.Length -gt $MaxTextLength) { $t = $t.Substring(0, $MaxTextLength) + '...' }
            return $t
        }

        # Every registered provider name - used to expand wildcards.
        Write-Info "Enumerating registered event providers..."
        $AllProviderNames = @($Session.GetProviderNames() | Sort-Object)
        Write-Info ("Found {0} registered provider(s). Requested culture: {1}" -f $AllProviderNames.Count, $TargetCulture.Name)
    }

    PROCESS {
        # Resolve names/patterns from this PROCESS call to concrete provider names.
        $targets = foreach ($p in $ProviderName) {
            if ([string]::IsNullOrWhiteSpace($p)) { continue }
            if ([System.Management.Automation.WildcardPattern]::ContainsWildcardCharacters($p)) {
                $AllProviderNames | Where-Object { $_ -like $p }
            } else {
                $p
            }
        }

        $total = @($targets).Count
        $i = 0
        foreach ($name in $targets) {
            $i++
            if (-not $seen.Add($name)) { continue }   # duplicates from overlapping patterns / pipeline
            if (-not $PSCmdlet.ShouldProcess($name, 'Read provider metadata')) { continue }

            $providersTried++
            if ($total -gt 0) {
                Write-Progress -Activity 'Reading provider metadata' -Status "$name ($i of $total)" -PercentComplete ([Math]::Min(100, $i / $total * 100)) -Id 1
            }

            $md = $null
            try {
                $md = [System.Diagnostics.Eventing.Reader.ProviderMetadata]::new($name, $Session, $TargetCulture)
            } catch {
                $msg = "Provider '$name': $($_.Exception.Message)"
                $errors.Add($msg)
                Write-Info $msg -Level ERROR
                if (-not $SkipProvidersWithoutEvents) {
                    $rows.Add([pscustomobject]@{
                        Provider = $name; ProviderGuid = $null; HasEvents = $false
                        EventId = $null; EventIdRaw = $null; Qualifiers = $null; Version = $null
                        LogName = $null; Level = $null; LevelValue = $null; Task = $null; TaskValue = $null
                        Opcode = $null; OpcodeValue = $null; Keywords = $null; KeywordsValue = $null
                        Description = $null; Template = $null; ProviderLogLinks = $null
                        MessageFilePath = $null; ResourceFilePath = $null; ReadError = $_.Exception.Message
                    })
                }
                continue
            }

            try {
                $guid        = Get-Safe { $md.Id }
                $logLinks    = Get-Safe { ($md.LogLinks | ForEach-Object { $_.LogName }) -join '; ' }
                $msgFile     = Get-Safe { $md.MessageFilePath }
                $resFile     = Get-Safe { $md.ResourceFilePath }

                $events = $null
                $eventsError = $null
                try { $events = @($md.Events) } catch { $eventsError = $_.Exception.Message }

                if (-not $events -or $events.Count -eq 0) {
                    if (-not $SkipProvidersWithoutEvents) {
                        $rows.Add([pscustomobject]@{
                            Provider = $name; ProviderGuid = $guid; HasEvents = $false
                            EventId = $null; EventIdRaw = $null; Qualifiers = $null; Version = $null
                            LogName = $null; Level = $null; LevelValue = $null; Task = $null; TaskValue = $null
                            Opcode = $null; OpcodeValue = $null; Keywords = $null; KeywordsValue = $null
                            Description = $null; Template = $null; ProviderLogLinks = $logLinks
                            MessageFilePath = $msgFile; ResourceFilePath = $resFile; ReadError = $eventsError
                        })
                    }
                    if ($eventsError) {
                        $errors.Add("Provider '$name' events: $eventsError")
                        Write-Info "Provider '$name': cannot enumerate events: $eventsError" -Level WARN
                    }
                    $providersOk++
                    continue
                }

                foreach ($e in $events) {
                    $rawId = [int64](Get-Safe { $e.Id })
                    $kwNames = Get-Safe { ($e.Keywords | ForEach-Object { $_.DisplayName } | Where-Object { $_ }) -join '; ' }
                    $kwValue = Get-Safe { $v = [int64]0; foreach ($k in $e.Keywords) { $v = $v -bor $k.Value }; '0x{0:X16}' -f $v }

                    $rows.Add([pscustomobject]@{
                        Provider         = $name
                        ProviderGuid     = $guid
                        HasEvents        = $true
                        EventId          = $rawId -band 0xFFFF
                        EventIdRaw       = $rawId
                        Qualifiers       = ($rawId -shr 16) -band 0xFFFF
                        Version          = Get-Safe { $e.Version }
                        LogName          = Get-Safe { $e.LogLink.LogName }
                        Level            = Get-Safe { $e.Level.DisplayName }
                        LevelValue       = Get-Safe { $e.Level.Value }
                        Task             = Get-Safe { $e.Task.DisplayName }
                        TaskValue        = Get-Safe { $e.Task.Value }
                        Opcode           = Get-Safe { $e.Opcode.DisplayName }
                        OpcodeValue      = Get-Safe { $e.Opcode.Value }
                        Keywords         = $kwNames
                        KeywordsValue    = $kwValue
                        Description      = Format-Text (Get-Safe { $e.Description })
                        Template         = Format-Text (Get-Safe { $e.Template })
                        ProviderLogLinks = $logLinks
                        MessageFilePath  = $msgFile
                        ResourceFilePath = $resFile
                        ReadError        = $null
                    })
                }
                $providersOk++
            } finally {
                $md.Dispose()
            }
        }
    }

    END {
        Write-Progress -Activity 'Reading provider metadata' -Completed -Id 1

        $resolvedCsvPath = $PSCmdlet.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputCsv)
        $csvWritten = $false
        if ($PSCmdlet.ShouldProcess($resolvedCsvPath, 'Export provider catalog to CSV')) {
            $sorted   = $rows | Sort-Object Provider, @{ Expression = { [int64]$_.EventId } }, Version
            $csvLines = $sorted | ConvertTo-Csv -NoTypeInformation
            [System.IO.File]::WriteAllLines($resolvedCsvPath, $csvLines, $Utf8BomEncoding)
            $csvWritten = $true
        }

        $withEvents    = @($rows | Where-Object HasEvents).Count
        $withoutEvents = @($rows | Where-Object { -not $_.HasEvents }).Count
        $ScriptEndTime = Get-Date
        $duration      = New-TimeSpan -Start $ScriptStartTime -End $ScriptEndTime
        $csvStatus     = if ($csvWritten) { $resolvedCsvPath } else { "$resolvedCsvPath (WhatIf - not written)" }

        Write-Host ""
        Write-Host "==================== Run summary ====================" -ForegroundColor Cyan
        Write-Host ("Start time            : {0}" -f $ScriptStartTime.ToString('yyyy-MM-dd HH:mm:ss'))
        Write-Host ("End time              : {0}" -f $ScriptEndTime.ToString('yyyy-MM-dd HH:mm:ss'))
        Write-Host ("Duration              : {0:hh\:mm\:ss}" -f $duration)
        Write-Host ("Requested culture     : {0}" -f $TargetCulture.Name)
        Write-Host ("Providers read        : {0} of {1} attempted ({2} error(s))" -f $providersOk, $providersTried, $errors.Count)
        Write-Host ("Event rows            : {0}" -f $withEvents)
        Write-Host ("Providers w/o events  : {0}" -f $withoutEvents)
        Write-Host ("CSV file              : {0}" -f $csvStatus)
        Write-Host "======================================================" -ForegroundColor Cyan
    }
}