function Get-EventIdInventory {
    <#
    .SYNOPSIS
        Inventories Windows event logs on a workstation: builds a unique list of
        (LogName, EventID) pairs with description, provider, hit count and the
        user accounts the events were recorded under.

    .DESCRIPTION
        Walks the specified (or all non-empty) Windows event logs, groups events
        by (LogName, EventID), captures the first line of the event message as a
        description, and resolves the event's SID (UserId) to an account name
        where the provider populates it.

        LIMITATION: many events - especially system/driver events and a good
        part of Application-log events - never populate UserId at all. For
        those the Users column will simply be empty; this is a property of the
        event source, not a script defect.

        In addition to writing a CSV, the function emits the collected inventory
        objects to the pipeline, so it composes like a normal cmdlet, e.g.:
            Get-EventIdInventory -LogNames Security | Where-Object Count -gt 1000

        Assumes it is always run interactively by a person in a PowerShell 7
        console - all progress/status messages go straight to the console via
        Write-Host and Write-Progress. There is no console-vs-non-interactive
        detection and no separate log file; if this is later run unattended
        (scheduled task, remoting, etc.), that output will simply go nowhere
        visible - see .NOTES if that scenario comes up.

    .PARAMETER LogNames
        One or more log names to process. Accepts pipeline input, e.g.:
            'Security','System' | Get-EventIdInventory
        If omitted entirely (no argument, no pipeline input), all logs with
        RecordCount -gt 0 are enumerated automatically.

    .PARAMETER MaxEventsPerLog
        Max events read from a single log (guards against a multi-hour pass over
        a Security log with millions of records). 0 = no limit, read the log in
        full.

    .PARAMETER OutputCsv
        Path to the resulting CSV. Defaults to a timestamped file named after
        the computer, in the current directory.

    .EXAMPLE
        Get-EventIdInventory
        Processes every non-empty log, up to 50000 events each.

    .EXAMPLE
        Get-EventIdInventory -LogNames 'Security','System','Application' -MaxEventsPerLog 0
        Full (unbounded) pass over three specific logs.

    .EXAMPLE
        Get-EventIdInventory -WhatIf
        Shows which logs would be processed and where the CSV would be written,
        without reading any events or writing any file.

    .NOTES
        Version: 1.1
        Author : M. Zaikin
        Date   : 22-Sep-2026

        WHICH ACCOUNT TO RUN THIS AS

        1) The Security log is not readable by a plain standard user. Membership
           in the built-in local group "Event Log Readers" (SID S-1-5-32-573) is
           enough for READ access - full local-administrator rights are not
           required for that.

        2) Several Microsoft-Windows-*/Operational channels, and in particular
           the hidden Analytic/Debug channels, are ACL'd to
           Administrators/SYSTEM only; Event Log Readers membership will not
           open those. Reading them requires local-administrator rights (and,
           for Analytic/Debug channels, enabling them first with
           `wevtutil sl <channel> /e:true`), or a channel ACL explicitly
           widened with `wevtutil sl <channel> /ca:<SDDL>`.

        3) For fleet-wide rollout via GPO/RMM, the simplest option is a
           scheduled task running as NT AUTHORITY\SYSTEM - SYSTEM has full
           read access to every log, including Security and the hidden
           Analytic/Debug channels, with no extra group membership needed.
           NOTE: that scenario is exactly the unattended case this version no
           longer handles specially (see .DESCRIPTION) - Write-Host output
           would not be visible from a scheduled task. Re-introduce a
           log-file fallback if this function needs to run that way.

        Summary: for a one-off manual run on a single machine, membership in
        "Event Log Readers" covers Security + Application + System + most
        Operational logs. For full coverage (including hidden Analytic/Debug)
        and/or fleet deployment, use SYSTEM (via a scheduled task) or a local
        administrator account.
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Low')]
    param(
        [Parameter(ValueFromPipeline = $true)]
        [string[]]$LogNames,

        [int]$MaxEventsPerLog = 50000,

        [string]$OutputCsv = ".\EventIdInventory_$($env:COMPUTERNAME)_$(Get-Date -Format yyyyMMdd_HHmmss).csv"
    )

    BEGIN {
        $ErrorActionPreference = 'Stop'

        # Always write CSV text as UTF-8 WITH a BOM via .NET directly, rather
        # than relying on the cmdlet's -Encoding UTF8 switch: that switch means
        # "UTF-8 with BOM" on Windows PowerShell 5.1 but "UTF-8 WITHOUT BOM" on
        # PowerShell 7/Core. Without a BOM, Excel often mis-detects the encoding
        # when the CSV is just double-clicked and shows Cyrillic text (usernames,
        # localized event descriptions) as garbage.
        $Utf8BomEncoding = [System.Text.UTF8Encoding]::new($true)

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

        function Resolve-UserName {
            param([System.Security.Principal.SecurityIdentifier]$Sid)
            if (-not $Sid) { return $null }
            try {
                return $Sid.Translate([System.Security.Principal.NTAccount]).Value
            } catch {
                # SID does not resolve (deleted account, foreign domain, etc.) - keep the raw SID
                return $Sid.Value
            }
        }

        # Aggregation state, shared across process{} invocations for this call
        $results = [ordered]@{}   # key "LogName|Id" -> aggregated info
        $errors  = New-Object System.Collections.Generic.List[string]

        # Resolve the default log list ONLY if nothing is going to be bound via
        # argument or pipeline - otherwise process{} handles whatever comes in.
        $DefaultLogNames = $null
        if (-not $PSCmdlet.MyInvocation.ExpectingInput -and -not $PSBoundParameters.ContainsKey('LogNames')) {
            Write-Info "No -LogNames supplied and no pipeline input detected - enumerating all non-empty logs..."
            $DefaultLogNames = Get-WinEvent -ListLog * -ErrorAction SilentlyContinue |
                Where-Object { $_.RecordCount -gt 0 } |
                Select-Object -ExpandProperty LogName
            Write-Info ("Found {0} non-empty log(s) to process." -f $DefaultLogNames.Count)
        }

        $logCounter = 0
    }

    PROCESS {
        $logsToProcess = if ($LogNames) { $LogNames } else { $DefaultLogNames }

        foreach ($log in $logsToProcess) {

            if (-not $PSCmdlet.ShouldProcess($log, "Read events and build EventID inventory")) {
                continue
            }

            $logCounter++

            # Cheap, best-effort count just for a nicer progress bar - not
            # required for correctness, so failures here are silently ignored.
            $totalHint = $null
            try {
                $logInfo = Get-WinEvent -ListLog $log -ErrorAction SilentlyContinue
                if ($logInfo) {
                    $totalHint = $logInfo.RecordCount
                    if ($MaxEventsPerLog -gt 0) { $totalHint = [Math]::Min($totalHint, $MaxEventsPerLog) }
                }
            } catch { }

            Write-Progress -Activity "Collecting events by log" -Status "Log: $log ($logCounter)" -Id 1
            Write-Info "Processing log '$log'..."

            try {
                # Read one record at a time via the lower-level EventLogReader
                # API instead of Get-WinEvent's own bulk materialization.
                #
                # Real-world logs (System in particular, on machines with
                # third-party/OEM drivers - Realtek, Intel, Dell, etc.) often
                # contain individual records whose message-table reference is
                # broken (uninstalled/mismatched provider). Get-WinEvent reads
                # the whole log in one call, and a SINGLE such record aborts
                # the entire call with an error like "Не удалось найти строку
                # описания для ссылки на параметр (%1)" / "The description for
                # Event ID ... cannot be found" - even though every other
                # record in that log is perfectly fine and the account has
                # full read rights. Reading record-by-record lets us skip just
                # the bad record(s) and keep the rest of the log.
                $query  = [System.Diagnostics.Eventing.Reader.EventLogQuery]::new($log, [System.Diagnostics.Eventing.Reader.PathType]::LogName)
                $query.ReverseDirection = $true   # newest-first, matches Get-WinEvent's default (no -Oldest)
                $reader = [System.Diagnostics.Eventing.Reader.EventLogReader]::new($query)

                $i = 0
                $totalUnreadable      = 0   # reported at the end - every record skipped over the whole log
                $consecutiveUnreadable = 0  # reset on every successful read - the actual "is the reader stuck" signal

                try {
                    while ($true) {
                        if ($MaxEventsPerLog -gt 0 -and $i -ge $MaxEventsPerLog) { break }

                        try {
                            $ev = $reader.ReadEvent()
                        } catch {
                            # This one record could not be read at all - skip it
                            # and move on to the next. A handful of these
                            # scattered across a large log (a few bad records
                            # from one flaky OEM driver among tens of thousands
                            # of good ones) is normal and expected - it is a RUN
                            # of consecutive failures that would mean the reader
                            # is actually stuck, so only that resets to zero on
                            # every success and trips the safety valve here.
                            $totalUnreadable++
                            $consecutiveUnreadable++
                            if ($consecutiveUnreadable -gt 200) {
                                throw "Too many unreadable records in a row ($consecutiveUnreadable) - aborting this log. Last error: $($_.Exception.Message)"
                            }
                            continue
                        }

                        if ($null -eq $ev) { break }   # end of log reached
                        $consecutiveUnreadable = 0

                        try {
                            $i++
                            if ($i % 1000 -eq 0) {
                                $status  = if ($totalHint) { "Event $i of ~$totalHint" } else { "Event $i" }
                                $percent = if ($totalHint) { [Math]::Min(100, ($i / [Math]::Max($totalHint, 1)) * 100) } else { 0 }
                                Write-Progress -Activity "Log: $log" -Status $status -PercentComplete $percent -Id 2 -ParentId 1
                            }

                            $key = "$($ev.LogName)|$($ev.Id)"

                            if (-not $results.Contains($key)) {
                                $desc = $null
                                try {
                                    $msg = $ev.Message
                                    if ($msg) {
                                        $desc = ($msg -split "`r?`n")[0].Trim()
                                        if ($desc.Length -gt 200) { $desc = $desc.Substring(0, 200) + '...' }
                                    }
                                } catch {
                                    # The record itself read fine, but its message
                                    # text specifically can't be resolved - same
                                    # root cause as above (broken provider/manifest
                                    # reference), just caught at a finer grain here.
                                    $desc = '(description unavailable - provider/manifest not found)'
                                }
                                if (-not $desc) { $desc = '(description unavailable - provider/manifest not found)' }

                                $results[$key] = [ordered]@{
                                    LogName      = $ev.LogName
                                    EventID      = $ev.Id
                                    ProviderName = $ev.ProviderName
                                    Level        = $ev.LevelDisplayName
                                    Description  = $desc
                                    Users        = New-Object System.Collections.Generic.HashSet[string]
                                    Count        = 0
                                    FirstSeen    = $ev.TimeCreated
                                    LastSeen     = $ev.TimeCreated
                                }
                            }

                            $entry = $results[$key]
                            $entry.Count++
                            if ($ev.TimeCreated -and $ev.TimeCreated -lt $entry.FirstSeen) { $entry.FirstSeen = $ev.TimeCreated }
                            if ($ev.TimeCreated -and $ev.TimeCreated -gt $entry.LastSeen)  { $entry.LastSeen  = $ev.TimeCreated }

                            if ($ev.UserId) {
                                $userName = Resolve-UserName -Sid $ev.UserId
                                if ($userName) { [void]$entry.Users.Add($userName) }
                            }
                        } finally {
                            $ev.Dispose()
                        }
                    }
                } finally {
                    $reader.Dispose()
                }

                $summary = "Log '{0}': {1} event(s) read, {2} unique EventID(s) so far." -f $log, $i, $results.Count
                if ($totalUnreadable -gt 0) { $summary += " ({0} unreadable record(s) skipped)" -f $totalUnreadable }
                Write-Info $summary

            } catch {
                $errMsg = "Log '$log': $($_.Exception.Message)"
                $errors.Add($errMsg)
                Write-Info $errMsg -Level ERROR
                continue
            }
        }
    }

    END {
        Write-Progress -Activity "Collecting events by log" -Completed -Id 1

        $export = foreach ($entry in $results.Values) {
            [pscustomobject]@{
                Workstation = $env:COMPUTERNAME
                LogName     = $entry.LogName
                EventID     = $entry.EventID
                Provider    = $entry.ProviderName
                Level       = $entry.Level
                Description = $entry.Description
                Users       = ($entry.Users -join '; ')
                Count       = $entry.Count
                FirstSeen   = $entry.FirstSeen
                LastSeen    = $entry.LastSeen
            }
        }
        $export = $export | Sort-Object LogName, EventID

        if ($PSCmdlet.ShouldProcess($OutputCsv, "Export EventID inventory to CSV")) {
            $resolvedCsvPath = $PSCmdlet.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputCsv)
            $csvLines = $export | ConvertTo-Csv -NoTypeInformation
            [System.IO.File]::WriteAllLines($resolvedCsvPath, $csvLines, $Utf8BomEncoding)
            Write-Info ("Done: {0} unique (log, EventID) pair(s) saved to {1}" -f $export.Count, $OutputCsv)
        } else {
            Write-Info ("WhatIf: would have saved {0} unique (log, EventID) pair(s) to {1}" -f $export.Count, $OutputCsv)
        }

        if ($errors.Count -gt 0) {
            Write-Info ("{0} log(s) could not be fully processed - most likely cause is insufficient permissions. See NOTES in the function's help (Get-Help Get-EventIdInventory -Full)." -f $errors.Count) -Level WARN
        }

        # Emit the collected objects to the pipeline as well as the CSV,
        # so the function composes like a normal cmdlet.
        $export
    }
}