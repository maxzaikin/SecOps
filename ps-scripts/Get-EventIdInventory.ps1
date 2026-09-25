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

        The function does NOT emit the collected inventory objects to the
        pipeline - only a short run summary (start/end time, duration, logs
        and events processed, CSV path) is printed to the console at the
        end. The full data lives in the CSV; if you need it back as
        objects for further filtering in the same session, read it back
        with Import-Csv against the printed CSV path, e.g.:
            Import-Csv $csvPath | Where-Object Count -gt 1000

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

    .PARAMETER HighRateThreshold
        Events-per-minute (Count / max(DurationMinutes, 1)) at or above which
        a row's "Density" column is rated "High". Default 1.0 (= roughly one
        event/minute sustained, i.e. ~1440/day and up) - a real-world example
        of "High" at a much larger scale: a flooding 4673 Sensitive-Privilege-
        Use stream on a busy workstation ran at dozens to thousands of
        events/minute.

    .PARAMETER MidRateThreshold
        Events-per-minute at or above which (and below HighRateThreshold) a
        row's "Density" column is rated "Mid" instead of "Low". Default 0.05
        (= roughly one event every 20 minutes, ~72/day).

    .PARAMETER MinCountForDensity
        Rows with fewer than this many total occurrences are always rated
        "Low" density, regardless of the rate math. Default 3 - a couple of
        occurrences over any window isn't a "flow" to measure a density for,
        it's just a couple of data points (and without this floor, a single
        occurrence with DurationMinutes = 0 would otherwise divide out to an
        artificially "High" rate).

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
        Version: 1.5
        Author : M. Zaikin
        Date   : 25-Sep-2026

        v1.5 CHANGES:
        - New "EventsPerMinute" and "Density" columns, derived from Count and
          the v1.4 DurationMinutes - a first-pass, self-contained answer to
          "is this row's traffic High/Mid/Low", computed purely from what the
          script already collected (no SIEM coverage data, no baseline,
          consistent with how this tool is meant to be used).
        - EventsPerMinute = Count / max(DurationMinutes, 1) - the 1-minute
          floor on the denominator avoids a divide-by-zero (DurationMinutes
          is 0 when every occurrence landed in the same instant) and avoids a
          handful of same-minute occurrences producing an absurdly inflated
          rate.
        - Density buckets EventsPerMinute against -HighRateThreshold (default
          1.0/min) and -MidRateThreshold (default 0.05/min), all three
          tunable per run - see .PARAMETER. Rows with Count below
          -MinCountForDensity (default 3) are always "Low": a couple of
          occurrences anywhere in the window isn't a "flow" worth rating.
          Density is "Unknown" (EventsPerMinute blank) only in the rare case
          where DurationMinutes itself couldn't be computed (every occurrence
          of that row was missing a TimeCreated) - there's no window to rate
          a density against at all in that case.
        - This is a starting point, not a verdict - it says nothing about
          whether a row is noise or a genuine misconfiguration on its own
          (High density is completely normal for some providers, e.g.
          telemetry/heartbeat events); it's meant to be read together with
          Task/Keywords/SampleEventData and compared across Workstation, per
          the methodology already captured in the project doc.

        v1.4 CHANGES:
        - New "DurationMinutes" column: minutes between FirstSeen and
          LastSeen for that (LogName, Provider, EventID) row, rounded to 2
          decimals. A quick way to see whether a high Count is spread over
          hours/days (routine background chatter) or crammed into a very
          short window (a burst worth a closer look, or a log that's
          rotating too fast to hold real history - see the Security/4673
          note further down).
        - The function no longer dumps its collected objects to the
          pipeline/console at the end (previously the last line of END was
          a bare "$export", which - when the function is called without
          capturing its output, i.e. normal interactive use - printed the
          entire in-memory object list to the console as a big per-object
          field dump). Replaced with a short, fixed-format run summary:
          start time, end time, duration, how many logs were attempted vs.
          fully processed, how many events were read in total, how many
          unique rows ended up in the CSV, and the resolved CSV path. The
          CSV itself is unaffected - it still gets every column. If you
          need the data back as PowerShell objects in the same session,
          Import-Csv the printed path.

        v1.3 CHANGES - aimed specifically at a downstream analysis question
        this data feeds: with no SIEM ingestion/coverage report and no
        baseline available to compare against, is a given (log, EventID) row
        (a) operational noise with no security value, or (b) a symptom of a
        misconfiguration - and if (b), is that misconfiguration local to one
        machine or applied fleet-wide via AD/GPO? None of that can be judged
        from a bare EventID + first line of text, so this version captures
        more of what each event itself already carries:
        - Aggregation key now includes ProviderName: "LogName|Provider|Id".
          The same numeric EventID means different things under different
          providers writing to the same log (EventID is only unique within
          one provider's manifest) - the old "LogName|Id" key silently
          merged unrelated events that happened to share a number.
        - Description now keeps the FULL message (newlines flattened to a
          single line with " | "), not just the first line, truncated at a
          much longer 800 chars instead of 200 - the parameter values that
          distinguish "routine" from "worth a look" for the same EventID
          (account name, process path, target object, privilege list, ...)
          are frequently on the second/third line of Security audit messages
          and were being discarded entirely before.
        - New "SampleEventData" column: a Name=Value list parsed straight
          from one occurrence's raw XML (.ToXml()), independent of whether
          ".FormatDescription()" resolves at all. This is the fallback for
          the "broken manifest" providers (OEM drivers etc.) where
          Description stays "(description unavailable...)" forever -
          .ToXml() needs no message-table lookup, so structured parameter
          data (ProcessName, TargetUserName, PrivilegeList, IpAddress, ...)
          is still recoverable even then. Works against both the classic
          <EventData> shape and the newer manifest-based <UserData> shape.
        - New "Task", "TaskRaw", "Opcode" and "Keywords" columns. On the
          Security log in particular, Task/Keywords is how a raw EventID
          maps back to a specific Advanced Audit Policy subcategory (e.g.
          "Sensitive Privilege Use" / "Audit Success") - the subcategories
          are what's actually configured via GPO, so this is the concrete
          hook for telling "this fires because subcategory X is enabled for
          everyone via GPO" apart from "this fires only here for some local
          reason". TaskRaw (numeric) is kept alongside Task (display name)
          because TaskDisplayName is null for a fair number of providers.
        - Level/LevelRaw/Task/TaskRaw/Opcode/Keywords are now all read via a
          small try/catch wrapper (previously only Description/FormatDescription
          had this). A provider with a broken manifest can throw on ANY of its
          display-name properties, not just Message/FormatDescription - and
          since these reads happen inside the same per-event try block that
          aborts the whole log on an uncaught exception, an unguarded read of
          one of them could reintroduce the exact "one bad record kills the
          whole log" failure mode v1.1 fixed for the message text alone.

        v1.2 CHANGES (found via real-world runs against System/Security logs
        with tens of thousands of events):
        - Description was empty in 100% of rows. Root cause: records read via
          EventLogReader.ReadEvent() are bare EventLogRecord objects - the
          ".Message" convenience property (which PowerShell's own Get-WinEvent
          output normally exposes) is not reliably populated on them. Fixed by
          calling ".FormatDescription()" directly instead of ".Message".
        - Description is now retried on later occurrences of the same
          (LogName, EventID) pair if the first occurrence encountered happened
          to be one whose own message couldn't be resolved, instead of
          permanently locking in the placeholder from that first record.
        - Added a raw numeric "LevelRaw" column alongside the localized
          "Level" (LevelDisplayName) text, since LevelDisplayName is not
          resolved for every provider (some show a raw digit or nothing) -
          LevelRaw is reliable for machine comparison/joins.

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

        [string]$OutputCsv = ".\EventIdInventory_$($env:COMPUTERNAME)_$(Get-Date -Format yyyyMMdd_HHmmss).csv",

        [double]$HighRateThreshold = 1.0,

        [double]$MidRateThreshold = 0.05,

        [int]$MinCountForDensity = 3
    )

    BEGIN {
        $ErrorActionPreference = 'Stop'

        # Captured here (as early as possible) rather than in END, so the
        # run summary's "Start time" reflects when the call actually began,
        # not just when the last log finished.
        $ScriptStartTime = Get-Date
        $totalEventsProcessed = 0   # summed across all logs, for the run summary
        $logsProcessedOk      = 0   # logs that finished without hitting the outer catch

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

        function Get-SafeDisplayName {
            # Wraps a single property read so a provider with a broken/missing
            # manifest (throws on LevelDisplayName, TaskDisplayName, etc.) can't
            # blow up the per-event try block that owns it and abort the whole log.
            param([Parameter(Mandatory)][scriptblock]$Getter)
            try { & $Getter } catch { $null }
        }

        function Get-EventDataSummary {
            # Pulls a Name=Value summary straight out of one occurrence's raw XML
            # (.ToXml()), independent of whether FormatDescription()/the message
            # table resolves at all. This is the fallback for "broken manifest"
            # providers where Description never resolves - .ToXml() needs no
            # message-table lookup, so the structured parameter values are still
            # recoverable. Handles both the classic <EventData><Data Name="..">
            # shape and the newer, provider-specific <UserData> manifest shape.
            param(
                [Parameter(Mandatory)][System.Diagnostics.Eventing.Reader.EventRecord]$Event,
                [int]$MaxLength = 600
            )
            try {
                [xml]$xml = $Event.ToXml()
            } catch {
                return $null
            }

            $pairs = New-Object System.Collections.Generic.List[string]

            try {
                # PowerShell's XML adapter exposes child elements as properties by
                # their local (namespace-stripped) name, so $xml.Event.EventData
                # works despite the default event-schema namespace on every
                # element in this document.
                $dataNodes = @($xml.Event.EventData.Data)
                foreach ($d in $dataNodes) {
                    if ($null -eq $d) { continue }
                    if ($d -is [string]) {
                        # <Data>value</Data> with no Name attribute
                        if (-not [string]::IsNullOrWhiteSpace($d)) { $pairs.Add($d) }
                        continue
                    }
                    $name  = $d.Name
                    $value = $d.'#text'
                    if ([string]::IsNullOrWhiteSpace($value)) { continue }
                    if ($name) { $pairs.Add("$name=$value") } else { $pairs.Add($value) }
                }
            } catch { }

            if ($pairs.Count -eq 0) {
                # No usable <EventData> - try <UserData> instead. Its schema is
                # entirely provider-specific, so walk every leaf element
                # generically rather than assuming field names.
                try {
                    $userData = $xml.Event.UserData
                    if ($userData) {
                        $walk = {
                            param($Node)
                            foreach ($child in $Node.ChildNodes) {
                                if ($child.NodeType -ne [System.Xml.XmlNodeType]::Element) { continue }
                                $childElements = @($child.ChildNodes | Where-Object { $_.NodeType -eq [System.Xml.XmlNodeType]::Element })
                                if ($childElements.Count -gt 0) {
                                    & $walk $child
                                } else {
                                    $val = $child.InnerText
                                    if (-not [string]::IsNullOrWhiteSpace($val)) {
                                        $pairs.Add("$($child.LocalName)=$val")
                                    }
                                }
                            }
                        }
                        & $walk $userData
                    }
                } catch { }
            }

            if ($pairs.Count -eq 0) { return $null }

            $summary = ($pairs -join '; ') -replace "`r?`n", ' '
            if ($summary.Length -gt $MaxLength) { $summary = $summary.Substring(0, $MaxLength) + '...' }
            return $summary
        }

        # Aggregation state, shared across process{} invocations for this call
        $results = [ordered]@{}   # key "LogName|Provider|Id" -> aggregated info
        $errors  = New-Object System.Collections.Generic.List[string]
        $DescriptionUnavailable = '(description unavailable - provider/manifest not found)'

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

                            # Key includes ProviderName: EventID is only unique
                            # WITHIN one provider's manifest - the same number under
                            # two different providers writing to the same log is two
                            # unrelated event types, not one.
                            $providerName = Get-SafeDisplayName { $ev.ProviderName }
                            $key = "$($ev.LogName)|$providerName|$($ev.Id)"

                            if (-not $results.Contains($key)) {
                                $results[$key] = [ordered]@{
                                    LogName      = $ev.LogName
                                    EventID      = $ev.Id
                                    ProviderName = $providerName
                                    Level        = Get-SafeDisplayName { $ev.LevelDisplayName }
                                    LevelRaw     = Get-SafeDisplayName { $ev.Level }
                                    Task         = Get-SafeDisplayName { $ev.TaskDisplayName }
                                    TaskRaw      = Get-SafeDisplayName { $ev.Task }
                                    Opcode       = Get-SafeDisplayName { $ev.OpcodeDisplayName }
                                    Keywords     = Get-SafeDisplayName { ($ev.KeywordsDisplayNames -join '; ') }
                                    Description     = $DescriptionUnavailable
                                    SampleEventData = $null
                                    Users        = New-Object System.Collections.Generic.HashSet[string]
                                    Count        = 0
                                    FirstSeen    = $ev.TimeCreated
                                    LastSeen     = $ev.TimeCreated
                                }
                            }

                            $entry = $results[$key]

                            # Try to resolve a real description from THIS occurrence
                            # if we don't have one yet. Note: this is deliberately
                            # NOT gated to "only on the first occurrence" - the very
                            # first record seen for an EventID can itself be one
                            # whose message can't be resolved, in which case later
                            # occurrences get a chance to fill it in instead of the
                            # placeholder being locked in forever. Keep the FULL
                            # message now (flattened to one line), not just its
                            # first line - the parameter values that distinguish
                            # "routine" from "worth a look" for the same EventID are
                            # often on line two or three, not line one.
                            if ($entry.Description -eq $DescriptionUnavailable) {
                                try {
                                    # Use FormatDescription() directly rather than the
                                    # ".Message" convenience property: records read via
                                    # EventLogReader.ReadEvent() (as opposed to
                                    # Get-WinEvent's own output) do not reliably expose
                                    # a populated ".Message" - it comes back empty even
                                    # for perfectly fine records with a real manifest.
                                    $msg = $ev.FormatDescription()
                                    if ($msg) {
                                        $desc = ($msg.Trim() -replace "`r?`n", ' | ')
                                        if ($desc.Length -gt 800) { $desc = $desc.Substring(0, 800) + '...' }
                                        if ($desc) { $entry.Description = $desc }
                                    }
                                } catch {
                                    # Still unavailable for this occurrence too - leave
                                    # the placeholder, a later occurrence may succeed.
                                }
                            }

                            # Same retry-until-filled pattern for SampleEventData: it
                            # doesn't need FormatDescription()/the message table to
                            # succeed at all, so it's frequently the ONLY source of
                            # real parameter values (account name, process, privilege
                            # list, ...) for providers with a broken/missing manifest
                            # where Description never resolves past the placeholder.
                            if (-not $entry.SampleEventData) {
                                $entry.SampleEventData = Get-EventDataSummary -Event $ev
                            }

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

                $totalEventsProcessed += $i
                $logsProcessedOk++

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
            $durationMinutes = $null
            if ($entry.FirstSeen -and $entry.LastSeen) {
                # Minutes between the earliest and latest occurrence seen for
                # this row - a quick signal for whether a high Count is spread
                # over a long, ordinary window or crammed into a short burst
                # (or, on Security in particular, whether the window is
                # suspiciously short because the log is rotating too fast to
                # hold real history at all - see the 4673 note above).
                $durationMinutes = [Math]::Round((New-TimeSpan -Start $entry.FirstSeen -End $entry.LastSeen).TotalMinutes, 2)
            }

            # EventsPerMinute / Density: a self-contained, first-pass read on
            # how "busy" this row's traffic is, built only from Count and
            # DurationMinutes - no SIEM coverage data or external baseline
            # involved.
            $eventsPerMinute = $null
            if ($null -eq $durationMinutes) {
                # Only happens if TimeCreated itself was missing on every
                # occurrence of this row (rare) - no window to rate at all,
                # so say so explicitly rather than guessing.
                $density = 'Unknown'
            } else {
                # 1-minute floor on the denominator avoids both a
                # divide-by-zero (DurationMinutes 0, i.e. every occurrence
                # landed in the same instant) and a handful of same-minute
                # occurrences producing an absurdly inflated rate.
                $effectiveMinutesForRate = [Math]::Max($durationMinutes, 1)
                $eventsPerMinute = [Math]::Round($entry.Count / $effectiveMinutesForRate, 4)

                $density = if ($entry.Count -lt $MinCountForDensity) {
                    # Too few occurrences anywhere in the window to call this
                    # a "flow" at all - not enough data points to rate a
                    # density, regardless of what the rate math above says.
                    'Low'
                } elseif ($eventsPerMinute -ge $HighRateThreshold) {
                    'High'
                } elseif ($eventsPerMinute -ge $MidRateThreshold) {
                    'Mid'
                } else {
                    'Low'
                }
            }

            [pscustomobject]@{
                Workstation      = $env:COMPUTERNAME
                LogName          = $entry.LogName
                EventID          = $entry.EventID
                Provider         = $entry.ProviderName
                Level            = $entry.Level
                LevelRaw         = $entry.LevelRaw
                Task             = $entry.Task
                TaskRaw          = $entry.TaskRaw
                Opcode           = $entry.Opcode
                Keywords         = $entry.Keywords
                Description      = $entry.Description
                SampleEventData  = $entry.SampleEventData
                Users            = ($entry.Users -join '; ')
                Count            = $entry.Count
                FirstSeen        = $entry.FirstSeen
                LastSeen         = $entry.LastSeen
                DurationMinutes  = $durationMinutes
                EventsPerMinute  = $eventsPerMinute
                Density          = $density
            }
        }
        $export = $export | Sort-Object LogName, EventID

        # Resolved unconditionally (this does not touch disk) so the run
        # summary below can always show the real path, -WhatIf included.
        $resolvedCsvPath = $PSCmdlet.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputCsv)
        $csvWasWritten = $false

        if ($PSCmdlet.ShouldProcess($OutputCsv, "Export EventID inventory to CSV")) {
            $csvLines = $export | ConvertTo-Csv -NoTypeInformation
            [System.IO.File]::WriteAllLines($resolvedCsvPath, $csvLines, $Utf8BomEncoding)
            $csvWasWritten = $true
        }

        if ($errors.Count -gt 0) {
            Write-Info ("{0} log(s) could not be fully processed - most likely cause is insufficient permissions. See NOTES in the function's help (Get-Help Get-EventIdInventory -Full)." -f $errors.Count) -Level WARN
        }

        # Run summary instead of dumping every collected object to the
        # console: the CSV already holds the full data with every column -
        # this is just the "did it work, how much did it do" answer.
        $ScriptEndTime = Get-Date
        $totalDuration = New-TimeSpan -Start $ScriptStartTime -End $ScriptEndTime
        $logsFailedSuffix = if ($errors.Count -gt 0) { " ($($errors.Count) failed)" } else { "" }
        $csvStatusLine = if ($csvWasWritten) { $resolvedCsvPath } else { "$resolvedCsvPath (WhatIf - not written)" }

        Write-Host ""
        Write-Host "==================== Run summary ====================" -ForegroundColor Cyan
        Write-Host ("Start time         : {0}" -f $ScriptStartTime.ToString('yyyy-MM-dd HH:mm:ss'))
        Write-Host ("End time           : {0}" -f $ScriptEndTime.ToString('yyyy-MM-dd HH:mm:ss'))
        Write-Host ("Duration           : {0:hh\:mm\:ss}" -f $totalDuration)
        Write-Host ("Logs processed     : {0} of {1} attempted{2}" -f $logsProcessedOk, $logCounter, $logsFailedSuffix)
        Write-Host ("Events processed   : {0}" -f $totalEventsProcessed)
        Write-Host ("Unique rows in CSV : {0}" -f $export.Count)
        Write-Host ("CSV file           : {0}" -f $csvStatusLine)
        Write-Host "======================================================" -ForegroundColor Cyan
    }
}