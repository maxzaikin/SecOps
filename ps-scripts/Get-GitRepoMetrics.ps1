function Get-GitRepoMetrics {
    <#
        .SYNOPSIS
            Fetches extended GitHub repository metrics, including release stability, 
            security advisories, and OpenSSF health scores.

        .PARAMETER RepoOwner
            GitHub organization or user name.

        .PARAMETER RepoName
            Repository name.

        .PARAMETER StartYear
            Analyze releases starting from this year.

        .PARAMETER EndYear
            Analyze releases until this year.

        .PARAMETER OutputCsv
            Path for the output CSV file. Defaults to a timestamped filename.

        .PARAMETER GitHubToken
            Optional Personal Access Token (PAT) for higher rate limits and security metrics access.
           
        .EXAMPLE
            Get-GitRepoMetrics -RepoOwner "maxzaikin" -RepoName "TGB-MicroSuite" -StartYear 2023
            Analyzes the specified repository starting from 2023.

        .NOTES
            Version: 1.3
            Author: M. Zaikin
            Date: 23-May-2024

        [-------------------------------------DISCLAIMER-------------------------------------]
         All script are provided as-is with no implicit
         warranty or support. It's always considered a best practice
         to test scripts in a DEV/TEST environment, before running them
         in production. In other words, I will not be held accountable
         if one of my scripts is responsible for an RGE (Resume Generating Event).
        [-------------------------------------DISCLAIMER-------------------------------------]
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)],

        [Parameter(Mandatory = $false)],

        [Parameter(Mandatory = $false)],

        [Parameter(Mandatory = $false)],

        [Parameter(Mandatory = $false)]
        [string]$OutputCsv = "repo_audit_$(Get-Date -Format 'yyyyMMdd_HHmm').csv",

        [Parameter(Mandatory = $false)]
        [string]$GitHubToken = ""
    )

    BEGIN {
        Write-Progress -Activity "Initialization" -Status "Preparing headers..." -PercentComplete 0
        
        # Setup Headers for GitHub API
        $headers = @{ Accept = "application/vnd.github+json" }
        if ($GitHubToken) {
            $headers.Authorization = "Bearer $GitHubToken"
            Write-Host "GitHub Token activated - High rate limit enabled." -ForegroundColor Green
        } else {
            Write-Warning "No token provided - Rate limit is restricted to 60 requests/hour."
        }
        
        $baseUrl = "https://api.github.com/repos/$RepoOwner/$RepoName"

        # Helper: Calculate Stability Score based on metrics
        function Get-StabilityScore {
            param ($minorCount, $fixCount, $pureIssues, $openPRs, $bugCount)
            $score = 0
            if ($minorCount -gt 5)   { $score += 2 }     # Mature branch
            if ($fixCount -gt 20)    { $score += 2 }     # Active maintenance
            if ($pureIssues -lt 500) { $score += 1 }     # Low issue debt
            if ($openPRs -lt 100)    { $score += 1 }     # Healthy PR flow
            if ($bugCount -lt 50)    { $score += 1 }     # Low bug count
    
            if ($score -ge 6) { return "High (Stable)" }
            elseif ($score -ge 4) { return "Medium-High" }
            elseif ($score -ge 2) { return "Medium" }
            else { return "Low (Early/High Debt)" }
        }

        # Helper: Reliable item counter using pagination
        function Get-GitHubCount {
            param([string]$Url, [hashtable]$Headers)
            $total = 0
            $page = 1
            do {
                $pagedUrl = "$Url&page=$page&per_page=100"
                try {
                    $resp = Invoke-RestMethod -Uri $pagedUrl -Headers $Headers -Method Get
                    $total += $resp.Count
                    $page++
                } catch { break }
            } while ($resp.Count -eq 100)
            return $total
        }
    }

    PROCESS {
        # 1. General Repository Metrics
        Write-Progress -Activity "Base Metrics" -Status "Requesting repo data..." -PercentComplete 5
        try {
            $repo = Invoke-RestMethod -Uri $baseUrl -Headers $headers
            $stars = $repo.stargazers_count
            $forks = $repo.forks_count
            $watchers = $repo.watchers_count
        } catch {
            Write-Error "Repository error: $($_.Exception.Message)"
            return
        }

        # 2. Activity Metrics (Issues vs PRs)
        # Note: GitHub API treats PRs as Issues in the /issues endpoint. 
        # We fetch PRs separately to get "Pure Issues".
        Write-Progress -Activity "Activity" -Status "Counting issues/PRs/bugs..." -PercentComplete 15
        $totalIssuesAndPRs = Get-GitHubCount "$baseUrl/issues?state=open" $headers
        $openPRs           = Get-GitHubCount "$baseUrl/pulls?state=open" $headers
        $pureIssues        = $totalIssuesAndPRs - $openPRs
        $bugCount          = Get-GitHubCount "$baseUrl/issues?state=open&labels=bug" $headers

        # 3. Security Advisories (GHSA)
        Write-Progress -Activity "Security" -Status "Fetching GHSA data..." -PercentComplete 30
        $ghsaTotal = $ghsaOpen = $ghsaClosed = 0
        try {
            $advisories = Invoke-RestMethod -Uri "$baseUrl/security-advisories?state=all&per_page=100" -Headers $headers
            $ghsaTotal  = $advisories.Count
            $ghsaOpen   = ($advisories | Where-Object state -eq "open").Count
            $ghsaClosed = $ghsaTotal - $ghsaOpen
        } catch {}

        # 4. OpenSSF Scorecard
        Write-Progress -Activity "Security" -Status "Fetching OpenSSF Scorecard..." -PercentComplete 40
        $scorecardScore = $scorecardDate = "N/A"
        try {
            $sc = Invoke-RestMethod -Uri "https://api.securityscorecards.dev/projects/github.com/$RepoOwner/$RepoName"
            $scorecardScore = $sc.score
            $scorecardDate  = $sc.date
        } catch {}

        # 5. Token-based Security Features
        $dependabot = $vulnAlerts = $codeScan = $codeAlerts = $secretScan = $secretAlerts = "N/A (No Token)"
        if ($GitHubToken) {
            Write-Progress -Activity "Auth Security" -Status "Analyzing Dependabot / Scanning..." -PercentComplete 50
            
            # Dependabot
            try {
                $vulnAlerts = Get-GitHubCount "$baseUrl/dependabot/alerts?state=open" $headers
                $dependabot = "Yes ($vulnAlerts open)"
            } catch { $dependabot = "No/Access Denied" }

            # Code Scanning
            try {
                $codeAlerts = Get-GitHubCount "$baseUrl/code-scanning/alerts?state=open" $headers
                $codeScan = "Yes ($codeAlerts)"
            } catch { $codeScan = "No/Access Denied" }

            # Secret Scanning
            try {
                $secretAlerts = Get-GitHubCount "$baseUrl/secret-scanning/alerts?state=open" $headers
                $secretScan = "Yes ($secretAlerts)"
            } catch { $secretScan = "No/Access Denied" }
        }

        # 6. Average CVE Fix Time
        $avgFixDays = "N/A"
        if ($advisories.Count -gt 0) {
            $closed = $advisories | Where-Object { $_.state -eq "closed" -and $_.created_at -and $_.published_at }
            if ($closed.Count -gt 0) {
                $days = $closed | ForEach-Object { ([datetimeoffset]$_.published_at - [datetimeoffset]$_.created_at).TotalDays }
                $avgFixDays = [math]::Round(($days | Measure-Object -Average).Average, 1)
            }
        }

        # 7. Collect and Group Releases
        Write-Progress -Activity "Releases" -Status "Downloading release history..." -PercentComplete 60
        $releases = @()
        $page = 1
        do {
            $url = "$baseUrl/releases?per_page=100&page=$page"
            try {
                $resp = Invoke-RestMethod -Uri $url -Headers $headers
                $releases += $resp
                $page++
                Start-Sleep -Milliseconds 100
            } catch { break }
        } while ($resp.Count -eq 100)

        # Filter: Universal tag matching (v1.0, 2.0.1, etc.)
        $filtered = $releases | Where-Object {
            $_.tag_name -match '\d+\.\d+' -and
            ([datetimeoffset]$_.published_at).Year -ge $StartYear -and
            ([datetimeoffset]$_.published_at).Year -le $EndYear
        } | Sort-Object published_at -Descending

        # Group by major.minor branch
        $grouped = $filtered | Group-Object { $_.tag_name -replace '\.\d+.*$', '' }

        # 8. Main Analysis Loop
        $results = @()
        $totalItems = $filtered.Count
        if ($totalItems -gt 0) {
            $currentIndex = 0
            foreach ($g in $grouped) {
                foreach ($rel in $g.Group) {
                    $currentIndex++
                    $pct = [math]::Min(95, 60 + ($currentIndex / $totalItems * 35))
                    Write-Progress -Activity "Analyzing Releases" -Status "$($rel.tag_name) ($currentIndex/$totalItems)" -PercentComplete $pct

                    $body = $rel.body
                    $fixes = [regex]::Matches($body, '(?i)(fix(?:ed)?|bugfix|patch|security\s?fix|cve-|resolved|addressed|backport)').Count

                    $stability = Get-StabilityScore -minorCount $g.Count -fixCount $fixes -pureIssues $pureIssues -openPRs $openPRs -bugCount $bugCount
                
                    $results += [PSCustomObject]@{
                        Branch            = $g.Name
                        Tag               = $rel.tag_name
                        Type              = if ($rel.tag_name -match '-lts$') { 'LTS' } else { 'Stable/Other' }
                        ReleaseDate       = ([datetimeoffset]$rel.published_at).ToString("yyyy-MM-dd")
                        Stability         = $stability
                        BreakingChanges   = if ($body -match '(?i)backward incompatible|breaking change') { 'Yes' } else { 'No' }
                        FixesInChangelog  = $fixes
                        Stars             = $stars
                        PureIssues        = $pureIssues
                        OpenPRs           = $openPRs
                        BugLabeledIssues  = $bugCount
                        OpenSSF_Score     = $scorecardScore
                        Dependabot        = $dependabot
                        VulnAlerts        = $vulnAlerts
                        GHSA_Open         = $ghsaOpen
                        AvgFixDaysCVE     = $avgFixDays
                    }
                }
            }
        }
    }

    END {
        Write-Progress -Activity "Processing" -Completed

        # Console Output
        if ($results.Count -gt 0) {
            $results | Sort-Object ReleaseDate -Descending | Format-Table -AutoSize
        } else {
            Write-Warning "No releases matched the filters (Year: $StartYear-$EndYear, Tag format)."
        }
        
        $results | Export-Csv -Path $OutputCsv -NoTypeInformation -Encoding UTF8

        # Summary Report (Detailed)
        Write-Host "`n=== Final Audit Summary ===" -ForegroundColor Cyan
        Write-Host "Releases Processed     : $($results.Count)"
        Write-Host "Total Branches         : $($grouped.Count)"
        Write-Host "Repository Stars       : $stars"
        Write-Host "Pure Open Issues       : $pureIssues"
        Write-Host "Open Pull Requests     : $openPRs"
        Write-Host "Bug Labeled Issues     : $bugCount"
        Write-Host "Dependabot Status      : $dependabot"
        Write-Host "Vulnerability Alerts   : $vulnAlerts"
        Write-Host "Code Scanning Status   : $codeScan"
        Write-Host "Secret Scanning Status : $secretScan"
        Write-Host "OpenSSF Health Score   : $scorecardScore"
        Write-Host "GHSA Total / Open      : $ghsaTotal / $ghsaOpen"
        Write-Host "Avg CVE Fix Time (Days): $avgFixDays"
        Write-Host "Output File            : $OutputCsv"
        Write-Host "==============================" -ForegroundColor Cyan
    }
}
