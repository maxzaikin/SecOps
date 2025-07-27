function Get-ShadowAdmin-Analysis-Ext {
   <#
        .SYNOPSIS
            Scan specific user's AD group memberships recursively to find "shadow administrator" access paths.

        .DESCRIPTION
            This is extended version of Get-ShadowAdmin-Analysis. The main diffrences are:
                1. Display aextended info about user aatributes
                2. Display queried domain controller name
                3. Display all groups path-chains 
                 
            This function takes a user's SamAccountName and analyzes all of their group memberships, including nested groups. 
            It checks if any of these groups are members of a predefined list of high-privilege administrative groups. 
            If such a path is found, it indicates that the user has administrative rights through group nesting (i.e., is a "shadow admin"). 
            The script will display the full inheritance chain for each path found.

        .PARAMETER SamAccountName
            The mandatory parameter SamAccountName of the user you want to audit for shadow admin permissions. 
 
        .EXAMPLE
            Get-ShadowAdmin-Analysis -SamAccountName jdoe

        .NOTES
            Prerequisites: This script requires the Active Directory module for PowerShell. 
                If you don't have, you can install it via "Remote Server Administration Tools" (RSAT).
            
            Privileged Groups List: The list of privileged groups is defined within the script. 
                You can modify this list to fit your organization's specific security policies. 
                The default list covers common high-privilege groups across Microsoft Windows infrastructure.

            Version: 0.1.0
            Author: M. Zaikin
            Date: 23-Jul-2025


            [-------------------------------------DISCLAIMER-------------------------------------]
            All script are provided as-is with no implicit
            warranty or support. It's always considered a best practice
            to test scripts in a DEV/TEST environment, before running them
            in production. In other words, I will not be held accountable
            if one of my scripts is responsible for an RGE (Resume Generating Event).
            If you have questions or issues, please reach out/report them on
            my GitHub page. Thanks for your support!
            [-------------------------------------DISCLAIMER-------------------------------------]
    #>
    [CmdletBinding(DefaultParameterSetName = 'Default')]
    param (
        [Parameter(Mandatory, Position = 0)][string]$SamAccountName
    )

    BEGIN {
        # Define the list of high-privilege groups.
        $PrivilegedGroups = @(
            # Core AD Groups
            'Administrators',
            'Domain Admins',
            'Enterprise Admins',
            'Schema Admins',
            'Server Operators',
            'Backup Operators',
            'Account Operators',
            'Print Operators', 
            'DNSAdmins',
            'list_your_AD_specific_priv_groups...'
            )

        function Find-NestingPath {
            param (
                [string]$CurrentGroupDN,
                [array]$PathSoFar,
                [hashtable]$VisitedGroups
            )

            if ($VisitedGroups.ContainsKey($CurrentGroupDN)) {
                return
            }
            $VisitedGroups[$CurrentGroupDN] = $true

            try {
                $currentGroup = Get-ADGroup -Identity $CurrentGroupDN -Properties MemberOf
                $currentPath = $PathSoFar + $currentGroup.Name

                if ($PrivilegedGroups -contains $currentGroup.Name) {
                    $script:ShadowPaths = $ShadowPaths + 1
                    Write-Host ("    * $SamAccountName -> " + ($currentPath -join ' -> ')) -ForegroundColor Red
                } else {
                    Write-Host ("    $SamAccountName -> " + ($currentPath -join ' -> ')) -ForegroundColor Gray
                }

                foreach ($parentGroupDN in $currentGroup.MemberOf) {
                    Find-NestingPath -CurrentGroupDN $parentGroupDN -PathSoFar $currentPath -VisitedGroups $VisitedGroups
                }
            } catch {
                Write-Warning "Could not process group: $CurrentGroupDN. Error: $($_.Exception.Message)"
            }
        }

        $script:ShadowPaths = 0
    }

    PROCESS {
        try {
            Write-Host "Searching for user '$SamAccountName'..." -ForegroundColor Gray
            $user = Get-ADUser -Identity $SamAccountName -Properties MemberOf, DisplayName, Description, Mail, Enabled, LockedOut, AccountExpirationDate, accountExpires, AccountLockoutTime, extensionAttribute7, Manager, DistinguishedName, SID, LastLogonDate

            if (-not $user) {
                Write-Error "User '$SamAccountName' not found."
                return
            }
        } catch {
            Write-Error "Error while finding user '$SamAccountName'. $_"
            return
        }

        $domainController = (Get-ADDomainController).Name
        $directGroups = $user.MemberOf
        $script:directGroupNames = @()
        $totalGroups = $directGroups.Count
        $processedCount = 0

        Write-Host "Found user: $($user.DisplayName). Analyzing $totalGroups groups..."

        foreach ($groupDN in $directGroups) {
            $processedCount++
            $groupName = (Get-ADGroup -Identity $groupDN).Name
            $script:directGroupNames += $groupName

            Write-Progress -Activity "Analyzing Group Nesting" -Status "$groupName ..." -PercentComplete (($processedCount / $totalGroups) * 100)

            Find-NestingPath -CurrentGroupDN $groupDN -PathSoFar @() -VisitedGroups @{}
        }

        Write-Progress -Activity "Analysis complete." -Completed
    }

    END {
        Write-Host "`n-------------------------------------------------------------------" -ForegroundColor Green
        Write-Host "Security Analysis Report for User: $SamAccountName" -ForegroundColor White
        Write-Host "Report Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor White
        Write-Host "SID: $($user.SID)" -ForegroundColor White
        Write-Host "DC Queried: $domainController" -ForegroundColor White
        Write-Host "DN: $($user.DistinguishedName)" -ForegroundColor White
        Write-Host ""
        Write-Host "  Display Name: $($user.DisplayName)" -ForegroundColor White
        Write-Host "  User Type: $($user.extensionAttribute7)" -ForegroundColor White
        Write-Host "  Manager: $($user.Manager)" -ForegroundColor White
        Write-Host "  Last Logon: $($user.LastLogonDate)" -ForegroundColor White
        Write-Host "  AccountExpirationDate: $($user.AccountExpirationDate)" -ForegroundColor White
        Write-Host "  LockedOut: $($user.LockedOut)" -ForegroundColor White
        Write-Host "  Enabled: $($user.Enabled)" -ForegroundColor White
        Write-Host "  Description: $($user.Description)" -ForegroundColor White
        Write-Host "  Mail: $($user.Mail)" -ForegroundColor White        
 
        Write-Host "`n[+] Summary:" -ForegroundColor Yellow
        Write-Host "  Total Direct Groups: $($script:directGroupNames.Count)" -ForegroundColor White
        if ($script:directGroupNames.Count -gt 0) {
            $script:directGroupNames | ForEach-Object { Write-Host "  - $_" -ForegroundColor Gray}
        } else {
            Write-Host "  - None"
        }

        Write-Host "`n[+] Shadow Administrator Path Analysis:" -ForegroundColor Yellow

        if ($script:ShadowPaths -gt 0) {
            Write-Host "  WARNING: Found $($script:ShadowPaths) path(s)!" -ForegroundColor Red           
        } else {
            Write-Host "  OK: No privileged paths found." -ForegroundColor Green
        }

        Write-Host "`n-------------------------- End of Report ---------------------------" -ForegroundColor Green
    } # END block
}  # End of function Find-ShadowAdmin
