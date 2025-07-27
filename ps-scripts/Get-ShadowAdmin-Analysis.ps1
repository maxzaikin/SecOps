 
function Get-ShadowAdmin-Analysis {
    <#
        .SYNOPSIS
            Scans Active Directory group memberships recursively to find "shadow administrator" access paths for a specified user.

        .DESCRIPTION
            This function takes a user's SamAccountName and analyzes all of their group memberships, including nested groups. 
            It checks if any of these groups are members of a predefined list of high-privilege administrative groups. 
            If such a path is found, it indicates that the user has administrative rights through group nesting (i.e., is a "shadow admin"). 
            The script will display the full inheritance chain for each path found.

        .PARAMETER SamAccountName
            The mandatory parameter SamAccountName of the user you want to audit for shadow admin permissions. 
 
        .EXAMPLE
            Find-ShadowAdmin -SamAccountName jdoe
                This command will analyze the group membership for the user "jdoe" and report any discovered shadow administrator paths.

        .NOTES
            Prerequisites: This script requires the Active Directory module for PowerShell. 
                If you don't have, you can install it via "Remote Server Administration Tools" (RSAT).
            
            Privileged Groups List: The list of privileged groups is defined within the script. 
                You can modify this list to fit your organization's specific security policies. 
                The default list covers common high-privilege groups across Microsoft Windows infrastructure.

            Version: 1.0
            Author: M. Zaikin
            Date: 15-Jul-2025

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
        [Parameter(Mandatory = $true, Position = 0, HelpMessage = "Enter the user's SamAccountName.")]
        [string]$SamAccountName
    )

    # This script requires the Active Directory module
    #requires -Module ActiveDirectory

    BEGIN {

        # Define the list of high-privilege groups.
        # This list can and should be customized for your environment.
        # Only you as a ruller of your AD realm knows which groups are priviliged
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

        # This helper function will perform the recursive search.
        function Find-NestingPath {
            param (
                [string]$CurrentGroupDN,
                [array]$PathSoFar,
                [hashtable]$VisitedGroups
            )
            
            # If we have already checked this group in this search path, stop to prevent infinite loops.
            if ($VisitedGroups.ContainsKey($CurrentGroupDN)) {
                 Write-Warning "Infinite loop warning: $CurrentGroupDN"
                return
            }
            $VisitedGroups[$CurrentGroupDN] = $true

            try {
                # Get the current group object and its properties
                $currentGroup = Get-ADGroup -Identity $CurrentGroupDN -Properties MemberOf
                $currentPath = $PathSoFar + $currentGroup.Name
                
                # BASE CASE: Check if the current group is in our privileged list
                if ($PrivilegedGroups -contains $currentGroup.Name) {

                    # Found a path! Add it to the global results array.
                    $script:AllFoundPaths += $currentPath -join ' -> '
                    return # No need to check further up this branch
                }

                # RECURSIVE STEP: If the group has parent groups, check each one
                if ($currentGroup.MemberOf) {
                    foreach ($parentGroupDN in $currentGroup.MemberOf) {
                        Find-NestingPath -CurrentGroupDN $parentGroupDN -PathSoFar $currentPath -VisitedGroups $VisitedGroups
                    }
                }
            }
            catch {
                Write-Warning "Could not process group with DN: $CurrentGroupDN. It might be in a different domain or has been deleted. Error: $($_.Exception.Message)"
            }
        }

        # Initialize an array to store the final shadow admin paths.
        # Using script scope so the helper function can access it.
        $script:AllFoundPaths = @()
    }

    PROCESS {
        try {
            # Find the user and get their direct group memberships
            Write-Host "Searching for user '$SamAccountName'..." -ForegroundColor Gray
            $user = Get-ADUser -Identity $SamAccountName -Properties MemberOf, DisplayName
            if (-not $user) {
                Write-Error "User '$SamAccountName' not found in Active Directory."
                return
            }
        }
        catch {
            Write-Error "An error occurred while trying to find user '$SamAccountName'. Please ensure the user exists and the Active Directory module is available. Error: $_"
            return
        }

        $directGroups = $user.MemberOf
        $script:directGroupNames = @()
        $totalGroups = $directGroups.Count
        $processedCount = 0

        Write-Host "Found user: $($user.DisplayName). Analyzing $($totalGroups) direct group memberships..."

        # Iterate through each group the user is a direct member of
        foreach ($groupDN in $directGroups) {
            $processedCount++
            $groupName = (Get-ADGroup -Identity $groupDN).Name
            $script:directGroupNames += $groupName
            
            # Update the progress bar
            Write-Progress -Activity "Analyzing Group Nesting for '$($user.DisplayName)'" -Status "Checking Path: $groupName -> ..." -PercentComplete (($processedCount / $totalGroups) * 100)
            
            # Start the recursive search for each direct group
            # A new hashtable for visited groups is created for each top-level branch search
            Find-NestingPath -CurrentGroupDN $groupDN -PathSoFar @() -VisitedGroups @{}
        }
        Write-Progress -Activity "Analysis complete." -Completed
    }

    END {
        # Display the final report
        Write-Host "`n--------------------------------------------------------------" -ForegroundColor Green
        Write-Host "Shadow Administrator Analysis Report for User: $($SamAccountName)" -ForegroundColor White
        Write-Host "--------------------------------------------------------------" -ForegroundColor Green
        
        # List the user's direct groups
        Write-Host "`n[+] User is a direct member of the following groups:" -ForegroundColor Yellow
        if ($script:directGroupNames.Count -gt 0) {
            $script:directGroupNames | ForEach-Object { Write-Host "  - $_" }
        } else {
            Write-Host "  - This user is not a direct member of any groups."
        }

        Write-Host "`n[+] Shadow Administrator Path Analysis:" -ForegroundColor Yellow
        if ($script:AllFoundPaths.Count -gt 0) {
            Write-Host "  WARNING: Found $($script:AllFoundPaths.Count) potential shadow administrator path(s)!" -ForegroundColor Red
            Write-Host "  The user '$SamAccountName' inherits high privileges through the following chains:" -ForegroundColor Red
            
            # Display each found path, prepending the user's name to the chain
            $script:AllFoundPaths | ForEach-Object {
                Write-Host "    * $SamAccountName -> $_"
            }
        }
        else {
            Write-Host "  OK: No shadow administrator paths were found for this user based on the defined privileged groups." -ForegroundColor Green
        }

        Write-Host "`n-------------------------- End of Report ---------------------------`n" -ForegroundColor Green
   } # END block
    
} # End of function Find-ShadowAdmin