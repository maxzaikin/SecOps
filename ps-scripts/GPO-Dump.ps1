Add-Type -AssemblyName System.DirectoryServices
Add-Type -AssemblyName System.DirectoryServices.AccountManagement

Function GPO-Dump
{
    <#
        .SYNOPSIS
            Extracts Group Policy Object (GPO) information? prepare it for further review and exports to a CSV file.
                  
        .PARAMETER csvPath
            The file path where the GPO data will be exported in CSV format.
        
        .PARAMETER xmlPath
            The file path where the GPO report in XML format will be stored.
        
        .EXAMPLE
            GPO-Dump -csvPath "C:\GPO_Dump.csv" -xmlPath "C:\Temp\GPO_Report.xml"
                    
        .LINK
            https://github.com/maxzaikin/Practical-RBAC
            
        .NOTES
            1. This function retrieves all GPOs, extracts relevant information, and exports it in CSV format with additional empty fields, prepeared for review process.

            2. If you have follwoing error while running the script
                File GPO-Dump.ps1 cannot be loaded because running scripts is disabled on this system. For more information, see about_Execution_Policies at 
                https:/go.microsoft.com/fwlink/?LinkID=135170.
                    + CategoryInfo          : SecurityError: (:) [], ParentContainsErrorRecordException
                    + FullyQualifiedErrorId : UnauthorizedAccess
                
               solution is following: 
                Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
            
            ---------------------
               Version: 1.0
               Author:  M. Zaikin
               Date:    2025-03-13
            
        [-------------------------------------DISCLAIMER-------------------------------------]
        This script is provided "AS IS" without warranty of any kind, express or implied.
        The author is not responsible for any damages or data loss that may occur as a result of using this script. 
        Thorough testing in a non-production environment is highly recommended before deployment.
        [-------------------------------------DISCLAIMER-------------------------------------]
    #>

    [cmdletbinding()]
    param (
        [parameter(Mandatory = $true, Position = 0)]
        [string]$csvPath,

        [parameter(Mandatory = $true, Position = 1)]
        [string]$xmlPath
    )

    BEGIN {
        # Get all GPOs
        $AllGpos = Get-GPO -All

        # Initialize a hashtable to store GPO data
        $GpoData = @{}
    }
    
    PROCESS {
        try {
            foreach ($g in $AllGpos) {
                [xml]$Gpo = Get-GPOReport -ReportType Xml -Guid $g.Id
                
                # Initialize an array to store linked OUs
                $linkedOUs = @()
                
                # Collect all linked OUs
                foreach ($i in $Gpo.GPO.LinksTo) {
                    $linkedOUs += $i.SOMPath
                }
                
                # Ensure uniqueness
                $linkedOUs = $linkedOUs | Sort-Object -Unique
                
                # Construct GPO data object
                $GpoData[$Gpo.GPO.Name] = [PSCustomObject]@{
                    "gpo_name" = $Gpo.GPO.Name
                    "gpo_description" = " "
                    "is_computer_enabled" = $Gpo.GPO.Computer.Enabled
                    "is_user_enabled" = $Gpo.GPO.User.Enabled
                    "links_count" = $linkedOUs.Count
                    "linked_to" = ($linkedOUs -join "; ")
                    "is_link_enabled" = ($Gpo.GPO.LinksTo | ForEach-Object { $_.Enabled }) -join "; "
                    "gpo_created_time" = [datetime]::ParseExact($Gpo.GPO.CreatedTime, "yyyy-MM-ddTHH:mm:ss", $null)
                    "gpo_modified_time" = [datetime]::ParseExact($Gpo.GPO.ModifiedTime, "yyyy-MM-ddTHH:mm:ss", $null)
                    "is_reviewed" = " "
                    "review_date" = " "
                    "review_action_list" = " "
                    "reviewer" = " "
                }
            }
        }
        catch {
            # Capture any errors that occur
            $message = $_.Exception.Message
            Write-Output "ERROR: $message"
        }
    }
    
    END {
        # Convert hashtable to array and sort by GPO name
        $GpoVersionInfo = $GpoData.Values | Sort-Object -Property gpo_name
        
        # Export data to CSV
        $GpoVersionInfo | Export-Csv -Path $csvPath -Encoding UTF8 -Delimiter "|" -NoTypeInformation
        
        Write-Host "✅ Data successfully exported to: $csvPath" -ForegroundColor Green
    }
}
