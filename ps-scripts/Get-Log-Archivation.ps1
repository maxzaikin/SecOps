Function Get-Log-Archivation {
    <#
        .SYNOPSIS
            Script that archives old log files, and maintain folder hygiene.

        .PARAMETER OldFilesAge
            Filters the files that falls under archiving action based on age criteria

        .PARAMETER OldCabsAge
            Criterion for clean up old arhive files

        .PARAMETER LogFilePath
            The output log file path. It is where all perforemed actions and statuses will be saved
           
        .EXAMPLE
            Get-Log-Archivation -OldFilesAge 0 -OldCabsAge 0 -LogFilePath 'C:\Temp\log.log'   
                Archive all log files whose age is 0 days and delete all all archives older then 0 days. Save log in  C:\Temp\log.log

        .NOTES
            Parameter's desctription
                Paths: list of folders that needs to be monitored for archives

            Version: 1.0
            Author: M. Zaikin
            Date: 12-Dec-2024

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
    [cmdletbinding()]
    param (
        
           [parameter(Mandatory = $true, Position = 0)]
           [int]$OldFilesAge,
        [parameter(Mandatory = $true, Position = 1)]
           [int]$OldCabsAge,
        [parameter(Mandatory = $true, Position = 2)]
           [string]$LogFilePath
    )# param

    BEGIN {
        $Paths= @(
            'C:\Temp\IIS'
        )
        Add-Content -Path $LogFilePath -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') START: Archive process"
    }

    PROCESS {
        try {
            foreach ($Path in $Paths) {
                if (Test-Path $Path) {
                    Add-Content -Path $LogFilePath -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') Processing $($Path)"

                    # Compress and Log
                    Get-ChildItem -Path $Path -Recurse -Filter *.log | Where-Object {$_.LastWriteTime -le (Get-Date).AddDays(-$OldFilesAge)} |
                        ForEach-Object {
                            $CabFile= "$($_.FullName).zip"

                            if (-not (Test-Path $CabFile)) {
                                # Log compress action
                                Add-Content -Path $LogFilePath -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') Compressing $($_.FullName) -> $($CabFile)"

                                # Compress file
                                Compress-Archive -Path $_.FullName -DestinationPath $CabFile -Force
                            }
                        }

                     # Remove source files that being archived
                     Get-ChildItem -Path $Path -Recurse -Filter *.log | Where-Object {$_.LastWriteTime -lt (Get-Date).AddDays(-$OldFilesAge)} |
                        ForEach-Object {
                            # Log File remove
                            $RemFile= "$($_.FullName)"
                            Add-Content -Path $LogFilePath -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') Remove file $($_.FullName)"
                            Remove-Item -Path $RemFile -Force
                        }                        

                     # Remove old archives
                     Get-ChildItem -Path $Path -Recurse -Filter *.zip | Where-Object {$_.LastWriteTime -lt (Get-Date).AddDays(-$OldCabsAge)} |
                        ForEach-Object {
                            # Log File remove
                            $RemCabFile= "$($_.FullName)"
                            Add-Content -Path $LogFilePath -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') Remove old archive: $($_.FullName). File age less then $($OldCabsAge) days"
                            Remove-Item -Path $RemCabFile -Force
                        }

                } else {
                    Add-Content -Path $LogFilePath -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') WARNING: Path $($Path) doesn't exist!"
                }
            }            
        }
        catch {
            Write-Error "An error occurred: $_"
            Add-Content -Path $LogFilePath -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') ERROR OCCURED"
        }
    }

    END {
        Add-Content -Path $LogFilePath -Value "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') END: Archive process"
        Add-Content -Path $LogFilePath -Value "--------------------------------------------------------------"
    }
} 
