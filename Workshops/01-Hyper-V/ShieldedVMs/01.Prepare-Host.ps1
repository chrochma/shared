Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Force -Confirm:$false

Set-ItemProperty -Path "HKCU:\Software\Microsoft\ServerManager" -Name DoNotOpenAtLogon -Value 1        
    $Result=Install-WindowsFeature -Name "Hyper-V" -ErrorAction SilentlyContinue
    if ($result.ExitCode -eq "failed"){
        Enable-WindowsOptionalFeature -FeatureName Microsoft-Hyper-V -Online -NoRestart 
    }
    Write-Host "Hyper-V Feature installed" -ForegroundColor Cyan
    
    Install-WindowsFeature -Name "Hyper-V-PowerShell","System-Insights","RSAT-System-Insights","Hyper-V-Tools" -IncludeManagementTools -IncludeAllSubFeature
    Write-Host "Additional Features installed" -ForegroundColor Cyan
    
    Set-TimeZone -Id "W. Europe Standard Time"
    Write-Host "Timezone set to W. Europe Standard Time" -ForegroundColor Cyan
  
    get-disk | Where-Object PartitionStyle -like RAW | Initialize-Disk -PartitionStyle GPT | New-Partition -UseMaximumSize -AssignDriveLetter

    $disks = get-disk | Where-Object Size -gt 1000000000000 
    foreach($Disk in $Disks){
        $Disk | New-Partition -UseMaximumSize -AssignDriveLetter | Format-Volume -FileSystem NTFS -AllocationUnitSize 65536 -NewFileSystemLabel "DATA" -Confirm:$false 
    }
  
    New-ItemProperty -Path HKCU:\Software\Microsoft\ServerManager -Name DoNotOpenServerManagerAtLogon -PropertyType DWORD -Value "0x1" -Force

    Write-Host "Pre Installation succeeded, press any key to restart." -ForegroundColor Cyan
    Pause
    Restart-Computer -Force -Confirm:$false