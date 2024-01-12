# 1. Initial Configuration per Hyper-V Host
# --------------------------------------
# Get the ID and security principal of the current user account
$myWindowsID=[System.Security.Principal.WindowsIdentity]::GetCurrent()
$myWindowsPrincipal=new-object System.Security.Principal.WindowsPrincipal($myWindowsID)
 
# Get the security principal for the Administrator role
$adminRole=[System.Security.Principal.WindowsBuiltInRole]::Administrator
 
# Check to see if we are currently running "as Administrator"
if ($myWindowsPrincipal.IsInRole($adminRole))
   {
   # We are running "as Administrator" - so change the title and background color to indicate this
   $Host.UI.RawUI.WindowTitle = $myInvocation.MyCommand.Definition + "(Elevated)"
   $Host.UI.RawUI.BackgroundColor = "DarkBlue"
   clear-host
   }
else
   {
   # We are not running "as Administrator" - so relaunch as administrator
   
   # Create a new process object that starts PowerShell
   $newProcess = new-object System.Diagnostics.ProcessStartInfo "PowerShell";
   
   # Specify the current script path and name as a parameter
   $newProcess.Arguments = $myInvocation.MyCommand.Definition;
   
   # Indicate that the process should be elevated
   $newProcess.Verb = "runas";
   
   # Start the new process
   [System.Diagnostics.Process]::Start($newProcess);
   
   # Exit from the current, unelevated, process
   exit
   }

# CONTINUE AS ADMIN

if(Test-Path 'HKLM:\Software\Autoconf')
{
Set-Location C:\temp\Staging
$nextstep = (Get-ItemProperty -Path 'HKLM:\Software\Autoconf' -Name "(default)")."(default)"

# START


if($nextstep -eq "01-InitialSetup")
    {
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\ServerManager" -Name DoNotOpenAtLogon -Value 1        
    if(Test-Path $Loglocation) {
        Write-Host "Loglocation $Loglocation exists" -ForegroundColor Cyan
    } else {
        Write-Host "Loglocation $Loglocation does not exist, creating it" -ForegroundColor Cyan
        New-Item -Path $Loglocation -ItemType Directory
    }
    $Date = Get-Date -Format "dd.MM.yyyy hh:mm:ss"
    "Starting Initial Configuration of $Computername, $Date" | Out-File -FilePath $Loglocation\InitialConfiguration.log -Append

    $Result=Install-WindowsFeature -Name "Hyper-V" -ErrorAction SilentlyContinue
    if ($result.ExitCode -eq "failed"){
        Enable-WindowsOptionalFeature -FeatureName Microsoft-Hyper-V -Online -NoRestart 
    }
    Write-Host "Hyper-V Feature installed" -ForegroundColor Cyan
    "Hyper-V Feature installed" | Out-File -FilePath $Loglocation\InitialConfiguration.log -Append

    Install-WindowsFeature -Name "Hyper-V-PowerShell","System-Insights","RSAT-System-Insights" -IncludeManagementTools
    Write-Host "Additional Features installed" -ForegroundColor Cyan
    "Additional Features installed" | Out-File -FilePath $Loglocation\InitialConfiguration.log -Append

    Set-TimeZone -Id "W. Europe Standard Time"
    Write-Host "Timezone set to W. Europe Standard Time" -ForegroundColor Cyan
    "Timezone set to W. Europe Standard Time" | Out-File -FilePath $Loglocation\InitialConfiguration.log -Append

    "Restarting Computer" | Out-File -FilePath $Loglocation\InitialConfiguration.log -Append

    get-disk | Where-Object PartitionStyle -like RAW | Initialize-Disk -PartitionStyle GPT | New-Partition -UseMaximumSize -AssignDriveLetter

    $disks = get-disk | Where-Object Size -gt 1000000000000 
    foreach($Disk in $Disks){
        $Disk | New-Partition -UseMaximumSize -AssignDriveLetter | Format-Volume -FileSystem NTFS -AllocationUnitSize 65536 -NewFileSystemLabel "DATA" -Confirm:$false 
    }


    Remove-Item -Path HKLM:\Software\Autoconf -Force -Confirm:$false
    New-Item -Path HKLM:\Software -Name Autoconf -Force
    New-Item -Path HKLM:\Software\Autoconf -Value "02-Networking" -Force
    Restart-Computer -Confirm:$false -Force
}

if($nextstep -eq "02-Networking"){ 
    # Retry Multiple times to install Updates
    $Searcher = New-Object -ComObject Microsoft.Update.Searcher
    $SearchCriteriaAllUpdates = "IsInstalled=0 and DeploymentAction='Installation' or
                                        IsInstalled=0 and DeploymentAction='OptionalInstallation' or
                                        IsPresent=1 and DeploymentAction='Uninstallation' or
                                        IsInstalled=1 and DeploymentAction='Installation' and RebootRequired=1 or
                                        IsInstalled=0 and DeploymentAction='Uninstallation' and RebootRequired=1"
    $SearchResult = $Searcher.Search($SearchCriteriaAllUpdates).Updates
    if ($SearchResult.Count -gt 0){
        $Session = New-Object -ComObject Microsoft.Update.Session
        $Downloader = $Session.CreateUpdateDownloader()
        $Downloader.Updates = $SearchResult
        $Downloader.Download()
        $Installer = New-Object -ComObject Microsoft.Update.Installer
        $Installer.Updates = $SearchResult
        $Result = $Installer.Install()
        $Result
    }

    Remove-Item -Path HKLM:\Software\Autoconf -Force -Confirm:$false
    New-Item -Path HKLM:\Software -Name Autoconf -Force
    New-Item -Path HKLM:\Software\Autoconf -Value "03-Updates" -Force
    Restart-Computer -Confirm:$false -Force
}

if((Get-ItemProperty -Path 'HKLM:\Software\Autoconf\RestartCount' -Name "(default)" -ErrorAction SilentlyContinue)."(default)" -gt 10){
    Remove-Item -Path HKLM:\Software\Autoconf -Force -Confirm:$false
    New-Item -Path HKLM:\Software -Name Autoconf -Force
    New-Item -Path HKLM:\Software\Autoconf -Value "Cancel" -Force
    Restart-Computer -Confirm:$false -Force
}

if($nextstep -eq "03-Updates"){
    Write-Host "Installing Windows Updates, that can take a while" -ForegroundColor Cyan
    $Searcher = New-Object -ComObject Microsoft.Update.Searcher
    $SearchCriteriaAllUpdates = "IsInstalled=0 and DeploymentAction='Installation' or
                                        IsInstalled=0 and DeploymentAction='OptionalInstallation' or
                                        IsPresent=1 and DeploymentAction='Uninstallation' or
                                        IsInstalled=1 and DeploymentAction='Installation' and RebootRequired=1 or
                                        IsInstalled=0 and DeploymentAction='Uninstallation' and RebootRequired=1"
    $SearchResult = $Searcher.Search($SearchCriteriaAllUpdates).Updates

    if($SearchResult.Count -gt 0){
        $Session = New-Object -ComObject Microsoft.Update.Session
        $Downloader = $Session.CreateUpdateDownloader()
        $Downloader.Updates = $SearchResult
        $Downloader.Download()
        $Installer = New-Object -ComObject Microsoft.Update.Installer
        $Installer.Updates = $SearchResult
        $Result = $Installer.Install()
        $Result
        if(!(Test-Path 'HKLM:\Software\Autoconf\RestartCount')){
            Set-Location C:\temp\Staging
            New-Item -Path HKLM:\Software\Autoconf\RestartCount -Value "1" -Force
        }else{
            [int32]$RestartCount = (Get-ItemProperty -Path 'HKLM:\Software\Autoconf\RestartCount' -Name "(default)")."(default)"
            $RestartCount = $RestartCount +1
            Remove-Item -Path HKLM:\Software\Autoconf\RestartCount -Force -Confirm:$false
            New-Item -Path HKLM:\Software\Autoconf\RestartCount -Value $RestartCount -Force
        }
    }else {
        Remove-Item -Path HKLM:\Software\Autoconf\RestartCount -Force -Confirm:$false
        Remove-Item -Path HKLM:\Software\Autoconf -Force -Confirm:$false
        New-Item -Path HKLM:\Software -Name Autoconf -Force
        New-Item -Path HKLM:\Software\Autoconf -Value "04-SetupVM-Images" -Force
        Restart-Computer -Confirm:$false -Force
    }
    Restart-Computer -Confirm:$false -Force
}

if($nextstep -eq "04-SetupVM-Images"){
    ﻿$Products=@()
$Products+=@{Product="Azure Stack HCI 21H2 and Windows Server 2022" ;SearchString="Cumulative Update for Microsoft server operating system version 21H2 for x64-based Systems" ;SSUSearchString="Servicing Stack Update for Microsoft server operating system version 21H2 for x64-based Systems" ; ID="Microsoft Server operating system-21H2" ; FolderID="WS2022"}

if(Test-path hklm:software\RMLab\Templates\Updates)
{
    $folder = (Get-ItemProperty -Path hklm:software\RMLab\Templates\Updates -Name "Path").Path
}
else
{
    do {
        $folder="C:\temp"
        if(Test-Path $folder)
        {
            New-Item -Path hklm:software -Name RMLab #-ErrorAction SilentlyContinue
            New-Item -Path hklm:software\RMLab -Name Templates #-ErrorAction SilentlyContinue
            New-Item -Path hklm:software\RMLab\Templates -Name Updates #-ErrorAction SilentlyContinue
            Set-ItemProperty -Path hklm:software\RMLab\Templates\Updates -Name "Path" -Value $folder
        }
        else
        {
            Write-Host "The Path $folder is not valid"
        }
    } until (Test-path hklm:software\RMLab\Templates\Updates)
    
}
if(!$folder){$folder=$PSScriptRoot}

$preview=$false

#let user choose products
$SelectedProducts= $Products.Product

#region download MSCatalog module
Write-Output "Checking if MSCatalog PS Module is Installed"
if (!(Get-InstalledModule -Name MSCatalog -ErrorAction Ignore)){
    # Verify Running as Admin
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
    If (!( $isAdmin )) {
        Write-Host "-- Restarting as Administrator to install Modules" -ForegroundColor Cyan ; Start-Sleep -Seconds 1
        Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs 
        exit
    }
    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
    Install-Module -Name MSCatalog -Force
}

#endregion

#region download products
Foreach($SelectedProduct in $SelectedProducts){
    $item=$Products | Where-Object product -eq $SelectedProduct
    #Download SSU
    $update=Get-MSCatalogUpdate -Search "Cumulative Update for Microsoft server operating system version 21H2 for x64-based Systems" | Select-Object -First 1
    $FolderItem = $item.FolderID
    $DestinationFolder="$folder\$FolderItem\$($update.title.Substring(0,7))"
    $UpdatePattern = $DestinationFolder -replace '^.*(?=.{7}$)'
       
    if(Test-Path $destinationFolder){
    }else {
        New-Item -Path $DestinationFolder -ItemType Directory -ErrorAction Ignore | Out-Null
        Write-Output "Downloading $($update.title) to $destinationFolder"
        Write-Host $update
        $update | Save-MSCatalogUpdate -Destination "$DestinationFolder" #-UseBits
        
        $update=Get-MSCatalogUpdate -Search $item.SSUSearchString | Where-Object Products -eq $item.ID | Select-Object -First 1
        if ($update){
            Write-Output "Downloading $($update.title) to $destinationFolder"
            Write-Host $update
            $update | Save-MSCatalogUpdate -Destination $DestinationFolder #-UseBits
        }

    }
}
#endregion
    #Parameters
    #VHD size
    $size=60GB
    $OSVersions = "WS2022"

    #region Functions
    $RunTimeDate = get-date -Format "ddMMyyyy"
    function Out-Date{
        $Date = Get-Date -Format "dd.MM.yyyy hh:mm:ss"
        return $Date
    }
    function Out-Log($message){
        $LogRoot = (Get-ItemProperty -Path hklm:software\RMLab\Templates\Updates -Name "Path").Path
        if (Test-Path $LogRoot\Logs) {}else{New-Item -Path $LogRoot -ItemType Directory -Name Logs }
        $message | Out-File -FilePath "$LogRoot\Logs\$RunTimeDate-VHDXTemplate.txt" -Append
    }
    function WriteInfo($message){
        $curTime = Out-Date
        $message = "$curTime |   INFO   | $message"
        Out-Log $message
        Write-Host $message
    }

    function WriteInfoHighlighted($message){
        $curTime = Out-Date
        $message = "$curTime |   INFO   | $message"
        Out-Log $message
        Write-Host $message -ForegroundColor Cyan
    }

    function WriteSuccess($message){
        $curTime = Out-Date
        $message = "$curTime | SUCCESS  | $message"
        Out-Log $message
        Write-Host $message -ForegroundColor Green
    }

    function WriteError($message){
        $curTime = Out-Date
        $message = "$curTime |  ERROR   | $message"
        Out-Log $message
        Write-Host $message -ForegroundColor Red
    }

    function WriteErrorAndExit($message){
        $curTime = Out-Date
        $message = "$curTime | CRITICAL | $message"
        Out-Log $message
        Write-Host $message -ForegroundColor Red
        Exit
    }

  # Verify Running as Admin
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
    If (!( $isAdmin )) {
        Write-Host "-- Restarting as Administrator" -ForegroundColor Cyan ; Start-Sleep -Seconds 1
        Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs 
        exit
    }

    If ((Get-ExecutionPolicy) -ne "RemoteSigned"){
        Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process
    }
        #region download convert-windowsimage if needed and load it
        
        if (!(Test-Path "$PSScriptRoot\convert-windowsimage.ps1")){
            WriteInfo "`t Downloading Convert-WindowsImage"
            try{
                Invoke-WebRequest -UseBasicParsing -Uri https://raw.githubusercontent.com/MicrosoftDocs/Virtualization-Documentation/live/hyperv-tools/Convert-WindowsImage/Convert-WindowsImage.ps1 -OutFile "$PSScriptRoot\convert-windowsimage.ps1"
            }catch{
                WriteErrorAndExit "`t Failed to download convert-windowsimage.ps1!"
            }
        }

        #load convert-windowsimage
        . "$PSScriptRoot\convert-windowsimage.ps1"

    #endregion

    #region Ask for ISO
    #grab folder to download to
    foreach($OSVersion in $OSVersions){
        if(Test-path hklm:software\RMLab\Templates\$OSVersion)
        {
            $openfile = (Get-ItemProperty -Path hklm:software\RMLab\Templates\$OSVersion -Name "Path").Path
        }
        else
        {
            WriteInfoHighlighted "Please select ISO image"
            [reflection.assembly]::loadwithpartialname("System.Windows.Forms")
            $OSName = "Windows Server 2022"
            Start-BitsTransfer -Source "https://go.microsoft.com/fwlink/p/?LinkID=2195280&clcid=0x409&culture=en-us&country=US" -Destination C:\Temp\win2022.iso
            New-Item -Path hklm:software -Name RMLab -ErrorAction SilentlyContinue
            New-Item -Path hklm:software\RMLab -Name Templates -ErrorAction SilentlyContinue
            New-Item -Path hklm:software\RMLab\Templates -Name $OSVersion -ErrorAction SilentlyContinue
            Set-ItemProperty -Path hklm:software\RMLab\Templates\$OSVersion -Name "Path" -Value "C:\Temp\win2022.iso"

        }
    }
        
    foreach($OSVersion in $OSVersions){
        $openfile = (Get-ItemProperty -Path hklm:software\RMLab\Templates\$OSVersion -Name "Path").Path
        $UpdateFolder = (Get-ItemProperty -Path hklm:software\RMLab\Templates\Updates -Name "Path").Path
        $LatestMSU = (Get-Item -Path $UpdateFolder\$OSVersion\* | Sort-Object -Property LastWriteTime -Descending | select -First 1).Name

        #VHD imagename
        switch ($OSVersion) {
        "WS2022" { $vhdname = "WS2022-$LatestMSU-G2.vhdx";$TemplateName = "WIN2022-G2";$KMSKey = "W3GNR-8DDXR-2TFRP-H8P33-DV9BG" }
        Default {$vhdname="WIN.vhdx"}
        }
        WriteInfo "$vhdname | Size: $size | setup started"
                
        if(Test-Path $UpdateFolder\$OSVersion\$LatestMSU\*.vhdx){
            WriteInfo "$vhdname is already existing"
            if((Get-Item $UpdateFolder\$OSVersion\*).count -gt 1){
                Get-Item $UpdateFolder\$OSVersion\* | Select-Object -First 1 | Remove-Item -Force -Confirm:$False
            }
            $VHDxs = (Get-Item $UpdateFolder\$OSVersion\$LatestMSU\*).Count
            if($VHDxs -gt 1){
                #Get-Item $UpdateFolder\$OSVersion\$LatestMSU\* | Select-Object -Last 1 | Remove-Item -Force -Confirm:$False
            }
            $VHDxs = (Get-Item $UpdateFolder\$OSVersion\$LatestMSU\*.vhdx).Count
        }else{
            $VHDxs = (Get-Item $UpdateFolder\$OSVersion\$LatestMSU\*).Count
            if($VHDxs -gt 1){
                #Get-Item $UpdateFolder\$OSVersion\$LatestMSU\* | Select-Object -Last 1 | Remove-Item -Force -Confirm:$False
            }
            $ISO = Mount-DiskImage -ImagePath $openFile -PassThru
            $ISOMediaPath = (Get-Volume -DiskImage $ISO).DriveLetter+':'
        }

        #region ask for MSU packages
            if(Test-Path $UpdateFolder\$OSVersion)
            {
                $msupackages = Get-Item -Path $UpdateFolder\$OSVersion\$LatestMSU\*.msu
                WriteInfoHighlighted  "Following patches selected:"
                foreach ($filename in $msupackages.Name){
                    WriteInfo "`t $filename"
                }
            }
    
            #Write info if nothing is selected
            if (!$msupackages.Name){
                WriteInfoHighlighted "No msu was selected..."
            }
    
            #sort packages by size (to apply Servicing Stack Update first)
            if ($msupackages.Name){
                $files=@()
                foreach ($Filename in $msupackages.Name){$files+=Get-ChildItem -Path $UpdateFolder\$OSVersion\$LatestMSU\$filename}
                $packages=($files |Sort-Object -Property Length).Fullname
            }
    
        #endregion
        #region do the job
            if(Test-Path $UpdateFolder\$OSVersion\$LatestMSU\$vhdname){
            WriteInfo "$vhdname is already existing"
                <#$VHDxs = (Get-Item $UpdateFolder\$OSVersion\$LatestMSU\*).Count
                if($VHDxs -gt 1){
                    Get-Item $UpdateFolder\$OSVersion\$LatestMSU\* | Select-Object -Last 1 | Remove-Item -Force -Confirm:$False
                }#>
            }else{
            if(Test-Path $UpdateFolder\$OSVersion\$LatestMSU\*.vhdx){
                $VHDXss = Get-Item "$UpdateFolder\$OSVersion\$LatestMSU\*.vhdx"
                foreach($VHDX in $VHDXss){
                    $VHDxsName = $VHDX.Name
                    if($VHDxsName -eq $vhdname){
                    }else{
                        Remove-Item $UpdateFolder\$OSVersion\$LatestMSU\$VHDxsName -Force -Confirm:$False
                    }
                }
            }
              $BuildNumber=(Get-ItemProperty -Path "$ISOMediaPath\setup.exe").versioninfo.FileBuildPart
    
            $WindowsImage=Get-WindowsImage -ImagePath "$ISOMediaPath\sources\install.wim"

            if ($BuildNumber -lt 7600){
                if ($ISO -ne $Null){
                    $ISO | Dismount-DiskImage
                }
                WriteErrorAndExit "`t Use Windows 7 or newer!"
            }
            #ask for edition
            if($OSVersion -like "AZ*"){
                $Edition=($WindowsImage | Where-Object ImageIndex -eq "1").ImageName
            }else{
                $Edition=($WindowsImage | Where-Object ImageIndex -eq "4").ImageName
            }
            if (-not ($Edition)){
                $ISO | Dismount-DiskImage
                WriteErrorAndExit "Edition not selected. Exitting "
            }
    
        #Create VHD
            if ($packages){
                if ($BuildNumber -le 7601){
                    Convert-WindowsImage -SourcePath "$ISOMediaPath\sources\install.wim" -Edition $Edition -VHDPath "$UpdateFolder\$OSVersion\$LatestMSU\$vhdname" -SizeBytes $size -VHDFormat VHDX -DiskLayout BIOS -Package $packages
                    If(Test-Path "$UpdateFolder\$OSVersion\$LatestMSU\$vhdname"){WriteSuccess -message "$vhdname created successfully"}else{WriteError -message "$vhdname creation failed"}
                }else{
                    Convert-WindowsImage -SourcePath "$ISOMediaPath\sources\install.wim" -Edition $Edition -VHDPath "$UpdateFolder\$OSVersion\$LatestMSU\$vhdname" -SizeBytes $size -VHDFormat VHDX -DiskLayout UEFI -Package $packages
                    If(Test-Path "$UpdateFolder\$OSVersion\$LatestMSU\$vhdname"){WriteSuccess -message "$vhdname created successfully"}else{WriteError -message "$vhdname creation failed"}
                }
            }else{
                if ($BuildNumber -le 7601){
                    Convert-WindowsImage -SourcePath "$ISOMediaPath\sources\install.wim" -Edition $Edition -VHDPath "$UpdateFolder\$OSVersion\$LatestMSU\$vhdname" -SizeBytes $size -VHDFormat VHDX -DiskLayout BIOS
                    If(Test-Path "$UpdateFolder\$OSVersion\$LatestMSU\$vhdname"){WriteSuccess -message "$vhdname created successfully"}else{WriteError -message "$vhdname creation failed"}
                }else{
                    Convert-WindowsImage -SourcePath "$ISOMediaPath\sources\install.wim" -Edition $Edition -VHDPath "$UpdateFolder\$OSVersion\$LatestMSU\$vhdname" -SizeBytes $size -VHDFormat VHDX -DiskLayout UEFI
                    If(Test-Path "$UpdateFolder\$OSVersion\$LatestMSU\$vhdname"){WriteSuccess -message "$vhdname created successfully"}else{WriteError -message "$vhdname creation failed"}
                }
            }
            
            WriteInfo "Dismounting ISO Image"
            if ($ISO -ne $Null){
            $ISO | Dismount-DiskImage
            WriteInfo "$OSVersion is finished"
            }

            #
            # Copy VHD to VMM Library
            #

            if(Test-Connection $LibraryServer){
                if(Test-Path "$LibraryPath\$vhdname"){
                WriteInfo "$vhdname is already existing"
                }else{
                WriteInfo -message "Copy $vhdname to $LibraryPath"
                if(Test-Path $LibraryPath){
                    Copy-Item -Path "$UpdateFolder\$OSVersion\$LatestMSU\$vhdname" -Destination "$LibraryPath" 
                }else{
                    New-Item -Path $LibraryPath -ItemType Directory
                    WriteInfo -message "The folder $LibraryPath has been created"
                    Copy-Item -Path "$UpdateFolder\$OSVersion\$LatestMSU\$vhdname" -Destination "$LibraryPath"
                }
                if(Test-Path "$LibraryPath\$vhdname"){
                    WriteInfo -message "$vhdname was succesfully copied to $LibraryPath"
                }else{
                    WriteError -message "$vhdname could not be copied to $LibraryPath"
                } 
            }
         }
      }            
    }
#endregion

    Remove-Item -Path HKLM:\Software\Autoconf -Force -Confirm:$false
    New-Item -Path HKLM:\Software -Name Autoconf -Force
    New-Item -Path HKLM:\Software\Autoconf -Value "finalize" -Force
    Restart-Computer -Confirm:$false -Force
}

##############################################################################################################################################################
#------------------------------------------------------------------------------------------------------------------------------------------------------CLEANUP
##############################################################################################################################################################

if($nextstep -eq "stopinst")
    {
        powershell.exe -ScriptBlock "Write-Host 'Stopping Installation, an error occured, please check Logs' -ForegroundColor Red; Pause"
    }
	
if($nextstep -eq "finalize")
    {
   	$produkt = "Final Step"
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "AutoAdminLogon" -Force
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "DefaultUserName" -Force
    Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "DefaultPassword" -Force
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name EnableLUA -Value 1		
	Remove-Item -Path HKLM:\Software\Autoconf -Force -Confirm:$false
	Unregister-ScheduledTask -TaskName "AutoConfigScedular" -Confirm:$false -Verbose
	Disable-LocalUser -Name hvstaging
    Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Force -Confirm:$false
    [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")
    [System.Windows.Forms.MessageBox]::Show("Configuration completed!")
    pause
    Restart-Computer -Confirm:$false -Force
    }	###########################################################################################################################################################
		#------------------------------------------------------------------------------------------------------------------------------------------------------FIN
}		###########################################################################################################################################################
else
{
Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Force -Confirm:$false
New-Item -Path c:\temp -Name Staging -ItemType directory -Verbose -Force -ErrorAction SilentlyContinue
Move-Item -Path $MyInvocation.MyCommand.Path -Destination c:\temp\Staging\Autoconf.ps1 -Verbose												#insert serverpath from script
$passcode = (New-Guid).Guid
$passcodesec = Convertto-securestring -string $passcode -asplaintext -force
New-LocalUser -Name hvstaging -password $passcodesec
Add-LocalGroupMember -Group Administrators -Member hvstaging
$action = New-ScheduledTaskAction -Execute 'Powershell.exe' -Argument 'c:\temp\Staging\Autoconf.ps1' -Verbose
$trigger = New-ScheduledTaskTrigger -AtLogOn -Verbose
Register-ScheduledTask -Action $action -Trigger $trigger -TaskName "AutoConfigScedular" -Description "startstherighttaskforautoconfig" -Verbose -user hvstaging -RunLevel Highest
New-Item -Path HKLM:\Software -Name Autoconf -Force
New-Item -Path HKLM:\Software\Autoconf -Value "01-InitialSetup" -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Value "1" -Name "AutoAdminLogon"				#
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Value "hvstaging" -Name "DefaultUserName"		# insert username
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Value $passcode -Name "DefaultPassword"	# insert password
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name EnableLUA -Value 0					#
Restart-Computer -Confirm:$false
}