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

    Set-VMHost -EnableEnhancedSessionMode:$true

    get-disk | Where-Object PartitionStyle -like RAW | Initialize-Disk -PartitionStyle GPT | New-Partition -UseMaximumSize -AssignDriveLetter

    $disks = get-disk | Where-Object Size -gt 1000000000000 
    foreach($Disk in $Disks){
        $Disk | New-Partition -UseMaximumSize -AssignDriveLetter | Format-Volume -FileSystem NTFS -AllocationUnitSize 65536 -NewFileSystemLabel "DATA" -Confirm:$false 
    }
    "Restarting Computer" | Out-File -FilePath $Loglocation\InitialConfiguration.log -Append

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

    New-VMSwitch -SwitchName "Corp-Network"-SwitchType Internal
    New-NetIPAddress -IPAddress "172.16.100.1" -PrefixLength 24 -InterfaceAlias "vEthernet (Corp-Network)"
    New-NetNat -Name "Corp-Network" -InternalIPInterfaceAddressPrefix 172.16.100.0/24

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
            }
         }

    # Create VM Foundation
    $DriveLetterLocation = (Get-Volume | Where-Object DriveLetter | Sort-Object -Descending SizeRemaining | Select-Object -First 1).DriveLetter
    $VMLocation = $DriveLetterLocation+":\VMs"

    if(!(Test-Path $VMLocation))
    {
        New-Item -Path $VMLocation -ItemType Directory
        New-Item -Path $VMLocation -Name "Image" -ItemType Directory
        $HostGuard = New-HgsGuardian -Name 'VMLocalGuardian' -GenerateCertificates

        
        '<?xml version="1.0" encoding="utf-8"?>'| Out-File -FilePath $VMLocation\Image\unattend.xml -Encoding utf8
        '<unattend xmlns="urn:schemas-microsoft-com:unattend" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">'| Out-File -FilePath $VMLocation\Image\unattend.xml -Encoding utf8 -Append
        '	<!--https://schneegans.de/windows/unattend-generator/?LanguageMode=Unattended&UILanguage=en-US&UserLocale=de-DE&KeyboardLayout=0407%3A00000407&ProcessorArchitecture=amd64&ComputerNameMode=Custom&ComputerName=TESTNAME&TimeZoneMode=Explicit&TimeZone=W.+Europe+Standard+Time&PartitionMode=Interactive&WindowsEditionMode=Interactive&UserAccountMode=Unattended&AccountName0=&AccountName1=&AccountName2=&AccountName3=&AccountName4=&AutoLogonMode=Builtin&BuiltinAdministratorPassword=Pa%24%24w0rd%21%21%21%21%21&LockoutMode=Default&EnableRemoteDesktop=true&WifiMode=Interactive&ExpressSettings=DisableAll&WdacMode=Skip-->'| Out-File -FilePath $VMLocation\Image\unattend.xml -Encoding utf8 -Append
        '	<settings pass="offlineServicing"></settings>'| Out-File -FilePath $VMLocation\Image\unattend.xml -Encoding utf8 -Append
        '	<settings pass="windowsPE">'| Out-File -FilePath $VMLocation\Image\unattend.xml -Encoding utf8 -Append
        '		<component name="Microsoft-Windows-International-Core-WinPE" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">'| Out-File -FilePath $VMLocation\Image\unattend.xml -Encoding utf8 -Append
        '			<SetupUILanguage>'| Out-File -FilePath $VMLocation\Image\unattend.xml -Encoding utf8 -Append
        '				<UILanguage>en-US</UILanguage>'| Out-File -FilePath $VMLocation\Image\unattend.xml -Encoding utf8 -Append
        '			</SetupUILanguage>'| Out-File -FilePath $VMLocation\Image\unattend.xml -Encoding utf8 -Append
        '			<InputLocale>0407:00000407</InputLocale>'| Out-File -FilePath $VMLocation\Image\unattend.xml -Encoding utf8 -Append
        '			<SystemLocale>de-DE</SystemLocale>'| Out-File -FilePath $VMLocation\Image\unattend.xml -Encoding utf8 -Append
        '			<UILanguage>en-US</UILanguage>'| Out-File -FilePath $VMLocation\Image\unattend.xml -Encoding utf8 -Append
        '			<UserLocale>de-DE</UserLocale>'| Out-File -FilePath $VMLocation\Image\unattend.xml -Encoding utf8 -Append
        '		</component>'| Out-File -FilePath $VMLocation\Image\unattend.xml -Encoding utf8 -Append
        '	</settings>'| Out-File -FilePath $VMLocation\Image\unattend.xml -Encoding utf8 -Append
        '	<settings pass="generalize"></settings>'| Out-File -FilePath $VMLocation\Image\unattend.xml -Encoding utf8 -Append
        '	<settings pass="specialize">'| Out-File -FilePath $VMLocation\Image\unattend.xml -Encoding utf8 -Append
        '		<component name="Microsoft-Windows-Deployment" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">'| Out-File -FilePath $VMLocation\Image\unattend.xml -Encoding utf8 -Append
        '			<RunSynchronous>'| Out-File -FilePath $VMLocation\Image\unattend.xml -Encoding utf8 -Append
        '				<RunSynchronousCommand wcm:action="add">'| Out-File -FilePath $VMLocation\Image\unattend.xml -Encoding utf8 -Append
        '					<Order>1</Order>'| Out-File -FilePath $VMLocation\Image\unattend.xml -Encoding utf8 -Append
        '					<Path>netsh.exe advfirewall firewall set rule group="Remote Desktop" new enable=Yes</Path>'| Out-File -FilePath $VMLocation\Image\unattend.xml -Encoding utf8 -Append
        '				</RunSynchronousCommand>'| Out-File -FilePath $VMLocation\Image\unattend.xml -Encoding utf8 -Append
        '				<RunSynchronousCommand wcm:action="add">'| Out-File -FilePath $VMLocation\Image\unattend.xml -Encoding utf8 -Append
        '					<Order>2</Order>'| Out-File -FilePath $VMLocation\Image\unattend.xml -Encoding utf8 -Append
        '					<Path>reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f</Path>'| Out-File -FilePath $VMLocation\Image\unattend.xml -Encoding utf8 -Append
        '				</RunSynchronousCommand>'| Out-File -FilePath $VMLocation\Image\unattend.xml -Encoding utf8 -Append
        '			</RunSynchronous>'| Out-File -FilePath $VMLocation\Image\unattend.xml -Encoding utf8 -Append
        '		</component>'| Out-File -FilePath $VMLocation\Image\unattend.xml -Encoding utf8 -Append
        '		<component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">'| Out-File -FilePath $VMLocation\Image\unattend.xml -Encoding utf8 -Append
        '			<ComputerName>XSERVERNAMEX</ComputerName>'| Out-File -FilePath $VMLocation\Image\unattend.xml -Encoding utf8 -Append
        '			<TimeZone>W. Europe Standard Time</TimeZone>'| Out-File -FilePath $VMLocation\Image\unattend.xml -Encoding utf8 -Append
        '		</component>'| Out-File -FilePath $VMLocation\Image\unattend.xml -Encoding utf8 -Append
        '	</settings>'| Out-File -FilePath $VMLocation\Image\unattend.xml -Encoding utf8 -Append
        '	<settings pass="auditSystem"></settings>'| Out-File -FilePath $VMLocation\Image\unattend.xml -Encoding utf8 -Append
        '	<settings pass="auditUser"></settings>'| Out-File -FilePath $VMLocation\Image\unattend.xml -Encoding utf8 -Append
        '	<settings pass="oobeSystem">'| Out-File -FilePath $VMLocation\Image\unattend.xml -Encoding utf8 -Append
        '		<component name="Microsoft-Windows-International-Core" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">'| Out-File -FilePath $VMLocation\Image\unattend.xml -Encoding utf8 -Append
        '			<InputLocale>0407:00000407</InputLocale>'| Out-File -FilePath $VMLocation\Image\unattend.xml -Encoding utf8 -Append
        '			<SystemLocale>de-DE</SystemLocale>'| Out-File -FilePath $VMLocation\Image\unattend.xml -Encoding utf8 -Append
        '			<UILanguage>en-US</UILanguage>'| Out-File -FilePath $VMLocation\Image\unattend.xml -Encoding utf8 -Append
        '			<UserLocale>de-DE</UserLocale>'| Out-File -FilePath $VMLocation\Image\unattend.xml -Encoding utf8 -Append
        '		</component>'| Out-File -FilePath $VMLocation\Image\unattend.xml -Encoding utf8 -Append
        '		<component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">'| Out-File -FilePath $VMLocation\Image\unattend.xml -Encoding utf8 -Append
        '			<UserAccounts>'| Out-File -FilePath $VMLocation\Image\unattend.xml -Encoding utf8 -Append
        '				<AdministratorPassword>'| Out-File -FilePath $VMLocation\Image\unattend.xml -Encoding utf8 -Append
        '					<Value>Pa$$w0rd!!!!!</Value>'| Out-File -FilePath $VMLocation\Image\unattend.xml -Encoding utf8 -Append
        '					<PlainText>true</PlainText>'| Out-File -FilePath $VMLocation\Image\unattend.xml -Encoding utf8 -Append
        '				</AdministratorPassword>'| Out-File -FilePath $VMLocation\Image\unattend.xml -Encoding utf8 -Append
        '			</UserAccounts>'| Out-File -FilePath $VMLocation\Image\unattend.xml -Encoding utf8 -Append
        '			<OOBE>'| Out-File -FilePath $VMLocation\Image\unattend.xml -Encoding utf8 -Append
        '				<ProtectYourPC>3</ProtectYourPC>'| Out-File -FilePath $VMLocation\Image\unattend.xml -Encoding utf8 -Append
        '				<HideEULAPage>true</HideEULAPage>'| Out-File -FilePath $VMLocation\Image\unattend.xml -Encoding utf8 -Append
        '				<HideWirelessSetupInOOBE>false</HideWirelessSetupInOOBE>'| Out-File -FilePath $VMLocation\Image\unattend.xml -Encoding utf8 -Append
        '			</OOBE>'| Out-File -FilePath $VMLocation\Image\unattend.xml -Encoding utf8 -Append
        '		</component>'| Out-File -FilePath $VMLocation\Image\unattend.xml -Encoding utf8 -Append
        '	</settings>'| Out-File -FilePath $VMLocation\Image\unattend.xml -Encoding utf8 -Append
        '</unattend>'| Out-File -FilePath $VMLocation\Image\unattend.xml -Encoding utf8 -Append

        $SourceDisc = Get-Item -Path "C:\WS2022\*.vhdx"
        $ImagePath = "$VMLocation\Image\"+$SourceDisc.Name
        Copy-Item -Path $SourceDisc.FullName -Destination $ImagePath -ErrorAction SilentlyContinue
    }
    # Create VMs
        #R-DC-1
        $VMName = "R-DC-1"
        $CPUCores = "4"
        [Int64]$RAMinGB = "4"

        # Prepare OSDisk
        New-Item -Path $VMLocation -Name $VMName -ItemType Directory
        $DestinationDisc = "$VMLocation\$VMName\"+$SourceDisc.Name
        Copy-Item -Path $ImagePath -Destination $DestinationDisc -ErrorAction SilentlyContinue
        Mount-VHD $DestinationDisc 
        $VHDMountLetter = (Get-Volume | Where-Object Size -EQ 64062746624).DriveLetter
        $VHDDestinationPath = $VHDMountLetter+":\Windows\Panther\"
        New-Item $VHDDestinationPath -ItemType Directory
        #Copy-Item "$VMLocation\Image\unattend.xml" -destination $VHDDestinationPath
        $unattendtochange = Get-Content "$VMLocation\Image\unattend.xml"
        foreach($Line in $unattendtochange){
            $Line = $Line -replace "XSERVERNAMEX",$VMName
            $Line | Out-File -FilePath $VHDDestinationPath\unattend.xml -Append -Encoding utf8
        }
        Dismount-VHD $DestinationDisc

        New-VM -Name $VMName -Generation 2 -VHDPath $DestinationDisc -SwitchName "Corp-Network" -Path "$VMLocation\$VMName\"
        $KeyProtector = New-HgsKeyProtector -Owner $HostGuard -AllowUntrustedRoot
        Set-VMKeyProtector -VMName $VMName -KeyProtector $KeyProtector.RawData
        Enable-VMTPM -VMNAME $VMName 
        Set-VMNetworkAdapter -VMName $VMName -MacAddressSpoofing On
        $RaminGB =  $RAMinGB*1024*1024*1024
        Set-VMMemory -VMName $VMName -StartupBytes $RAMinGB -DynamicMemoryEnabled $false
        Set-VMProcessor -VMName $VMName -Count $CPUCores -ExposeVirtualizationExtensions:$true
        Start-VM -Name $VMName

        #R-HGS-1
        $VMName = "R-HGS-1"
        $CPUCores = "4"
        [Int64]$RAMinGB = "4"

        # Prepare OSDisk
        New-Item -Path $VMLocation -Name $VMName -ItemType Directory
        $DestinationDisc = "$VMLocation\$VMName\"+$SourceDisc.Name
        Copy-Item -Path $ImagePath -Destination $DestinationDisc -ErrorAction SilentlyContinue
        Mount-VHD $DestinationDisc 
        $VHDMountLetter = (Get-Volume | Where-Object Size -EQ 64062746624).DriveLetter
        $VHDDestinationPath = $VHDMountLetter+":\Windows\Panther\"
        New-Item $VHDDestinationPath -ItemType Directory
        #Copy-Item "$VMLocation\Image\unattend.xml" -destination $VHDDestinationPath
        $unattendtochange = Get-Content "$VMLocation\Image\unattend.xml"
        foreach($Line in $unattendtochange){
            $Line = $Line -replace "XSERVERNAMEX",$VMName
            $Line | Out-File -FilePath $VHDDestinationPath\unattend.xml -Append -Encoding utf8
        }
        Dismount-VHD $DestinationDisc

        New-VM -Name $VMName -Generation 2 -VHDPath $DestinationDisc -SwitchName "Corp-Network" -Path "$VMLocation\$VMName\"
        $KeyProtector = New-HgsKeyProtector -Owner $HostGuard -AllowUntrustedRoot
        Set-VMKeyProtector -VMName $VMName -KeyProtector $KeyProtector.RawData
        Enable-VMTPM -VMNAME $VMName 
        Set-VMNetworkAdapter -VMName $VMName -MacAddressSpoofing On
        $RaminGB =  $RAMinGB*1024*1024*1024
        Set-VMMemory -VMName $VMName -StartupBytes $RAMinGB -DynamicMemoryEnabled $false
        Set-VMProcessor -VMName $VMName -Count $CPUCores -ExposeVirtualizationExtensions:$true
        Start-VM -Name $VMName
      
        #R-HGS-2
        $VMName = "R-HGS-2"
        $CPUCores = "4"
        [Int64]$RAMinGB = "4"

        # Prepare OSDisk
        New-Item -Path $VMLocation -Name $VMName -ItemType Directory
        $DestinationDisc = "$VMLocation\$VMName\"+$SourceDisc.Name
        Copy-Item -Path $ImagePath -Destination $DestinationDisc -ErrorAction SilentlyContinue
        Mount-VHD $DestinationDisc 
        $VHDMountLetter = (Get-Volume | Where-Object Size -EQ 64062746624).DriveLetter
        $VHDDestinationPath = $VHDMountLetter+":\Windows\Panther\"
        New-Item $VHDDestinationPath -ItemType Directory
        #Copy-Item "$VMLocation\Image\unattend.xml" -destination $VHDDestinationPath
        $unattendtochange = Get-Content "$VMLocation\Image\unattend.xml"
        foreach($Line in $unattendtochange){
            $Line = $Line -replace "XSERVERNAMEX",$VMName
            $Line | Out-File -FilePath $VHDDestinationPath\unattend.xml -Append -Encoding utf8
        }
        Dismount-VHD $DestinationDisc

        New-VM -Name $VMName -Generation 2 -VHDPath $DestinationDisc -SwitchName "Corp-Network" -Path "$VMLocation\$VMName\"
        $KeyProtector = New-HgsKeyProtector -Owner $HostGuard -AllowUntrustedRoot
        Set-VMKeyProtector -VMName $VMName -KeyProtector $KeyProtector.RawData
        Enable-VMTPM -VMNAME $VMName 
        Set-VMNetworkAdapter -VMName $VMName -MacAddressSpoofing On
        $RaminGB =  $RAMinGB*1024*1024*1024
        Set-VMMemory -VMName $VMName -StartupBytes $RAMinGB -DynamicMemoryEnabled $false
        Set-VMProcessor -VMName $VMName -Count $CPUCores -ExposeVirtualizationExtensions:$true
        Start-VM -Name $VMName
      
       #G-WKS-1
        $VMName = "G-WKS-1"
        $CPUCores = "4"
        [Int64]$RAMinGB = "8"

        # Prepare OSDisk
        New-Item -Path $VMLocation -Name $VMName -ItemType Directory
        $DestinationDisc = "$VMLocation\$VMName\"+$SourceDisc.Name
        Copy-Item -Path $ImagePath -Destination $DestinationDisc -ErrorAction SilentlyContinue
        Mount-VHD $DestinationDisc 
        $VHDMountLetter = (Get-Volume | Where-Object Size -EQ 64062746624).DriveLetter
        $VHDDestinationPath = $VHDMountLetter+":\Windows\Panther\"
        New-Item $VHDDestinationPath -ItemType Directory
        #Copy-Item "$VMLocation\Image\unattend.xml" -destination $VHDDestinationPath
        $unattendtochange = Get-Content "$VMLocation\Image\unattend.xml"
        foreach($Line in $unattendtochange){
            $Line = $Line -replace "XSERVERNAMEX",$VMName
            $Line | Out-File -FilePath $VHDDestinationPath\unattend.xml -Append -Encoding utf8
        }
        Dismount-VHD $DestinationDisc

        New-VM -Name $VMName -Generation 2 -VHDPath $DestinationDisc -SwitchName "Corp-Network" -Path "$VMLocation\$VMName\"
        $KeyProtector = New-HgsKeyProtector -Owner $HostGuard -AllowUntrustedRoot
        Set-VMKeyProtector -VMName $VMName -KeyProtector $KeyProtector.RawData
        Enable-VMTPM -VMNAME $VMName 
        Set-VMNetworkAdapter -VMName $VMName -MacAddressSpoofing On
        $RaminGB =  $RAMinGB*1024*1024*1024
        Set-VMMemory -VMName $VMName -StartupBytes $RAMinGB -DynamicMemoryEnabled $false
        Set-VMProcessor -VMName $VMName -Count $CPUCores -ExposeVirtualizationExtensions:$true
        Start-VM -Name $VMName
      
       #B-DC-1
        $VMName = "B-DC-1"
        $CPUCores = "4"
        [Int64]$RAMinGB = "4"

        # Prepare OSDisk
        New-Item -Path $VMLocation -Name $VMName -ItemType Directory
        $DestinationDisc = "$VMLocation\$VMName\"+$SourceDisc.Name
        Copy-Item -Path $ImagePath -Destination $DestinationDisc -ErrorAction SilentlyContinue
        Mount-VHD $DestinationDisc 
        $VHDMountLetter = (Get-Volume | Where-Object Size -EQ 64062746624).DriveLetter
        $VHDDestinationPath = $VHDMountLetter+":\Windows\Panther\"
        New-Item $VHDDestinationPath -ItemType Directory
        #Copy-Item "$VMLocation\Image\unattend.xml" -destination $VHDDestinationPath
        $unattendtochange = Get-Content "$VMLocation\Image\unattend.xml"
        foreach($Line in $unattendtochange){
            $Line = $Line -replace "XSERVERNAMEX",$VMName
            $Line | Out-File -FilePath $VHDDestinationPath\unattend.xml -Append -Encoding utf8
        }
        Dismount-VHD $DestinationDisc

        New-VM -Name $VMName -Generation 2 -VHDPath $DestinationDisc -SwitchName "Corp-Network" -Path "$VMLocation\$VMName\"
        $KeyProtector = New-HgsKeyProtector -Owner $HostGuard -AllowUntrustedRoot
        Set-VMKeyProtector -VMName $VMName -KeyProtector $KeyProtector.RawData
        Enable-VMTPM -VMNAME $VMName 
        Set-VMNetworkAdapter -VMName $VMName -MacAddressSpoofing On
        $RaminGB =  $RAMinGB*1024*1024*1024
        Set-VMMemory -VMName $VMName -StartupBytes $RAMinGB -DynamicMemoryEnabled $false
        Set-VMProcessor -VMName $VMName -Count $CPUCores -ExposeVirtualizationExtensions:$true
        Start-VM -Name $VMName
      
       #B-HYP-1
        $VMName = "B-HYP-1"
        $CPUCores = "4"
        [Int64]$RAMinGB = "16"

        # Prepare OSDisk
        New-Item -Path $VMLocation -Name $VMName -ItemType Directory
        $DestinationDisc = "$VMLocation\$VMName\"+$SourceDisc.Name
        Copy-Item -Path $ImagePath -Destination $DestinationDisc -ErrorAction SilentlyContinue
        Mount-VHD $DestinationDisc 
        $VHDMountLetter = (Get-Volume | Where-Object Size -EQ 64062746624).DriveLetter
        $VHDDestinationPath = $VHDMountLetter+":\Windows\Panther\"
        New-Item $VHDDestinationPath -ItemType Directory
        #Copy-Item "$VMLocation\Image\unattend.xml" -destination $VHDDestinationPath
        $unattendtochange = Get-Content "$VMLocation\Image\unattend.xml"
        foreach($Line in $unattendtochange){
            $Line = $Line -replace "XSERVERNAMEX",$VMName
            $Line | Out-File -FilePath $VHDDestinationPath\unattend.xml -Append -Encoding utf8
        }
        Dismount-VHD $DestinationDisc

        New-VM -Name $VMName -Generation 2 -VHDPath $DestinationDisc -SwitchName "Corp-Network" -Path "$VMLocation\$VMName\"
        $KeyProtector = New-HgsKeyProtector -Owner $HostGuard -AllowUntrustedRoot
        Set-VMKeyProtector -VMName $VMName -KeyProtector $KeyProtector.RawData
        Enable-VMTPM -VMNAME $VMName 
        Set-VMNetworkAdapter -VMName $VMName -MacAddressSpoofing On
        $RaminGB =  $RAMinGB*1024*1024*1024
        Set-VMMemory -VMName $VMName -StartupBytes $RAMinGB -DynamicMemoryEnabled $false
        Set-VMProcessor -VMName $VMName -Count $CPUCores -ExposeVirtualizationExtensions:$true
        New-VHD -Dynamic -Path "$VMLocation\$VMName\DATA1.vhdx" -SizeBytes 500GB 
        Add-VMHardDiskDrive -vmname $VMName -path "$VMLocation\$VMName\DATA1.vhdx"
        Start-VM -Name $VMName
      
       #B-HYP-2
        $VMName = "B-HYP-2"
        $CPUCores = "4"
        [Int64]$RAMinGB = "16"

        # Prepare OSDisk
        New-Item -Path $VMLocation -Name $VMName -ItemType Directory
        $DestinationDisc = "$VMLocation\$VMName\"+$SourceDisc.Name
        Copy-Item -Path $ImagePath -Destination $DestinationDisc -ErrorAction SilentlyContinue
        Mount-VHD $DestinationDisc 
        $VHDMountLetter = (Get-Volume | Where-Object Size -EQ 64062746624).DriveLetter
        $VHDDestinationPath = $VHDMountLetter+":\Windows\Panther\"
        New-Item $VHDDestinationPath -ItemType Directory
        #Copy-Item "$VMLocation\Image\unattend.xml" -destination $VHDDestinationPath
        $unattendtochange = Get-Content "$VMLocation\Image\unattend.xml"
        foreach($Line in $unattendtochange){
            $Line = $Line -replace "XSERVERNAMEX",$VMName
            $Line | Out-File -FilePath $VHDDestinationPath\unattend.xml -Append -Encoding utf8
        }
        Dismount-VHD $DestinationDisc

        New-VM -Name $VMName -Generation 2 -VHDPath $DestinationDisc -SwitchName "Corp-Network" -Path "$VMLocation\$VMName\"
        $KeyProtector = New-HgsKeyProtector -Owner $HostGuard -AllowUntrustedRoot
        Set-VMKeyProtector -VMName $VMName -KeyProtector $KeyProtector.RawData
        Enable-VMTPM -VMNAME $VMName 
        Set-VMNetworkAdapter -VMName $VMName -MacAddressSpoofing On
        $RaminGB =  $RAMinGB*1024*1024*1024
        Set-VMMemory -VMName $VMName -StartupBytes $RAMinGB -DynamicMemoryEnabled $false
        Set-VMProcessor -VMName $VMName -Count $CPUCores -ExposeVirtualizationExtensions:$true
        New-VHD -Dynamic -Path "$VMLocation\$VMName\DATA1.vhdx" -SizeBytes 500GB 
        Add-VMHardDiskDrive -vmname $VMName -path "$VMLocation\$VMName\DATA1.vhdx"
        Start-VM -Name $VMName
    
        # Configure VMs
        # R-DC-1
        $UserName = "Administrator"
        $Password = ConvertTo-SecureString 'Pa$$w0rd!!!!!' -AsPlainText -Force
        $psCred = New-Object System.Management.Automation.PSCredential($UserName, $Password)

        Invoke-Command -VMName R-DC-1 -Credential $psCred -ScriptBlock {
            New-NetIPAddress -IPAddress "172.16.100.11" -InterfaceAlias "Ethernet" -PrefixLength "24" -DefaultGateway "172.16.100.1" -AddressFamily IPv4
            Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ServerAddresses "172.16.100.11"
            ### Install Features

            # Install Windows Server based certificate authority
            Install-WindowsFeature -name "ADCS-Cert-Authority" -IncludeManagementTools 
            Install-WindowsFeature -Name "AD-Domain-Services","DNS" -IncludeManagementTools -IncludeAllSubFeature -Restart
            $Password = ConvertTo-SecureString 'Pa$$w0rd!!!!!' -AsPlainText -Force
            Install-ADDSForest -DomainName "red.contoso.com" -SafeModeAdministratorPassword $Password -Force:$true -installDns:$true 
        }

        do{
            Start-Sleep -Seconds 15
        }until((Test-NetConnection 172.16.100.11 -Port 3389) -eq $true)

        $UserName = "red\Administrator"
        $Password = ConvertTo-SecureString 'Pa$$w0rd!!!!!' -AsPlainText -Force
        $psCred = New-Object System.Management.Automation.PSCredential($UserName, $Password)
        Invoke-Command -VMName R-DC-1 -Credential $psCred -ScriptBlock {
            Get-DnsServerforwarder | remove-dnsServerforwarder -force
            Add-DNSServerforwarder -IPAddress 1.1.1.1
            New-ADOrganizationalUnit -Name "Corp" -Path "DC=RED,DC=CONTOSO,DC=COM"
            New-ADOrganizationalUnit -Name "Accounts" -Path "CN=CORP,DC=RED,DC=CONTOSO,DC=COM"
            New-ADOrganizationalUnit -Name "Administrators" -Path "CN=ACCOUNTS,CN=CORP,DC=RED,DC=CONTOSO,DC=COM"
            New-ADOrganizationalUnit -Name "ServiceAccounts" -Path "CN=ACCOUNTS,CN=CORP,DC=RED,DC=CONTOSO,DC=COM"
            New-ADOrganizationalUnit -Name "Users" -Path "CN=ACCOUNTS,CN=CORP,DC=RED,DC=CONTOSO,DC=COM"
            New-ADOrganizationalUnit -Name "Groups" -Path "CN=CORP,DC=RED,DC=CONTOSO,DC=COM"
            New-ADOrganizationalUnit -Name "Servers" -Path "CN=CORP,DC=RED,DC=CONTOSO,DC=COM"
            New-ADOrganizationalUnit -Name "Tier-0" -Path "CN=SERVERS,CN=CORP,DC=RED,DC=CONTOSO,DC=COM"
            New-ADOrganizationalUnit -Name "Tier-1" -Path "CN=SERVERS,CN=CORP,DC=RED,DC=CONTOSO,DC=COM"
            New-ADOrganizationalUnit -Name "Tier-2" -Path "CN=SERVERS,CN=CORP,DC=RED,DC=CONTOSO,DC=COM"
            New-ADOrganizationalUnit -Name "Workstations" -Path "CN=CORP,DC=RED,DC=CONTOSO,DC=COM"
            New-ADOrganizationalUnit -Name "Tier-0" -Path "CN=WORKSTATIONS,CN=CORP,DC=RED,DC=CONTOSO,DC=COM"
            New-ADOrganizationalUnit -Name "Tier-1" -Path "CN=WORKSTATIONS,CN=CORP,DC=RED,DC=CONTOSO,DC=COM"
            New-ADOrganizationalUnit -Name "Tier-2" -Path "CN=WORKSTATIONS,CN=CORP,DC=RED,DC=CONTOSO,DC=COM"
            Install-AdcsCertificationAuthority -CAType EnterpriseRootCA -KeyLength 4096 -HashAlgorithmName SHA256 -ValidityPeriod Years -ValidityPeriodUnits 10 -CryptoProviderName "RSA#Microsoft Software Key Storage Provider" -OverwriteExistingKey -CACommonName "Red-CA-2024" -Force:$true
        }

        # B-DC-1
        $UserName = "Administrator"
        $Password = ConvertTo-SecureString 'Pa$$w0rd!!!!!' -AsPlainText -Force
        $psCred = New-Object System.Management.Automation.PSCredential($UserName, $Password)

        Invoke-Command -VMName B-DC-1 -Credential $psCred -ScriptBlock {
            New-NetIPAddress -IPAddress "172.16.100.21" -InterfaceAlias "Ethernet" -PrefixLength "24" -DefaultGateway "172.16.100.1" -AddressFamily IPv4
            Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ServerAddresses "172.16.100.21"
            ### Install Features

            # Install Windows Server based certificate authority
            Install-WindowsFeature -Name "AD-Domain-Services","DNS" -IncludeManagementTools -IncludeAllSubFeature -Restart
            $Password = ConvertTo-SecureString 'Pa$$w0rd!!!!!' -AsPlainText -Force
            Install-ADDSForest -DomainName "blue.contoso.com" -SafeModeAdministratorPassword $Password -Force:$true -installDns:$true 
        }

        do{
            Start-Sleep -Seconds 15
        }until((Test-NetConnection 172.16.100.21 -Port 3389) -eq $true)

        $UserName = "blue\Administrator"
        $Password = ConvertTo-SecureString 'Pa$$w0rd!!!!!' -AsPlainText -Force
        $psCred = New-Object System.Management.Automation.PSCredential($UserName, $Password)
        Invoke-Command -VMName B-DC-1 -Credential $psCred -ScriptBlock {
            Get-DnsServerforwarder | remove-dnsServerforwarder -force
            Add-DNSServerforwarder -IPAddress 172.16.100.11
            New-ADOrganizationalUnit -Name "Corp" -Path "DC=BLUE,DC=CONTOSO,DC=COM"
            New-ADOrganizationalUnit -Name "Accounts" -Path "CN=CORP,DC=BLUE,DC=CONTOSO,DC=COM"
            New-ADOrganizationalUnit -Name "Administrators" -Path "CN=ACCOUNTS,CN=CORP,DC=BLUE,DC=CONTOSO,DC=COM"
            New-ADOrganizationalUnit -Name "ServiceAccounts" -Path "CN=ACCOUNTS,CN=CORP,DC=BLUE,DC=CONTOSO,DC=COM"
            New-ADOrganizationalUnit -Name "Users" -Path "CN=ACCOUNTS,CN=CORP,DC=BLUE,DC=CONTOSO,DC=COM"
            New-ADOrganizationalUnit -Name "Groups" -Path "CN=CORP,DC=BLUE,DC=CONTOSO,DC=COM"
            New-ADOrganizationalUnit -Name "Servers" -Path "CN=CORP,DC=BLUE,DC=CONTOSO,DC=COM"
            New-ADOrganizationalUnit -Name "Tier-0" -Path "CN=SERVERS,CN=CORP,DC=BLUE,DC=CONTOSO,DC=COM"
            New-ADOrganizationalUnit -Name "Tier-1" -Path "CN=SERVERS,CN=CORP,DC=BLUE,DC=CONTOSO,DC=COM"
            New-ADOrganizationalUnit -Name "Tier-2" -Path "CN=SERVERS,CN=CORP,DC=BLUE,DC=CONTOSO,DC=COM"
            New-ADOrganizationalUnit -Name "Workstations" -Path "CN=CORP,DC=BLUE,DC=CONTOSO,DC=COM"
            New-ADOrganizationalUnit -Name "Tier-0" -Path "CN=WORKSTATIONS,CN=CORP,DC=BLUE,DC=CONTOSO,DC=COM"
            New-ADOrganizationalUnit -Name "Tier-1" -Path "CN=WORKSTATIONS,CN=CORP,DC=BLUE,DC=CONTOSO,DC=COM"
            New-ADOrganizationalUnit -Name "Tier-2" -Path "CN=WORKSTATIONS,CN=CORP,DC=BLUE,DC=CONTOSO,DC=COM"
        }

        # R-HGS-1
        $UserName = "Administrator"
        $Password = ConvertTo-SecureString 'Pa$$w0rd!!!!!' -AsPlainText -Force
        $psCred = New-Object System.Management.Automation.PSCredential($UserName, $Password)

        Invoke-Command -VMName R-HGS-1 -Credential $psCred -ScriptBlock {
            New-NetIPAddress -IPAddress "172.16.100.12" -InterfaceAlias "Ethernet" -PrefixLength "24" -DefaultGateway "172.16.100.1" -AddressFamily IPv4
            Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ServerAddresses "172.16.100.11"
            ### Install Features
            $UserName = "red\Administrator"
            $Password = ConvertTo-SecureString 'Pa$$w0rd!!!!!' -AsPlainText -Force
            $psCred = New-Object System.Management.Automation.PSCredential($UserName, $Password)
            Add-computer -DomainName "red.contoso.com" -Credential $psCred -OUPath "CN=Tier-0,CN=SERVERS,CN=CORP,DC=RED,DC=CONTOSO,DC=COM" -Restart
        }

        # R-HGS-2
        $UserName = "Administrator"
        $Password = ConvertTo-SecureString 'Pa$$w0rd!!!!!' -AsPlainText -Force
        $psCred = New-Object System.Management.Automation.PSCredential($UserName, $Password)

        Invoke-Command -VMName R-HGS-2 -Credential $psCred -ScriptBlock {
            New-NetIPAddress -IPAddress "172.16.100.13" -InterfaceAlias "Ethernet" -PrefixLength "24" -DefaultGateway "172.16.100.1" -AddressFamily IPv4
            Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ServerAddresses "172.16.100.11"
            ### Install Features
            $UserName = "red\Administrator"
            $Password = ConvertTo-SecureString 'Pa$$w0rd!!!!!' -AsPlainText -Force
            $psCred = New-Object System.Management.Automation.PSCredential($UserName, $Password)
            Add-computer -DomainName "red.contoso.com" -Credential $psCred -OUPath "CN=Tier-0,CN=SERVERS,CN=CORP,DC=RED,DC=CONTOSO,DC=COM" -Restart
        }

        # G-WKS-1
        $UserName = "Administrator"
        $Password = ConvertTo-SecureString 'Pa$$w0rd!!!!!' -AsPlainText -Force
        $psCred = New-Object System.Management.Automation.PSCredential($UserName, $Password)

        Invoke-Command -VMName G-WKS-1 -Credential $psCred -ScriptBlock {
            New-NetIPAddress -IPAddress "172.16.100.32" -InterfaceAlias "Ethernet" -PrefixLength "24" -DefaultGateway "172.16.100.1" -AddressFamily IPv4
            Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ServerAddresses "172.16.100.21"
            ### Install Features
        }

        # B-HYP-1
        $UserName = "Administrator"
        $Password = ConvertTo-SecureString 'Pa$$w0rd!!!!!' -AsPlainText -Force
        $psCred = New-Object System.Management.Automation.PSCredential($UserName, $Password)

        Invoke-Command -VMName B-HYP-1 -Credential $psCred -ScriptBlock {
            New-NetIPAddress -IPAddress "172.16.100.22" -InterfaceAlias "Ethernet" -PrefixLength "24" -DefaultGateway "172.16.100.1" -AddressFamily IPv4
            Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ServerAddresses "172.16.100.21"
            ### Install Features
            Install-WindowsFeature -name "Hyper-V" -IncludeManagementTools -IncludeAllSubFeature -Restart
        }
        do{
            Start-Sleep -Seconds 15
        }until((Test-NetConnection 172.16.100.22) -eq $true)
        $UserName = "blue\Administrator"
        $Password = ConvertTo-SecureString 'Pa$$w0rd!!!!!' -AsPlainText -Force
        $psCred = New-Object System.Management.Automation.PSCredential($UserName, $Password)
        Invoke-Command -VMName B-HYP-1 -Credential $psCred -ScriptBlock {
            Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard -Name RequirePlatformSecurityFeatures -Value 0
            $UserName = "blue\Administrator"
            $Password = ConvertTo-SecureString 'Pa$$w0rd!!!!!' -AsPlainText -Force
            $psCred = New-Object System.Management.Automation.PSCredential($UserName, $Password)
            Add-computer -DomainName "blue.contoso.com" -Credential $psCred -OUPath "CN=Tier-1,CN=SERVERS,CN=CORP,DC=BLUE,DC=CONTOSO,DC=COM" -Restart
        }

        # B-HYP-2
        $UserName = "Administrator"
        $Password = ConvertTo-SecureString 'Pa$$w0rd!!!!!' -AsPlainText -Force
        $psCred = New-Object System.Management.Automation.PSCredential($UserName, $Password)

        Invoke-Command -VMName B-HYP-2 -Credential $psCred -ScriptBlock {
            New-NetIPAddress -IPAddress "172.16.100.23" -InterfaceAlias "Ethernet" -PrefixLength "24" -DefaultGateway "172.16.100.1" -AddressFamily IPv4
            Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ServerAddresses "172.16.100.21"
            ### Install Features
            Install-WindowsFeature -name "Hyper-V" -IncludeManagementTools -IncludeAllSubFeature -Restart
        }
        do{
            Start-Sleep -Seconds 15
        }until((Test-NetConnection 172.16.100.23) -eq $true)
        $UserName = "blue\Administrator"
        $Password = ConvertTo-SecureString 'Pa$$w0rd!!!!!' -AsPlainText -Force
        $psCred = New-Object System.Management.Automation.PSCredential($UserName, $Password)
        Invoke-Command -VMName B-HYP-2 -Credential $psCred -ScriptBlock {
            Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard -Name RequirePlatformSecurityFeatures -Value 0
            $UserName = "blue\Administrator"
            $Password = ConvertTo-SecureString 'Pa$$w0rd!!!!!' -AsPlainText -Force
            $psCred = New-Object System.Management.Automation.PSCredential($UserName, $Password)
            Add-computer -DomainName "blue.contoso.com" -Credential $psCred -OUPath "CN=Tier-1,CN=SERVERS,CN=CORP,DC=BLUE,DC=CONTOSO,DC=COM" -Restart
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