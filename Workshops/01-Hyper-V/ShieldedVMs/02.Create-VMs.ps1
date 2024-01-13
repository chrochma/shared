Set-VMHost -EnableEnhancedSessionMode:$true
New-VMSwitch -SwitchName "Corp-Network"-SwitchType Internal
New-NetIPAddress -IPAddress "172.16.100.1" -PrefixLength 24 -InterfaceAlias "vEthernet (Corp-Network)"
New-NetNat -Name "Corp-Network" -InternalIPInterfaceAddressPrefix 172.16.100.0/24

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
    #Start-VM -Name $VMName
  
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
        Install-WindowsFeature -Name "AD-Domain-Services","DNS" -IncludeManagementTools -IncludeAllSubFeature -Restart
        $Password = ConvertTo-SecureString 'Pa$$w0rd!!!!!' -AsPlainText -Force
        Install-ADDSForest -DomainName "red.contoso.com" -SafeModeAdministratorPassword $Password -Force:$true -installDns:$true 
    }

        Start-Sleep -Seconds 60

    $UserName = "red\Administrator"
    $Password = ConvertTo-SecureString 'Pa$$w0rd!!!!!' -AsPlainText -Force
    $psCred = New-Object System.Management.Automation.PSCredential($UserName, $Password)
    Invoke-Command -VMName R-DC-1 -Credential $psCred -ScriptBlock {
        Install-WindowsFeature -name "ADCS-Cert-Authority" -IncludeManagementTools 
        Get-DnsServerforwarder | remove-dnsServerforwarder -force
        Add-DnsServerPrimaryZone -NetworkID "172.16.100.0/24" -ReplicationScope "Forest"
        Add-DNSServerforwarder -IPAddress 1.1.1.1
        New-ADOrganizationalUnit -Name "Corp" -Path "DC=RED,DC=CONTOSO,DC=COM"
        New-ADOrganizationalUnit -Name "Accounts" -Path "OU=CORP,DC=RED,DC=CONTOSO,DC=COM"
        New-ADOrganizationalUnit -Name "Administrators" -Path "OU=ACCOUNTS,OU=CORP,DC=RED,DC=CONTOSO,DC=COM"
        New-ADOrganizationalUnit -Name "ServiceAccounts" -Path "OU=ACCOUNTS,OU=CORP,DC=RED,DC=CONTOSO,DC=COM"
        New-ADOrganizationalUnit -Name "Users" -Path "OU=ACCOUNTS,OU=CORP,DC=RED,DC=CONTOSO,DC=COM"
        New-ADOrganizationalUnit -Name "Groups" -Path "OU=CORP,DC=RED,DC=CONTOSO,DC=COM"
        New-ADOrganizationalUnit -Name "Servers" -Path "OU=CORP,DC=RED,DC=CONTOSO,DC=COM"
        New-ADOrganizationalUnit -Name "Tier-0" -Path "OU=SERVERS,OU=CORP,DC=RED,DC=CONTOSO,DC=COM"
        New-ADOrganizationalUnit -Name "Tier-1" -Path "OU=SERVERS,OU=CORP,DC=RED,DC=CONTOSO,DC=COM"
        New-ADOrganizationalUnit -Name "Tier-2" -Path "OU=SERVERS,OU=CORP,DC=RED,DC=CONTOSO,DC=COM"
        New-ADOrganizationalUnit -Name "Workstations" -Path "OU=CORP,DC=RED,DC=CONTOSO,DC=COM"
        New-ADOrganizationalUnit -Name "Tier-0" -Path "OU=WORKSTATIONS,OU=CORP,DC=RED,DC=CONTOSO,DC=COM"
        New-ADOrganizationalUnit -Name "Tier-1" -Path "OU=WORKSTATIONS,OU=CORP,DC=RED,DC=CONTOSO,DC=COM"
        New-ADOrganizationalUnit -Name "Tier-2" -Path "OU=WORKSTATIONS,OU=CORP,DC=RED,DC=CONTOSO,DC=COM"
        Restart-Service NlaSvc -Force
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

        Start-Sleep -Seconds 60

    $UserName = "blue\Administrator"
    $Password = ConvertTo-SecureString 'Pa$$w0rd!!!!!' -AsPlainText -Force
    $psCred = New-Object System.Management.Automation.PSCredential($UserName, $Password)
    Invoke-Command -VMName B-DC-1 -Credential $psCred -ScriptBlock {
        Get-DnsServerforwarder | remove-dnsServerforwarder -force
        Add-DNSServerforwarder -IPAddress 172.16.100.11
        New-ADOrganizationalUnit -Name "Corp" -Path "DC=BLUE,DC=CONTOSO,DC=COM"
        New-ADOrganizationalUnit -Name "Accounts" -Path "OU=CORP,DC=BLUE,DC=CONTOSO,DC=COM"
        New-ADOrganizationalUnit -Name "Administrators" -Path "OU=ACCOUNTS,OU=CORP,DC=BLUE,DC=CONTOSO,DC=COM"
        New-ADOrganizationalUnit -Name "ServiceAccounts" -Path "OU=ACCOUNTS,OU=CORP,DC=BLUE,DC=CONTOSO,DC=COM"
        New-ADOrganizationalUnit -Name "Users" -Path "OU=ACCOUNTS,OU=CORP,DC=BLUE,DC=CONTOSO,DC=COM"
        New-ADOrganizationalUnit -Name "Groups" -Path "OU=CORP,DC=BLUE,DC=CONTOSO,DC=COM"
        New-ADOrganizationalUnit -Name "Servers" -Path "OU=CORP,DC=BLUE,DC=CONTOSO,DC=COM"
        New-ADOrganizationalUnit -Name "Tier-0" -Path "OU=SERVERS,OU=CORP,DC=BLUE,DC=CONTOSO,DC=COM"
        New-ADOrganizationalUnit -Name "Tier-1" -Path "OU=SERVERS,OU=CORP,DC=BLUE,DC=CONTOSO,DC=COM"
        New-ADOrganizationalUnit -Name "Tier-2" -Path "OU=SERVERS,OU=CORP,DC=BLUE,DC=CONTOSO,DC=COM"
        New-ADOrganizationalUnit -Name "Workstations" -Path "OU=CORP,DC=BLUE,DC=CONTOSO,DC=COM"
        New-ADOrganizationalUnit -Name "Tier-0" -Path "OU=WORKSTATIONS,OU=CORP,DC=BLUE,DC=CONTOSO,DC=COM"
        New-ADOrganizationalUnit -Name "Tier-1" -Path "OU=WORKSTATIONS,OU=CORP,DC=BLUE,DC=CONTOSO,DC=COM"
        New-ADOrganizationalUnit -Name "Tier-2" -Path "OU=WORKSTATIONS,OU=CORP,DC=BLUE,DC=CONTOSO,DC=COM"
        Restart-Service NlaSvc -Force
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
        Add-computer -DomainName "red.contoso.com" -Credential $psCred -OUPath "OU=Tier-0,OU=SERVERS,OU=CORP,DC=RED,DC=CONTOSO,DC=COM" -Restart
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
        Add-computer -DomainName "red.contoso.com" -Credential $psCred -OUPath "OU=Tier-0,OU=SERVERS,OU=CORP,DC=RED,DC=CONTOSO,DC=COM" -Restart
    }

    # B-HYP-1
    $UserName = "Administrator"
    $Password = ConvertTo-SecureString 'Pa$$w0rd!!!!!' -AsPlainText -Force
    $psCred = New-Object System.Management.Automation.PSCredential($UserName, $Password)

    Invoke-Command -VMName B-HYP-1 -Credential $psCred -ScriptBlock {
        New-NetIPAddress -IPAddress "172.16.100.22" -InterfaceAlias "Ethernet" -PrefixLength "24" -DefaultGateway "172.16.100.1" -AddressFamily IPv4
        Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ServerAddresses "172.16.100.21"
        ### Install Features
        get-disk | Where-Object PartitionStyle -like RAW | Initialize-Disk -PartitionStyle GPT | New-Partition -UseMaximumSize -AssignDriveLetter

        $disks = get-disk | Where-Object Size -gt 500000000000 
        foreach($Disk in $Disks){
            $Disk | New-Partition -UseMaximumSize -AssignDriveLetter | Format-Volume -FileSystem NTFS -AllocationUnitSize 65536 -NewFileSystemLabel "DATA" -Confirm:$false 
        }
        Install-WindowsFeature -name "Hyper-V" -IncludeManagementTools -IncludeAllSubFeature -Restart
    }
        Start-Sleep -Seconds 60
    $UserName = "blue\Administrator"
    $Password = ConvertTo-SecureString 'Pa$$w0rd!!!!!' -AsPlainText -Force
    $psCred = New-Object System.Management.Automation.PSCredential($UserName, $Password)
    Invoke-Command -VMName B-HYP-1 -Credential $psCred -ScriptBlock {
        Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard -Name RequirePlatformSecurityFeatures -Value 0
        $UserName = "blue\Administrator"
        $Password = ConvertTo-SecureString 'Pa$$w0rd!!!!!' -AsPlainText -Force
        $psCred = New-Object System.Management.Automation.PSCredential($UserName, $Password)
        Add-computer -DomainName "blue.contoso.com" -Credential $psCred -OUPath "OU=Tier-1,OU=SERVERS,OU=CORP,DC=BLUE,DC=CONTOSO,DC=COM" -Restart
    }

    # B-HYP-2
    $UserName = "Administrator"
    $Password = ConvertTo-SecureString 'Pa$$w0rd!!!!!' -AsPlainText -Force
    $psCred = New-Object System.Management.Automation.PSCredential($UserName, $Password)

    Invoke-Command -VMName B-HYP-2 -Credential $psCred -ScriptBlock {
        New-NetIPAddress -IPAddress "172.16.100.23" -InterfaceAlias "Ethernet" -PrefixLength "24" -DefaultGateway "172.16.100.1" -AddressFamily IPv4
        Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ServerAddresses "172.16.100.21"
        ### Install Features
        get-disk | Where-Object PartitionStyle -like RAW | Initialize-Disk -PartitionStyle GPT | New-Partition -UseMaximumSize -AssignDriveLetter

        $disks = get-disk | Where-Object Size -gt 500000000000 
        foreach($Disk in $Disks){
            $Disk | New-Partition -UseMaximumSize -AssignDriveLetter | Format-Volume -FileSystem NTFS -AllocationUnitSize 65536 -NewFileSystemLabel "DATA" -Confirm:$false 
        }
        Install-WindowsFeature -name "Hyper-V" -IncludeManagementTools -IncludeAllSubFeature -Restart
    }
        Start-Sleep -Seconds 60
    $UserName = "blue\Administrator"
    $Password = ConvertTo-SecureString 'Pa$$w0rd!!!!!' -AsPlainText -Force
    $psCred = New-Object System.Management.Automation.PSCredential($UserName, $Password)
    Invoke-Command -VMName B-HYP-2 -Credential $psCred -ScriptBlock {
        Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard -Name RequirePlatformSecurityFeatures -Value 0
        $UserName = "blue\Administrator"
        $Password = ConvertTo-SecureString 'Pa$$w0rd!!!!!' -AsPlainText -Force
        $psCred = New-Object System.Management.Automation.PSCredential($UserName, $Password)
        Add-computer -DomainName "blue.contoso.com" -Credential $psCred -OUPath "OU=Tier-1,OU=SERVERS,OU=CORP,DC=BLUE,DC=CONTOSO,DC=COM" -Restart
    }

    <#
    # G-WKS-1
    $UserName = "Administrator"
    $Password = ConvertTo-SecureString 'Pa$$w0rd!!!!!' -AsPlainText -Force
    $psCred = New-Object System.Management.Automation.PSCredential($UserName, $Password)

    Invoke-Command -VMName G-WKS-1 -Credential $psCred -ScriptBlock {
        New-NetIPAddress -IPAddress "172.16.100.32" -InterfaceAlias "Ethernet" -PrefixLength "24" -DefaultGateway "172.16.100.1" -AddressFamily IPv4
        Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ServerAddresses "172.16.100.21"
        ### Install Features
        Stop-Computer -Confirm:$false
    }#>

#endregion
