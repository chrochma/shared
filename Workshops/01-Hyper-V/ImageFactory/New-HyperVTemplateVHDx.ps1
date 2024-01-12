<# 

Script name : New-HyperVTemplateVHDx.ps1

Authors : Christoph Roch-Mauf

Version : V1.0.0.2

Dependencies : run as Admin, SCVMM Comandlets Needed, Hyper-V Role needs to be installed

----------------------------------------------------------------------------------------------------------------------------------- 
Tool to create updated VHDx Templates to use in Hyper-V. Based on https://github.com/microsoft/MSLab/blob/master/Tools/Convert-WindowsImage.ps1
----------------------------------------------------------------------------------------------------------------------------------- 

Version Changes: 

Date: Version: Changed By: Info: 

----------------------------------------------------------------------------------------------------------------------------------- 

DISCLAIMER 

 THIS SAMPLE IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED 
 OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR 
 FITNESS FOR A PARTICULAR PURPOSE. 

 This sample is not supported under any Microsoft standard support program or service. 
 The script is provided AS IS without warranty of any kind. Microsoft further disclaims all 
 implied warranties including, without limitation, any implied warranties of merchantability 
 or of fitness for a particular purpose. The entire risk arising out of the use or performance 
 of the sample and documentation remains with you. In no event shall Microsoft, its authors, 
 or anyone else involved in the creation, production, or delivery of the script be liable for 
 any damages whatsoever (including, without limitation, damages for loss of business profits, 
 business interruption, loss of business information, or other pecuniary loss) arising out of 
 the use of or inability to use the sample or documentation, even if Microsoft has been advised 
 of the possibility of such damages. 

#> 

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