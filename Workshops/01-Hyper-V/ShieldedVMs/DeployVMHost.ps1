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
        New-Item -Path HKLM:\Software\Autoconf -Value "04-SetupVMs" -Force
        Restart-Computer -Confirm:$false -Force
    }
    Restart-Computer -Confirm:$false -Force
}

if($nextstep -eq "04-SetupVMs"){
##### DO STH

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