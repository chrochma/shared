# Create VMM VM

#B-VMM-1
$VMName = "B-VMM-1"
$CPUCores = "4"
[Int64]$RAMinGB = "16"
$VMLocation = "E:\VMs"
$SourceDisc = Get-Item -Path "E:\VMs\Image\*.vhdx"
$ImagePath = $SourceDisc.FullName

Stop-VM -VMName B-HYP-2 -Force -Confirm:$false

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
$RaminGB =  $RAMinGB*1024*1024*1024
Set-VMMemory -VMName $VMName -StartupBytes $RAMinGB -DynamicMemoryEnabled $false
Set-VMProcessor -VMName $VMName -Count $CPUCores -ExposeVirtualizationExtensions:$true
Start-VM -Name $VMName

Start-Sleep -Seconds 120
# Configure VMM
$UserName = "Administrator"
$Password = ConvertTo-SecureString 'Pa$$w0rd!!!!!' -AsPlainText -Force
$psCred = New-Object System.Management.Automation.PSCredential($UserName, $Password)

Invoke-Command -VMName B-VMM-1 -Credential $psCred -ScriptBlock {
    New-NetIPAddress -IPAddress "172.16.100.24" -InterfaceAlias "Ethernet" -PrefixLength "24" -DefaultGateway "172.16.100.1" -AddressFamily IPv4
    Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ServerAddresses "172.16.100.21"
    ### Install Features
    Restart-Computer -Force -Confirm:$false
}
Start-Sleep -Seconds 15
Invoke-Command -VMName B-VMM-1 -Credential $psCred -ScriptBlock {
    $UserName = "blue\Administrator"
    $Password = ConvertTo-SecureString 'Pa$$w0rd!!!!!' -AsPlainText -Force
    $psCred = New-Object System.Management.Automation.PSCredential($UserName, $Password)
    Add-computer -DomainName "blue.contoso.com" -Credential $psCred -OUPath "OU=Tier-1,OU=SERVERS,OU=CORP,DC=BLUE,DC=CONTOSO,DC=COM" -Restart
}
$UserName = "Blue\Administrator"
$Password = ConvertTo-SecureString 'Pa$$w0rd!!!!!' -AsPlainText -Force
$psCred = New-Object System.Management.Automation.PSCredential($UserName, $Password)

Write-Host "Please logon to B-VMM-1 as blue\Administrator and run the following script locally:" -ForegroundColor Cyan

<#
    New-Item -ItemType Directory -Path C:\VMM -Force
    Start-BitsTransfer -Source "https://go.microsoft.com/fwlink/p/?LinkID=2195845&clcid=0x409&culture=en-us&country=US" -Destination "C:\VMM\SCVMM_2022.exe"
    Start-BitsTransfer -Source "https://go.microsoft.com/fwlink/?linkid=2162950" -Destination "C:\VMM\20348.1.210507-1500.fe_release_amd64fre_ADK.iso"
    Start-BitsTransfer -Source "https://go.microsoft.com/fwlink/?linkid=2163233" -Destination "C:\VMM\20348.1.210507-1500.fe_release_amd64fre_ADKWINPEADDONS.iso"
    Start-BitsTransfer -Source "https://aka.ms/ssmsfullsetup" -Destination "C:\VMM\SSMS-Setup-ENU.exe"
    Start-BitsTransfer -Source "https://go.microsoft.com/fwlink/?linkid=866664&clcid=0x409&culture=en-us&country=us" -Destination "C:\VMM\SQL2019-SSEI-Eval.exe"
    Write-Host "Please run SQL2019-SSEI-Eval.exe and download English ISO to C:\VMM\SQLServer2019-x64-ENU.iso" -ForegroundColor Cyan
    Pause
    
    cd C:\vmm
    Mount-DiskImage -ImagePath C:\VMM\20348.1.210507-1500.fe_release_amd64fre_ADK.iso
    $ADKIsoDir = (Get-Volume | Where-Object FileSystemLabel -like "*KADK_MULFRE*").DriveLetter
    $ADKIsoDir = $ADKIsoDir+":"
    cd $ADKIsoDir
    .\adksetup.exe /quiet /installpath C:\ADK /features OptionId.DeploymentTools
    Dismount-DiskImage -ImagePath C:\VMM\20348.1.210507-1500.fe_release_amd64fre_ADK.iso

    Mount-DiskImage -ImagePath C:\VMM\20348.1.210507-1500.fe_release_amd64fre_ADKWINPEADDONS.iso
    $ADKIsoDir = (Get-Volume | Where-Object FileSystemLabel -like "*ADKWPEADDS_MULFRE*").DriveLetter
    $ADKIsoDir = $ADKIsoDir+":"
    cd $ADKIsoDir
    .\adkwinpesetup.exe /quiet /installpath C:\ADK /features OptionId.WindowsPreinstallationEnvironment /forcerestart
    Start-sleep -Seconds 90
    restart-computer -Force -Confirm:$false

#>


Pause

    Start-Sleep -Seconds 15
        Invoke-Command -VMName B-DC-1 -Credential $psCred -ScriptBlock {
            $AccountPW = ConvertTo-SecureString 'Pa$$w0rd!!!!!' -AsPlainText -Force
            New-ADUser -Name 'svc.db' -Path 'OU=ServiceAccounts,OU=Accounts,OU=Corp,DC=blue,DC=contoso,DC=com' -AccountPassword $AccountPW -Enabled:$true
            New-ADUser -Name 'svc.scvmm' -Path 'OU=ServiceAccounts,OU=Accounts,OU=Corp,DC=blue,DC=contoso,DC=com' -AccountPassword $AccountPW -Enabled:$true
        }
        Invoke-Command -VMName B-VMM-1 -Credential $psCred -ScriptBlock {
            Mount-DiskImage -ImagePath C:\VMM\SQLServer2019-x64-ENU.iso
            $SQLIsoDir = (Get-Volume | Where-Object FileSystemLabel -like "*SqlSetup*").DriveLetter
            $SQLIsoDir = $SQLIsoDir+":"
            cd $SQLIsoDir
            .\Setup.exe /Q /ACTION=install /IACCEPTSQLSERVERLICENSETERMS /FEATURES=SQLEngine /INSTANCENAME=VMM2022 /INSTANCEDIR="C:\Program Files\Microsoft SQL Server" /INSTALLSHAREDWOWDIR="C:\Program Files (x86)\Microsoft SQL Server" /INSTALLSHAREDDIR="C:\Program Files\Microsoft SQL Server" /SQLSVCACCOUNT="blue\svc.db" /SQLSVCPASSWORD='Pa$$w0rd!!!!!' /SQLSYSADMINACCOUNTS="blue\svc.scvmm" /AGTSVCACCOUNT="NT AUTHORITY\Network Service" /AGTSVCSTARTUPTYPE="Automatic" /SECURITYMODE=SQL /SAPWD='Pa$$w0rd!!!!!' /SQLTEMPDBDIR="C:\Program Files\Microsoft SQL Server\TempDB\\" /SQLUSERDBDIR="C:\Program Files\Microsoft SQL Server\SQLData\\" /SQLUSERDBLOGDIR="C:\Program Files\Microsoft SQL Server\SQLLog\\" 
            Dismount-DiskImage -ImagePath C:\VMM\SQLServer2019-x64-ENU.iso
            
            cd c:
            .\SSMS-Setup-ENU.exe /install /quiet /norestart /log ssms.txt
            Start-Sleep -Seconds 300
            Net localgroup Administrators blue\svc.scvmm /add
            Restart-Computer -Force -Confirm:$false
            # SQL Port 1433, Firewall
        }

Write-Host "Please logon to B-VMM-1 as blue\Administrator and run extract C:\SCVMM_2022.exe to C:\VMM\System Center Virtual Machine Manager" -ForegroundColor Cyan
Pause

        Invoke-Command -VMName B-VMM-1 -Credential $psCred -ScriptBlock {
#scvmm ini
'[OPTIONS]'| Out-File -FilePath "C:\VMM\System Center Virtual Machine Manager\VMServer.ini" -Encoding utf8
'ProductKey=BXH69-M62YX-QQD6R-3GPWX-8WMFY'| Out-File -FilePath "C:\VMM\System Center Virtual Machine Manager\VMServer.ini" -Encoding utf8 -Append
'UserName=svc.scvmm'| Out-File -FilePath "C:\VMM\System Center Virtual Machine Manager\VMServer.ini" -Encoding utf8 -Append
'CompanyName=TestLab'| Out-File -FilePath "C:\VMM\System Center Virtual Machine Manager\VMServer.ini" -Encoding utf8 -Append
'ProgramFiles=C:\Program Files\Microsoft System Center 2022\Virtual Machine Manager'| Out-File -FilePath "C:\VMM\System Center Virtual Machine Manager\VMServer.ini" -Encoding utf8 -Append
'CreateNewSqlDatabase=1'| Out-File -FilePath "C:\VMM\System Center Virtual Machine Manager\VMServer.ini" -Encoding utf8 -Append
'SqlInstanceName=VMM2022'| Out-File -FilePath "C:\VMM\System Center Virtual Machine Manager\VMServer.ini" -Encoding utf8 -Append
'SqlDatabaseName=VirtualManager2022'| Out-File -FilePath "C:\VMM\System Center Virtual Machine Manager\VMServer.ini" -Encoding utf8 -Append
'RemoteDatabaseImpersonation=1'| Out-File -FilePath "C:\VMM\System Center Virtual Machine Manager\VMServer.ini" -Encoding utf8 -Append
'SqlMachineName=B-VMM-1'| Out-File -FilePath "C:\VMM\System Center Virtual Machine Manager\VMServer.ini" -Encoding utf8 -Append
'IndigoTcpPort=8100'| Out-File -FilePath "C:\VMM\System Center Virtual Machine Manager\VMServer.ini" -Encoding utf8 -Append
'IndigoHTTPSPort=8101'| Out-File -FilePath "C:\VMM\System Center Virtual Machine Manager\VMServer.ini" -Encoding utf8 -Append
'IndigoNETTCPPort=8102'| Out-File -FilePath "C:\VMM\System Center Virtual Machine Manager\VMServer.ini" -Encoding utf8 -Append
'IndigoHTTPPort=8103'| Out-File -FilePath "C:\VMM\System Center Virtual Machine Manager\VMServer.ini" -Encoding utf8 -Append
'WSManTcpPort=5985'| Out-File -FilePath "C:\VMM\System Center Virtual Machine Manager\VMServer.ini" -Encoding utf8 -Append
'BitsTcpPort=4443'| Out-File -FilePath "C:\VMM\System Center Virtual Machine Manager\VMServer.ini" -Encoding utf8 -Append
'CreateNewLibraryShare=1'| Out-File -FilePath "C:\VMM\System Center Virtual Machine Manager\VMServer.ini" -Encoding utf8 -Append
'LibraryShareName=MSSCVMMLibrary'| Out-File -FilePath "C:\VMM\System Center Virtual Machine Manager\VMServer.ini" -Encoding utf8 -Append
'LibrarySharePath=C:\VMMLib'| Out-File -FilePath "C:\VMM\System Center Virtual Machine Manager\VMServer.ini" -Encoding utf8 -Append
'LibraryShareDescription=Virtual Machine Manager Library Files'| Out-File -FilePath "C:\VMM\System Center Virtual Machine Manager\VMServer.ini" -Encoding utf8 -Append
'SQMOptIn=0'| Out-File -FilePath "C:\VMM\System Center Virtual Machine Manager\VMServer.ini" -Encoding utf8 -Append
'MUOptIn=0'| Out-File -FilePath "C:\VMM\System Center Virtual Machine Manager\VMServer.ini" -Encoding utf8 -Append
'VmmServiceLocalAccount=1'| Out-File -FilePath "C:\VMM\System Center Virtual Machine Manager\VMServer.ini" -Encoding utf8 -Append
'HighlyAvailable=0'| Out-File -FilePath "C:\VMM\System Center Virtual Machine Manager\VMServer.ini" -Encoding utf8 -Append
'VmmServerName=B-VMM-1'| Out-File -FilePath "C:\VMM\System Center Virtual Machine Manager\VMServer.ini" -Encoding utf8 -Append
cd "C:\VMM\System Center Virtual Machine Manager"            
.\Setup.exe /server /i /f "C:\VMM\System Center Virtual Machine Manager\VMServer.ini" /SqlDBAdminDomain red.contoso.com /SqlDBAdminName svc.scvmm /SqlDBAdminPassword 'Pa$$w0rd!!!!!' /VmmServiceDomain blue.contoso.com /VmmServiceUserName svc.scvmm /VmmServiceUserPassword 'Pa$$w0rd!!!!!' /IACCEPTSCEULA
        }
    Write-Host "VMM Installation finished." -ForegroundColor Cyan
    pause
