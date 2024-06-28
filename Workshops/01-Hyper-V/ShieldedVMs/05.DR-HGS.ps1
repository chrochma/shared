# Create DR HGS VM

#R-HGS-3
$VMName = "R-HGS-3"
$CPUCores = "4"
[Int64]$RAMinGB = "4"
$VMLocation = "E:\VMs"
$SourceDisc = Get-Item -Path "E:\VMs\Image\*.vhdx"
$ImagePath = $SourceDisc.FullName

Stop-VM -VMName R-HGS-2 -Force -Confirm:$false

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

Invoke-Command -VMName R-HGS-3 -Credential $psCred -ScriptBlock {
    New-NetIPAddress -IPAddress "172.16.100.15" -InterfaceAlias "Ethernet" -PrefixLength "24" -DefaultGateway "172.16.100.1" -AddressFamily IPv4
    Set-DnsClientServerAddress -InterfaceAlias "Ethernet" -ServerAddresses "172.16.100.11"
    ### Install Features
    Restart-Computer -Force -Confirm:$false
}
Start-Sleep -Seconds 15
Invoke-Command -VMName R-HGS-3 -Credential $psCred -ScriptBlock {
    $UserName = "red\Administrator"
    $Password = ConvertTo-SecureString 'Pa$$w0rd!!!!!' -AsPlainText -Force
    $psCred = New-Object System.Management.Automation.PSCredential($UserName, $Password)
    Add-computer -DomainName "red.contoso.com" -Credential $psCred -OUPath "OU=Tier-0,OU=SERVERS,OU=CORP,DC=RED,DC=CONTOSO,DC=COM" -Restart
}

