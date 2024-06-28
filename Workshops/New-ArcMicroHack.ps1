### Deploy Azure Arc MicroHack 

Login-AzAccount -useDeviceAuthentication -TenantId "" -SubscriptionId ""
# Clean All
# do{Get-AzResource | Remove-AzResource -Force -ErrorAction SilentlyContinue -Confirm:$false}until((Get-AzResource).count -eq 0)
# do{Get-AzResourceGroup | Remove-AzResourceGroup -Force -ErrorAction SilentlyContinue -Confirm:$false -AsJob;Start-Sleep -Seconds 10}until((Get-AzResourceGroup).count -eq 0)

$region = "germanywestcentral"
$PasswordClear = Read-Host "Please enter the Password you like to use for the Lab VMs"
$PasswordSecure = ConvertTo-SecureString $PasswordClear -AsPlainText -Force
[Int16]$LabCount = Read-Host "How many Users are planned to attend at the MicroHack?"


function OutInfo {
    [CmdletBinding()]
	param(
		[Parameter()]
		[string] $InfoText
	)
    $TimeStamp = Get-Date -Format "yyyy.MM.dd hh:mm:ss"
    Write-Host "$TimeStamp | $InfoText"
}
function OutInfoHighlighted {
    [CmdletBinding()]
	param(
		[Parameter()]
		[string] $InfoText
	)
    $TimeStamp = Get-Date -Format "yyyy.MM.dd hh:mm:ss"
    Write-Host "$TimeStamp | $InfoText" -ForegroundColor Cyan
}
if ($LabCount -gt "254") {
    throw "This tool is supposed to create 254 labs max at a time. Please scale to more than one subscription. Script is going to be canceled"
}else{    
    # Create Admin Stuff
    OutInfoHighlighted -InfoText "Create Admin Ressources"
    if(!(Get-AzResourceGroup -Name "rg-admin" -ErrorAction SilentlyContinue)){
        OutInfo -InfoText "Create RessourceGroup rg-admin"
        New-AzResourceGroup -Name "rg-admin" -Location $region 

        # Register Subscription Service Providers
        OutInfo -InfoText "Register Subscription Service Providers"
        Register-AzResourceProvider -ProviderNamespace Microsoft.Compute
        Register-AzResourceProvider -ProviderNamespace Microsoft.Network
        Register-AzResourceProvider -ProviderNamespace Microsoft.Quota
        Register-AzResourceProvider -ProviderNamespace Microsoft.HybridCompute

        #Create vNet
        OutInfo -InfoText "Create vNet vnet-lab, adding AzureBastionSubnet, snet-admin and NAT Gateway"
        $publicIP = New-AzPublicIpAddress -Name "pip-nat" -ResourceGroupName "rg-admin" -Location $region -Sku Standard -AllocationMethod Static -Zone 1,2,3
        $natGateway = New-AzNatGateway -Name "nat-gateway" -ResourceGroupName "rg-admin" -Location $region -Sku Standard -PublicIpAddress $publicIP -IdleTimeoutInMinutes "10"
        $snet1 = New-AzVirtualNetworkSubnetConfig -Name "AzureBastionSubnet" -AddressPrefix "172.16.0.0/26" 
        $snet2 = New-AzVirtualNetworkSubnetConfig -Name "snet-admin" -AddressPrefix "172.16.0.64/26" -NatGateway $natGateway
        $virtualNetwork = New-AzVirtualNetwork -Name "vnet-lab" -ResourceGroupName "rg-admin" -Location $region -AddressPrefix "172.16.0.0/16" -Subnet $snet1,$snet2
        $virtualNetwork | Set-AzVirtualNetwork

        #Create Azure Bastion
        $Bastioncount = $LabCount/20
        OutInfo -InfoText "Create Bastion Host"
        New-AzPublicIpAddress -ResourceGroupName "rg-admin" -name "pip-bastion" -location $region -AllocationMethod Static -Sku Standard
        New-AzBastion -ResourceGroupName "rg-admin" -Name "bastion" -PublicIpAddressRgName "rg-admin" -PublicIpAddressName "pip-bastion" -VirtualNetworkRgName "rg-admin" -VirtualNetworkName "vnet-lab" -Sku Standard -ScaleUnit $Bastioncount -EnableIpConnect:$true -EnableShareableLink:$true -AsJob

        # Create Storage Account for CloudShell
        OutInfo -InfoText "Create Storage Account for CloudShell"
        do{
            $SAName = Get-Random
            $SAName = "mh" + $SAName
            New-AzStorageAccount -ResourceGroupName "mh-admin" -name $SAName -Location $region -SkuName Standard_LRS -Kind StorageV2 -AccessTier Hot
            $SA = Get-AzStorageAccount -ResourceGroupName "mh-admin" -name $SAName 
        }until($SA -ne $null)

        # Check and increase Quota on Subscription for Micro Hack
        if($LabCount -le "50"){
            OutInfo -InfoText "Labcount is less than 50, Quota Increase skipped"
        }else{
            OutInfo -InfoText "Labcount requires Quota Increase. This is currently not implemented"
            throw "Quota increase is not enabled yet within this Script. Please create 50 or less Labs per Subscription."
            # REST API, Quota:  https://learn.microsoft.com/de-de/rest/api/reserved-vm-instances/quotaapi
            #                   https://techcommunity.microsoft.com/t5/azure-governance-and-management/using-the-new-quota-rest-api/ba-p/2183670
            # REST API, Case:   https://learn.microsoft.com/en-us/rest/api/support/
        }
        
    }
    #Write empty line for visual cut between administrative area and individual lab creation 
    Write-Host ""

    # Create Labs
    OutInfoHighlighted -InfoText "Create Lab Ressources"
    # Determine SKU for Windows VMs
    Get-AzVMSize -Location $region
    $WinVMSkus = Get-AzVMSize -Location $region | Where-Object {$_.NumberOfCores -eq 2 -and $_.ResourceDiskSizeInMB -eq 0 -and $_.MemoryInMB -eq 8192 -and $_.Name -like "*B2s*"}
    if($WinVMSkus -eq $null){
        throw "No SKU found for Windows VM, please check for available Quota, and adjust Script to use specific SKU for Windows VMs"
    }else{
        $WinVMSku = $WinVMSkus | Select-Object -First 1
    }

    # Determine SKU for Linux VMs
    $LinVMSkus = Get-AzVMSize -Location $region | Where-Object {$_.NumberOfCores -eq 2 -and $_.ResourceDiskSizeInMB -eq 0 -and $_.MemoryInMB -eq 4096 -and $_.Name -like "*B2a*"}
    if($LinVMSkus -eq $null){
        throw "No SKU found for Linux VM, please check for available Quota, and adjust Script to use specific SKU for Linux VMs"
    }else{
        $LinVMSku = $LinVMSkus | Select-Object -First 1
    }

    if((Get-AzResourceGroup -Name "rg-lab*" -ErrorAction SilentlyContinue).count -gt $LabCount){
        throw "Old Labs found, please cleanup manualy first, or change subscription"
    }else{
        OutInfo -InfoText "Creating $LabCount Labs"
        do {
            if(!(Get-AzResourceGroup -Name "rg-lab-$LabCount" -ErrorAction SilentlyContinue)){
                # Set the administrator and password for the Azure User and VMs
                $UserName = "arc-mhuser-$LabCount"
                $mhUserCred = New-Object System.Management.Automation.PSCredential($UserName, $PasswordSecure)
                
                # Add Azure AD User Account
                # - TBD - 
                # New-AzADUser -DisplayName $UserName -Password $PasswordSecure -AccountEnabled:$true
                # Grant RBAC to SUB/ RG etc
                # RBAC Role for MicroHack >> Defender ???
                # foreach($User in $Users){
                #    $UserID = $User.Split("@")[0]
                #    New-AzResourceGroup -Name $UserID -Location $region
                #    Get-AzResourceGroup -Name $UserID | New-AzRoleAssignment -SignInName $User -RoleDefinitionName Contributor
                # }

                # Add Core ressources
                New-AzResourceGroup -Name "rg-lab-$LabCount" -Location $region 
                $vnet = $(Get-AzVirtualNetwork -Name "vnet-lab" -ResourceGroupName "rg-admin")
                Add-AzVirtualNetworkSubnetConfig -Name "snet-lab-prd-$LabCount" -VirtualNetwork $vnet -AddressPrefix "172.16.$LabCount.0/24"  -NatGateway $natGateway | Set-AzVirtualNetwork

                ## Create network interface for virtual machine. ##
                $vnet = $(Get-AzVirtualNetwork -Name "vnet-lab" -ResourceGroupName "rg-admin")
                $snet = $vnet.Subnets | Where-Object Name -like "snet-lab-prd-$LabCount"
                $nicWinVM = New-AzNetworkInterface -Name "nic-winvm-$LabCount" -ResourceGroupName "rg-lab-$LabCount" -Location $region -Subnet $snet
                $nicLinVM = New-AzNetworkInterface -Name "nic-linvm-$LabCount" -ResourceGroupName "rg-lab-$LabCount" -Location $region -Subnet $snet
                
                ## Create a virtual machine configuration for VMs ##
                $WinVMConfig = New-AzVMConfig -VMName $("winvm-$LabCount") -VMSize $($WinVMSku.Name) | Set-AzVMOperatingSystem -ComputerName $("winvm-$LabCount") -Credential $mhUserCred | Set-AzVMSourceImage -PublisherName 'MicrosoftWindowsServer' -Offer 'WindowsServer' -Skus '2022-Datacenter' -Version 'latest' | Add-AzVMNetworkInterface -Id $nicWinVM.Id
                $LinVMConfig = New-AzVMConfig -VMName $("linvm-$LabCount") -VMSize $($LinVMSku.Name) | Set-AzVMOperatingSystem -ComputerName $("linvm-$LabCount") -Credential $mhUserCred -Linux | Set-AzVMSourceImage -PublisherName 'Canonical' -Offer '0001-com-ubuntu-server-jammy' -Skus '22_04-lts-gen2' -Version 'latest' | Add-AzVMNetworkInterface -Id $nicLinVM.Id

                ## Create the virtual machine for VMs ##
                New-AzVM -Location $region -ResourceGroupName "rg-lab-$LabCount" -VM $WinVMConfig -AsJob
                New-AzVM -Location $region -ResourceGroupName "rg-lab-$LabCount" -VM $LinVMConfig -AsJob
                ####################################
                
                # Customize Azure VM to be capable to be Arc enabled
                # Create Script and publish via GitHub in Microhack Repository TBD
                # Set-AzVMCustomScriptExtension -ResourceGroupName "rg-lab-$LabCount" -VMName "winvm-$LabCount" -Location $region -FileUri "https://xxxxxxx.blob.core.windows.net/buildServer1/1_Add_Tools.ps1" -Run 'myScript.ps1' -Name "AzureArcPrerequesits" -NoWait
                # Set-AzVMCustomScriptExtension -ResourceGroupName "rg-lab-$LabCount" -VMName "linvm-$LabCount" -Location $region -FileUri "https://xxxxxxx.blob.core.windows.net/buildServer1/1_Add_Tools.ps1" -Run 'myScript.ps1' -Name "AzureArcPrerequesits" -NoWait
                    
                    ## Configure the OS to allow Azure Arc Agent to be deploy on an Azure VM
                    <#
                        Write-Host "Configure the OS to allow Azure Arc Agent to be deploy on an Azure VM"
                        Set-Service WindowsAzureGuestAgent -StartupType Disabled -Verbose
                        Stop-Service WindowsAzureGuestAgent -Force -Verbose
                        New-NetFirewallRule -Name BlockAzureIMDS -DisplayName "Block access to Azure IMDS" -Enabled True -Profile Any -Direction Outbound -Action Block -RemoteAddress 169.254.169.254
                    #> 
                    
                    #>
                    
                    <# Linux
                    
                    ## Configure Ubuntu to allow Azure Arc Connected Machine Agent Installation
                    
                    echo "Configuring walinux agent"
                    sudo service walinuxagent stop
                    sudo waagent -deprovision -force
                    sudo rm -rf /var/lib/waagent
                    
                    echo "Configuring Firewall"
                    
                    sudo ufw --force enable
                    sudo ufw deny out from any to 169.254.169.254
                    sudo ufw default allow incoming
                    sudo apt-get update
                    
                    #>

                # Create Bastion Link
                # Create Link and Show it TBD

                # Output Username, Password, VMNames and Bastionlink Data to File (Apend) TBD

                OutInfo -InfoText "Lab $LabCount finished"
            }else{
                OutInfo -InfoText "Lab $LabCount already exists"
            }
            $LabCount = $LabCount -1
        } until (
            $LabCount -le 0
        )
        #>
    }
}








