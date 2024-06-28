Login-AzAccount -useDeviceAuthentication -TenantId "" -SubscriptionId ""
# Clean All
# do{Get-AzResource | Remove-AzResource -Force -ErrorAction SilentlyContinue -Confirm:$false}until((Get-AzResource).count -eq 0)
# do{Get-AzResourceGroup | Remove-AzResourceGroup -Force -ErrorAction SilentlyContinue -Confirm:$false -AsJob;Start-Sleep -Seconds 10}until((Get-AzResourceGroup).count -eq 0)

$region = "germanywestcentral"
[Int16]$LabCount = 1

# HV Lab

if(!(Get-AzResourceGroup -Name "rg-admin-prd-001" -ErrorAction SilentlyContinue)){
    New-AzResourceGroup -Name "rg-admin-prd-001" -Location $region 

    #Create vNet
    $snet1 = New-AzVirtualNetworkSubnetConfig -Name "AzureBastionSubnet" -AddressPrefix "172.16.0.0/26" 
    $snet2 = New-AzVirtualNetworkSubnetConfig -Name "snet-admin-prd-1" -AddressPrefix "172.16.0.64/26" 
    $virtualNetwork = New-AzVirtualNetwork -Name "vnet-lab-prd-001" -ResourceGroupName "rg-admin-prd-001" -Location $region -AddressPrefix "172.16.0.0/16" -Subnet $snet1,$snet2
    $virtualNetwork | Set-AzVirtualNetwork

    #Create Azure Bastion
    New-AzPublicIpAddress -ResourceGroupName "rg-admin-prd-001" -name "pip-bastion-001" -location $region -AllocationMethod Static -Sku Standard
    New-AzBastion -ResourceGroupName "rg-admin-prd-001" -Name "bastion-001" -PublicIpAddressRgName "rg-admin-prd-001" -PublicIpAddressName "pip-bastion-001" -VirtualNetworkRgName "rg-admin-prd-001" -VirtualNetworkName "vnet-lab-prd-001" -Sku Standard -ScaleUnit 2 -EnableIpConnect:$true -EnableShareableLink:$true -AsJob


}

if((Get-AzResourceGroup -Name "rg-lab*" -ErrorAction SilentlyContinue).count -gt $LabCount){
    Write-Host "Old Labs found, please cleanup manualy first, or change subscription" -ForegroundColor Red
}else{
    Write-Host "Creating $LabCount Labs" -ForegroundColor Cyan
    do {
        if(!(Get-AzResourceGroup -Name "rg-lab-$LabCount" -ErrorAction SilentlyContinue)){
            Write-Host "Creating Lab $LabCount" -ForegroundColor Green

            # Add RG
            New-AzResourceGroup -Name "rg-lab-$LabCount" -Location $region 

            # Add vNet
            $vnet = $(Get-AzVirtualNetwork -Name "vnet-lab-prd-001" -ResourceGroupName "rg-admin-prd-001") # Get-AzVirtualNetwork -Name "vnet-lab-prd-001" -ResourceGroupName "rg-admin-prd-001"
            Add-AzVirtualNetworkSubnetConfig -Name "snet-lab-prd-$LabCount" -VirtualNetwork $vnet -AddressPrefix "172.16.$LabCount.0/24" | Set-AzVirtualNetwork
        }else{
            Write-Host "Lab $LabCount already exists" -ForegroundColor Yellow
        }
        $LabCount = $LabCount -1
    } until (
        $LabCount -le 0
    )
    #>
}









