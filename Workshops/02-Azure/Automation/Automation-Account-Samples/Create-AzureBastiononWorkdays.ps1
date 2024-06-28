# Ensures you do not inherit an AzContext in your runbook
Disable-AzContextAutosave –Scope Process

Connect-AzAccount -Identity
Start-Sleep -Seconds 30

Select-AzSubscription -SubscriptionId "xxxxxx-xxxxxxxxxxx-xxxxxxxx-xxxxx"
$vnet1 = Get-AzVirtualNetwork -Name "xxxxxx" -ResourceGroupName "xxxxxx"
$publicip = Get-AzPublicIpAddress -ResourceGroupName "xxxxxx" -Name "xxxxxx"
New-AzBastion -ResourceGroupName "xxxxxx" -Name "xxxxxx" -PublicIpAddress $publicip -VirtualNetwork $vnet1 -Sku Standard -ScaleUnit 2 -AsJob