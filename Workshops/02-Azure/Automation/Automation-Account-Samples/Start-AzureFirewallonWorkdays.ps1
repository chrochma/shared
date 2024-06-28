# Ensures you do not inherit an AzContext in your runbook
Disable-AzContextAutosave –Scope Process

Connect-AzAccount -Identity
Start-Sleep -Seconds 30

Select-AzSubscription -SubscriptionId "xxxxx-xxxxxxx-xxxxxxxx-xxxxxx-xxxxx"

#Starting firewall not configured for forced tunneling
$fw = Get-AzFirewall -ResourceGroupName "xxxxx" -Name "xxxxx"
$vnet = Get-AzVirtualNetwork -Name "xxxxx" -ResourceGroupName "xxxxx"
$ip1 = Get-AzPublicIpAddress -ResourceGroupName "xxxxx" -Name "xxxxx"
$ip2 = Get-AzPublicIpAddress -ResourceGroupName "xxxxx" -Name "xxxxx"
$fw.Allocate($vnet, $ip1, $ip2)
$fw | Set-AzFirewall