# Ensures you do not inherit an AzContext in your runbook
Disable-AzContextAutosave –Scope Process

Connect-AzAccount -Identity
Start-Sleep -Seconds 30

Select-AzSubscription -SubscriptionId "xxxxx-xxxxx-xxxxx-xxxxx-xxxxx"
#Deallocate Azure Firewall
$fw = Get-AzFirewall -ResourceGroupName "xxxxx" -Name "xxxxx"
$fw.Deallocate()
$fw | Set-AzFirewall