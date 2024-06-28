# Ensures you do not inherit an AzContext in your runbook
Disable-AzContextAutosave –Scope Process

Connect-AzAccount -Identity
Start-Sleep -Seconds 30

$Subscriptions = Get-AzSubscription
foreach($Subscription in $Subscriptions){
    Select-AZSubscription $Subscription
    $Bastions = Get-AzResource | Where-Object {$_.ResourceType -eq "Microsoft.Network/bastionHosts"}
    foreach($Bastion in $Bastions)
    {
        Remove-AzResource -ResourceId $Bastion.Id -Force    
    }
}