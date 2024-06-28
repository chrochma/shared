# Ensures you do not inherit an AzContext in your runbook
Disable-AzContextAutosave –Scope Process

Connect-AzAccount -Identity
Start-Sleep -Seconds 30

$Subscriptions = Get-AzSubscription
foreach($Subscription in $Subscriptions){
    Select-AZSubscription $Subscription
    $VMs = Get-AzResource | Where-Object {$_.ResourceType -eq "Microsoft.Compute/virtualMachines"}
    foreach($VM in $VMs)
    {
        if($VM.Name -like "WESTEUDDC00*" -or $VM.Name -like "WCGERMADM*" -or $VM.Name -like "WESTEUMON00*" -or $VM.Name -like "WCGERMDDC00*")
        {
            $VMName = $VM.Name
            Write-Output "Start $VMName"
            Start-AzVM -Id $VM.ResourceId -NoWait
	    }else{
            $VMName = $VM.Name
            Write-Output "$VMName keeps offline"
        }
    }
}