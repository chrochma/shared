# Ensures you do not inherit an AzContext in your runbook
Disable-AzContextAutosave –Scope Process

Connect-AzAccount -Identity
Start-Sleep -Seconds 30

$Subscriptions = Get-AzSubscription
foreach($Subscription in $Subscriptions){
    Select-AZSubscription $Subscription

    
    $VMs = Get-AzResource | Where-Object {$_.ResourceType -eq "Microsoft.Compute/virtualMachines"}

    Write-output "Stop $Time VMs"
    foreach($VM in $VMs)
    {
	    if($VM.Name -like "WESTEUDDC00*" -or $VM.Name -like "WCGERMADM*" -or $VM.Name -like "WCGERMOPN*" -or $VM.Name -like "WCGERMDDC*" -or $VM.Name -like "WESTEUMON*")
	    {
	    $VMName = $VM.Name
	    Write-Output "$VMName keeps online"
	    }else{
	    $VMName = $VM.Name
        Write-Output "Stop $VMName"
        Stop-AzVM -Id $VM.ResourceId -Confirm:$false -Force -NoWait
	    }
    }
}