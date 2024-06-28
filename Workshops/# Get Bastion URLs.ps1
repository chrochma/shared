# Get Bastion URLs


$VMName = "Labs_7225ef86"
$VMId = (get-azvm -Name $VMName).Id

$VMIdSplits = $VMId -split "/"

# Log in first with Connect-AzAccount if not using Cloud Shell

$azContext = Get-AzContext
$azProfile = [Microsoft.Azure.Commands.Common.Authentication.Abstractions.AzureRmProfileProvider]::Instance.Profile
$profileClient = New-Object -TypeName Microsoft.Azure.Commands.ResourceManager.Common.RMProfileClient -ArgumentList ($azProfile)
$token = $profileClient.AcquireAccessToken($azContext.Subscription.TenantId)
$authHeader = @{
    'Content-Type'='application/json'
    'Authorization'='Bearer ' + $token.AccessToken
}

# Invoke the REST API
$restUri = "https://management.azure.com/subscriptions/$($VMIdSplits[2])/resourceGroups/$($VMIdSplits[4])/providers/Microsoft.Network/bastionHosts/bastion-001/getShareableLinks?api-version=2023-06-01"
$response = Invoke-RestMethod -Uri $restUri -Method Post -Headers $authHeader

$BastionLinks = ($response).value | Select-Object vm,bsl

foreach($BastionLink in $BastionLinks){
    $VMN = $BastionLink.vm -replace "}","" 
    $VMN = $VMN -split "/"
    $VMN = $VMN[8] 
    Write-Host $VMN "|" $BastionLink.bsl
}
