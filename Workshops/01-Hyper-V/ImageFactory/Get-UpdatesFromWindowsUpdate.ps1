$Products=@()
$Products+=@{Product="Azure Stack HCI 21H2 and Windows Server 2022" ;SearchString="Cumulative Update for Microsoft server operating system version 21H2 for x64-based Systems" ;SSUSearchString="Servicing Stack Update for Microsoft server operating system version 21H2 for x64-based Systems" ; ID="Microsoft Server operating system-21H2" ; FolderID="WS2022"}
#grab folder to download to
#grab folder to download to
if(Test-path hklm:software\RMLab\Templates\Updates)
{
    $folder = (Get-ItemProperty -Path hklm:software\RMLab\Templates\Updates -Name "Path").Path
}
else
{
    do {
        $folder=C:\temp
        if(Test-Path $folder)
        {
            New-Item -Path hklm:software -Name RMLab #-ErrorAction SilentlyContinue
            New-Item -Path hklm:software\RMLab -Name Templates #-ErrorAction SilentlyContinue
            New-Item -Path hklm:software\RMLab\Templates -Name Updates #-ErrorAction SilentlyContinue
            Set-ItemProperty -Path hklm:software\RMLab\Templates\Updates -Name "Path" -Value $folder
        }
        else
        {
            Write-Host "The Path $folder is not valid"
        }
    } until (Test-path hklm:software\RMLab\Templates\Updates)
    
}
if(!$folder){$folder=$PSScriptRoot}

$preview=$false

#let user choose products
$SelectedProducts= $Products.Product

#region download MSCatalog module
Write-Output "Checking if MSCatalog PS Module is Installed"
if (!(Get-InstalledModule -Name MSCatalog -ErrorAction Ignore)){
    # Verify Running as Admin
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
    If (!( $isAdmin )) {
        Write-Host "-- Restarting as Administrator to install Modules" -ForegroundColor Cyan ; Start-Sleep -Seconds 1
        Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs 
        exit
    }
    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
    Install-Module -Name MSCatalog -Force
}

#endregion

#region download products
Foreach($SelectedProduct in $SelectedProducts){
    $item=$Products | Where-Object product -eq $SelectedProduct
    #Download SSU
    $update=Get-MSCatalogUpdate -Search $item.searchstring | Where-Object Products -eq $item.ID | Where-Object Title -like "*$($item.SearchString)*" | Select-Object -First 1
    $FolderItem = $item.FolderID
    $DestinationFolder="$folder\$FolderItem\$($update.title.Substring(0,7))"
    $UpdatePattern = $DestinationFolder -replace '^.*(?=.{7}$)'
       
    if(Test-Path $destinationFolder){
    }else {
        New-Item -Path $DestinationFolder -ItemType Directory -ErrorAction Ignore | Out-Null
        Write-Output "Downloading $($update.title) to $destinationFolder"
        Write-Host $update
        $update | Save-MSCatalogUpdate -Destination "$DestinationFolder" #-UseBits
        
    #Download Security Update KB5012170 (2022-08 Sicherheitsupdate)
    #    $update=Get-MSCatalogUpdate -Search "KB5012170" | Where-Object {$_.Products -eq $item.ID} | Select-Object -First 1
    #    Write-Output "Downloading $($update.title) to $destinationFolder"
    #    $update | Save-MSCatalogUpdate -Destination $DestinationFolder

    <#Download CU
        $update=Get-MSCatalogUpdate -Search $item.searchstring | Where-Object {$_.Products -eq $item.ID -and $_.Classification -eq "Updates"} | Select-Object -First 1
        if($update.Title -like "$UpdatePattern*"){
            Write-Output "Downloading $($update.title) to $destinationFolder"
            $update | Save-MSCatalogUpdate -Destination $DestinationFolder #-UseBits   
        }#>
    #Download SSU
        $update=Get-MSCatalogUpdate -Search $item.SSUSearchString | Where-Object Products -eq $item.ID | Select-Object -First 1
        if ($update){
            Write-Output "Downloading $($update.title) to $destinationFolder"
            Write-Host $update
            $update | Save-MSCatalogUpdate -Destination $DestinationFolder #-UseBits
        }
        <#
    #Download Adobe Removal
        if ($item.Product -like "*2012*" -or $item.Product -like "*2016*" -or $item.Product -like "*2019*" ) {
            $update=Get-MSCatalogUpdate -Search "KB4577586" | Where-Object {$_.Products -eq $item.ID -and $_.Classification -eq "Updates"} | Select-Object -First 1
            Write-Output "Downloading $($update.title) to $destinationFolder"
            Write-Host $update
            $update | Save-MSCatalogUpdate -Destination $DestinationFolder
        }
    #Download Security Update KB4535680 (2021-01 Sicherheitsupdate)
    if ($item.Product -like "*2012*" -or $item.Product -like "*2016*" -or $item.Product -like "*2019*" ) {
        $update=Get-MSCatalogUpdate -Search "KB4535680" | Where-Object {$_.Products -eq $item.ID} | Select-Object -First 1
        Write-Output "Downloading $($update.title) to $destinationFolder"
        Write-Host $update
        $update | Save-MSCatalogUpdate -Destination $DestinationFolder
    }
    #Download Security Update KB4589208 (2021-01 Update 2019)
    if ($item.Product -like "*2019*" ) {
        $update=Get-MSCatalogUpdate -Search "KB4589208" | Where-Object {$_.Products -eq $item.ID -and $_.Classification -eq "Updates"} | Select-Object -First 1
        Write-Output "Downloading $($update.title) to $destinationFolder"
        Write-Host $update
        $update | Save-MSCatalogUpdate -Destination $DestinationFolder
    }
    #Download Security Update KB4589210 (2021-01 Update 2016)
    if ($item.Product -like "*2016*" ) {
        $update=Get-MSCatalogUpdate -Search "KB4589210" | Where-Object {$_.Products -eq $item.ID -and $_.Classification -eq "Updates"} | Select-Object -First 1
        Write-Output "Downloading $($update.title) to $destinationFolder"
        Write-Host $update
        $update | Save-MSCatalogUpdate -Destination $DestinationFolder
    }#>

    }
}
#endregion