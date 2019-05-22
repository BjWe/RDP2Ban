<#
.DESCRIPTION
  Count failed RDP sessions (username / password missmatch)
  by IP-Address.
  If the adjustable threshold is exceeded, 
  the address is entered in the firewall.
  After a certain time the entry will be deleted.

.NOTES
  Version:        1.0
  Author:         Bjoern Weis
  Creation Date:  2019-05-21
  Purpose/Change: Initial script development
#>


#### Config ####

$storageBasePath = "HKLM:\SOFTWARE"
$storageName = "RDP2Ban"
$itemStorageName = "Items"

$failGraceTries = 2
$failGraceMinutes = 60*24
$failLookbackMinutes = 15


# Prepare some variables
$combinedStoragePath = $storageBasePath+"\"+$storageName
$combinedItemPath = $combinedStoragePath+"\"+$itemStorageName
Write-Host -ForegroundColor Yellow $combinedStoragePath
Write-Host -ForegroundColor Yellow $combinedItemPath


# Create structure if nessesary
if(!(Test-Path -Path $combinedStoragePath)){
    New-Item -ItemType Directory -Path $storageBasePath -Name $storageName
}

if(!(Test-Path -Path $combinedItemPath)){
    New-Item -ItemType Directory -Path $combinedStoragePath -Name $itemStorageName
}


# Datetime lookup 
$starttime = (Get-Date).AddMinutes(0 - $failLookbackMinutes)

# Read events from windows eventlog
$events = Get-WinEvent -FilterHashtable @{logname="Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational";level=3;starttime=$starttime}
foreach($event in $events){
  if($event.Opcode -eq 14){
    $ipaddr = $event.Properties[0].Value;
    $ipPath = $combinedItemPath+"\"+$ipaddr

    # Check if it was here already
    if(!(Test-Path -Path $ipPath)){
        New-Item -ItemType Directory -Path $combinedItemPath -Name $ipaddr
    }
    
    if(!((Get-Item -Path $ipPath).GetValue($event.TimeCreated) -ne $null)){
        New-ItemProperty -Path $ipPath -Name $event.TimeCreated -PropertyType "DWORD" -Value 0
    }
    
  }
}

# Parse registry with filled items
$failItems = Get-ChildItem -Path $combinedItemPath

# Initial array ... 0.0.0.1 was used to never have an empty list (not the smartest solution, but simplest)
$bannedIPs = @("0.0.0.1")

$currentGrace = (Get-Date).AddMinutes(0 - $failGraceMinutes);
foreach($item in $failItems){
    $ipaddr = $item.PSChildName
    Write-Host -ForegroundColor Magenta $ipaddr
        
    $failCount = 0
    foreach($failure in $item.GetValueNames()){      
       if($currentGrace -lt $failure){
            Write-Host -ForegroundColor Gray $failure
            $failCount++
       }
       
    }
    if($failCount -gt $failGraceTries){
        Write-Host -ForegroundColor DarkRed $failCount $ipaddr
        $bannedIPs += $ipaddr
    }

}


# Create or update firewall rule
if(!((Get-NetFirewallRule -DisplayName "RDP2Ban") -ne $null)){
    New-NetFirewallRule -DisplayName "RDP2Ban" -Action Block -Profile Any -Direction Inbound -Protocol Any -RemoteAddress $bannedIPs 
    Write-Host -ForegroundColor Yellow "FW Add"
} else {
    $storedBannedIPs = (Get-NetFirewallRule -DisplayName "RDP2Ban" | Get-NetFirewallAddressFilter).RemoteAddress
    $diffCount = (Compare-Object -ReferenceObject $bannedIPs -DifferenceObject $storedBannedIPs).Count
    Write-Host -ForegroundColor Green "ObjDiff" $diffCount
    
    # update only with new data
    if(($diffCount -gt 0) -or ($diffCount -eq $null)){
        Write-Host -ForegroundColor Yellow "FW Set"
        Set-NetFirewallRule -DisplayName "RDP2Ban" -RemoteAddress $bannedIPs
    }
}
