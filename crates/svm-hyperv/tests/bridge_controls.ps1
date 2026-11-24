# All hardware, registry and network reads resolve to the fixture functions below.
$ErrorActionPreference='Stop'
Import-Module Microsoft.PowerShell.Utility
$PSModuleAutoLoadingPreference='None'
. ([scriptblock]::Create([IO.File]::ReadAllText($env:SVM_BRIDGE_SOURCE)))
$link=[pscustomobject]@{Name='Ethernet';InterfaceGuid=[guid]::NewGuid();ifIndex=4;InterfaceDescription='Fixture';InterfaceType=6;Status='Up'}
$bound=@()
$good=$true
function Get-NetAdapter { param([switch]$Physical) $script:link }
function Get-VMSwitch { $script:bound }
function Get-NetAdapterBinding {
    param($Name,[switch]$AllBindings,$ErrorAction)
    foreach ($id in 'ms_tcpip','ms_tcpip6','ms_implat','vendor_filter') {
        [pscustomobject]@{ComponentID=$id;Enabled=$(if ($script:good) { $id -in @('ms_tcpip','ms_tcpip6') } else { $id -ne 'ms_tcpip6' })}
    }
}
function Get-NetAdapterAdvancedProperty {
    param($Name,[switch]$AllProperties,$ErrorAction)
    [pscustomobject]@{RegistryKeyword='VlanID';RegistryValue=$(if ($script:good) {'00'} else {'3'})}
}
function Get-NetIPInterface {
    param($InterfaceIndex,$AddressFamily,$ErrorAction)
    if (!$script:good -and $AddressFamily -eq 'IPv6') { throw 'No IPv6 interface.' }
    if ($script:good) { return [pscustomobject]@{Dhcp='Enabled';AutomaticMetric='Enabled';NlMtu=1500;Forwarding='Disabled';WeakHostSend='Disabled';WeakHostReceive='Disabled'} }
    [pscustomobject]@{Dhcp='Disabled';AutomaticMetric='Disabled';NlMtu=8200;Forwarding='Enabled';WeakHostSend='Enabled';WeakHostReceive='Disabled'}
}
function Get-NetIPAddress {
    param($InterfaceIndex,$ErrorAction)
    [pscustomobject]@{PrefixOrigin=$(if($script:good){'Dhcp'}else{'Manual'});IPAddress='192.0.2.2';AddressState='Preferred';AddressFamily='IPv4'}
}
function Get-NetRoute {
    param($AddressFamily,$PolicyStore,$ErrorAction)
    if ($PolicyStore -and !$script:good) { return [pscustomobject]@{InterfaceIndex=4;Protocol='NetMgmt'} }
    if (!$PolicyStore -and $script:good) { [pscustomobject]@{InterfaceIndex=4;DestinationPrefix='0.0.0.0/0'} }
}
function Get-DnsClient { param($InterfaceIndex,$ErrorAction) [pscustomobject]@{} }
function Get-DnsClientServerAddress {
    param($InterfaceIndex,$AddressFamily,$ErrorAction)
    [pscustomobject]@{ServerAddresses=$(if($script:good){'192.0.2.1'})}
}
function Get-CimInstance {
    param($ClassName,$Filter,$ErrorAction)
    [pscustomobject]@{IPEnabled=$true;TcpipNetbiosOptions=[int]!$script:good}
}
function Test-Path { param($LiteralPath,$ErrorAction) $true }
function Get-ItemProperty {
    param($LiteralPath,$ErrorAction)
    if (!$script:good) { [pscustomobject]@{NameServer='192.0.2.3';Domain='fixture.invalid'} }
}
function Get-VMNetworkAdapter {
    param([switch]$ManagementOS,$ErrorAction)
    [pscustomobject]@{SwitchId=$script:bound[0].Id}
}
function CheckId($id) {}
function Refuse($msg) { throw $msg }
function Assert($condition,$message) { if(!$condition){throw $message} }

$p=@{op='resolveBridge';networkId='fixture';adapterId=$link.InterfaceGuid.ToString('D')}
$row=(BridgeAdapters).adapters[0]
Assert ($row.available -and !$row.bound -and $row.reasons.Count -eq 0) 'A plain physical adapter must be eligible.'
Assert (ResolveBridge $p).canSetup 'Setup should be available.'
$good=$false
$row=(BridgeAdapters).adapters[0]
Assert (!$row.available -and !$row.bound) 'A blocked physical adapter must remain visible.'
foreach ($phrase in 'vendor_filter','ms_implat','IPv6 is not bound','static DNS server','static DNS suffix','VLAN','DHCP is disabled','custom interface metric','custom MTU','weak-host','forwarding','static IP','persistent static route','default IPv4 route','IPv4 DNS server','NetBIOS') {
    Assert ($row.reason.Contains($phrase)) "Missing bridge refusal: $phrase"
}
Assert (@($row.reasons | Where-Object {$_ -like '*static DNS server*'}).Count -eq 1) 'Repeated reasons should be grouped.'
$check=ResolveBridge $p
Assert (!$check.canSetup -and $check.reasons.Count -eq $row.reasons.Count) 'Registered adapter lost its refusal reasons.'
$bound=@([pscustomobject]@{Id=[guid]::NewGuid();Name='Shared';Notes='';SwitchType='External';EmbeddedTeamingEnabled=$false;AllowManagementOS=$true;NetAdapterInterfaceGuid=$link.InterfaceGuid})
$row=(BridgeAdapters).adapters[0]
Assert ($row.available -and $row.bound -and $row.switchGuid -eq $bound[0].Id) 'Reusing a compatible shared switch must not apply creation-only policy.'
$bound[0].EmbeddedTeamingEnabled=$true
$row=(BridgeAdapters).adapters[0]
Assert (!$row.available -and $row.bound -and $row.reason.Contains('team')) 'An incompatible bound adapter must remain distinct from an unbound one.'
