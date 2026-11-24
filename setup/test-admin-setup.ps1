#Requires -Version 5.1
# Run this file unelevated in Windows PowerShell. It never invokes the administrator script.
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$tokens = $null
$errors = $null
$setupPath = Join-Path $PSScriptRoot 'svm-admin-setup.ps1'
$ast = [Management.Automation.Language.Parser]::ParseFile($setupPath,[ref]$tokens,[ref]$errors)
if ($errors.Count) { throw $errors[0].Message }
$include = @('Pending-Observation','Resolve-PendingPlain','Bridge-Hardware','Check-BridgeHardware','Bridge-Equal',
    'Undo-Bridge','Bridge-Record','Net-U32','Network-Address','New-Entry','Change','Nat-State','Nat-Matches',
    'Test-RoutedNatRange','Add-ProjectNat','Undo-ProjectNat','Undo-Entry','Bridge-Link','Bridge-Identity','Bridge-NoGuests')
$functions = @($ast.EndBlock.Statements | Where-Object {
    $_ -is [Management.Automation.Language.FunctionDefinitionAst] -and $include -ccontains $_.Name })
if ($functions.Count -ne $include.Count) { throw 'The selected setup functions changed. Review the test list.' }
$caseMarker = '# In-memory' + ' test cases'
$testFile = [IO.File]::ReadAllText($PSCommandPath)
$cases = $testFile.Substring($testFile.IndexOf($caseMarker,[StringComparison]::Ordinal) + $caseMarker.Length)
# Only functions are imported. The setup entry point, elevation, mutex, journal and host providers never run.
$state = [Management.Automation.Runspaces.InitialSessionState]::CreateDefault2()
$space = [RunspaceFactory]::CreateRunspace($state)
$space.Open()
$ps = [PowerShell]::Create()
try {
    $ps.Runspace = $space
    [void]$ps.AddScript({
        $ErrorActionPreference='Stop'
        $PSModuleAutoLoadingPreference='None'
        Import-Module ([IO.Path]::Combine($PSHOME,'Modules\Microsoft.PowerShell.Utility\Microsoft.PowerShell.Utility.psd1'))
        Set-StrictMode -Version Latest
    }).Invoke()
    if ($ps.HadErrors) { throw $ps.Streams.Error[0] }
    $ps.Commands.Clear()
    # Install fail-closed network mocks before dot-sourcing function definitions. Dynamic binding changes are included.
    $names = @($functions | ForEach-Object {
        $_.FindAll({param($node) $node -is [Management.Automation.Language.CommandAst]},$true) |
            ForEach-Object { $_.GetCommandName() } | Where-Object { $_ -match '^(Get|Set|New|Remove|Enable|Disable)-(Net|VM|Dns)' }
    }) + @('Enable-NetAdapterBinding','Disable-NetAdapterBinding')
    $mocks = foreach ($name in @($names | Sort-Object -Unique)) { "function $name { throw 'Unexpected fake command $name' }" }
    $loaded = ($functions | ForEach-Object { $_.Extent.Text }) -join [Environment]::NewLine
    $space.SessionStateProxy.SetVariable('fixtureDefinitions',$loaded)
    $program = ($mocks -join [Environment]::NewLine) + [Environment]::NewLine +
        '. ([scriptblock]::Create($fixtureDefinitions))' + [Environment]::NewLine + $cases +
        [Environment]::NewLine + '"Setup fixture passed $script:checks assertions."'
    [void]$ps.AddScript($program)
    $output = $ps.Invoke()
    if ($ps.HadErrors) { throw $ps.Streams.Error[0] }
    $output
} finally { $ps.Dispose(); $space.Dispose() }
return

# In-memory test cases
$script:checks=0
$script:log=[Collections.ArrayList]::new()
$script:saves=0
$changes=[Collections.ArrayList]::new()
$script:setupPath='C:\fixture\svm-admin-setup.ps1'
$script:setupCmdlet=[pscustomobject]@{}
$script:setupCmdlet | Add-Member -MemberType ScriptMethod -Name ShouldProcess -Value {param($target,$action) return $true}
function Check([bool]$condition,[string]$description) {
    if (!$condition) { throw "Assertion failed: $description" }
    $script:checks++
}
function ExpectFailure([scriptblock]$operation,[string]$description) {
    try { & $operation } catch {
        if ($_.Exception.Message.IndexOf($description,[StringComparison]::OrdinalIgnoreCase) -lt 0) { throw }
        $script:checks++
        return
    }
    throw "Expected refusal containing '$description'."
}
function Save-Journal { $script:saves++ }
function Record-Result([string]$message) { [void]$script:log.Add($message) }
function Write-Warning([string]$Message) { [void]$script:log.Add("Warning: $Message") }
function Write-Host([string]$Object) {}
# NAT cases
& {
    $script:nat=$null
    $script:mappings=@()
    $script:external=@()
    $script:addresses=@()
    $script:creations=0
    $script:removals=0
    $changes.Clear()
    function Owned-Adapter($id,$guid) {
        $index = switch ($id) { 'first' {11} 'second' {12} default {throw 'Unexpected network lookup'} }
        [pscustomobject]@{ifIndex=$index}
    }
    function Get-NetIPAddress { param($AddressFamily,$ErrorAction) $script:addresses }
    function Get-NetNat { param($ErrorAction) if ($null -ne $script:nat) { $script:nat } }
    function Get-NetNatStaticMapping { param($ErrorAction) $script:mappings }
    function Get-NetNatExternalAddress { param($ErrorAction) $script:external }
    function New-NetNat {
        param($Name,$InternalIPInterfaceAddressPrefix,$ErrorAction,[switch]$Confirm)
        Check ($changes.Count -eq 1 -and $changes[0].pending -and $changes[0].rule -ceq $Name) 'NAT identity journaled before creation'
        $script:creations++
        $script:nat=[pscustomobject]@{Name=$Name;InternalIPInterfaceAddressPrefix=$InternalIPInterfaceAddressPrefix;UdpIdleSessionTimeout=120}
        $script:nat
    }
    function Remove-NetNat {
        param($Name,[switch]$Confirm,$ErrorAction)
        Check ($null -ne $script:nat -and $Name -ceq $script:nat.Name) 'removal selects the recorded simulated NAT'
        $script:removals++
        $script:nat=$null
    }
    $a=[pscustomobject]@{id='first';mode='Routed';subnet='10.77.1.0/24';gateway='10.77.1.1';switchGuid=[guid]::NewGuid()}
    $b=[pscustomobject]@{id='second';mode='Routed';subnet='10.77.22.0/24';gateway='10.77.22.1';switchGuid=[guid]::NewGuid()}
    $outside=[pscustomobject]@{id='outside';mode='Routed';subnet='192.168.82.0/24';gateway='192.168.82.1'}
    $local=[pscustomobject]@{id='old-local';mode='Host-only';subnet='10.77.72.0/24';gateway='10.77.72.1'}
    Add-ProjectNat @($outside)
    Check ($script:creations -eq 0 -and $changes.Count -eq 0) 'an outside-range network stays local'
    ExpectFailure { Add-ProjectNat @($a,$local) } 'old-local'
    $script:addresses=@([pscustomobject]@{InterfaceIndex=99;InterfaceAlias='Foreign';IPAddress='10.77.95.7';PrefixLength=24})
    ExpectFailure { Add-ProjectNat @($a,$b) } 'Foreign'
    Check ($script:creations -eq 0) 'overlaps refuse before creating a NAT'
    $script:addresses=@([pscustomobject]@{InterfaceIndex=11;InterfaceAlias='First';IPAddress='10.77.1.1';PrefixLength=24},
        [pscustomobject]@{InterfaceIndex=12;InterfaceAlias='Second';IPAddress='10.77.22.1';PrefixLength=24})
    Add-ProjectNat @($a,$b,$outside)
    Add-ProjectNat @($b,$a)
    Check ($script:creations -eq 1 -and $changes.Count -eq 1 -and !$changes[0].pending) 'two subnets share one NAT across reruns'
    Check ($script:nat.InternalIPInterfaceAddressPrefix -eq '10.77.0.0/16' -and $script:nat.Name -cmatch '^SVM-Routed-[0-9a-f]{32}$') 'exact aggregate and generated identity'
    $entry=$changes[0]
    $script:mappings=@([pscustomobject]@{NatName=$script:nat.Name})
    ExpectFailure { Undo-ProjectNat $entry } 'mappings'
    $script:mappings=@()
    $script:nat.UdpIdleSessionTimeout=240
    ExpectFailure { Undo-ProjectNat $entry } 'changed'
    $script:nat.UdpIdleSessionTimeout=120
    Undo-ProjectNat $entry
    Undo-ProjectNat $entry
    Check ($script:removals -eq 1 -and $null -eq $script:nat) 'verified undo and second undo'
    $changes.Clear()
    $script:nat=[pscustomobject]@{Name='Foreign';InternalIPInterfaceAddressPrefix='10.77.0.0/16'}
    Add-ProjectNat @($a,$b)
    Undo-ProjectNat $entry
    Check ($changes.Count -eq 0 -and $script:nat.Name -ceq 'Foreign' -and $script:removals -eq 1) 'foreign same-prefix NAT preserved'
    $old=[pscustomobject]@{kind='win-nat';pending=$false;id='first';rule=('SecwizVM-NAT-'+[guid]::NewGuid().ToString('N'));ip='10.77.1.0/24'}
    $script:nat=[pscustomobject]@{Name=$old.rule;InternalIPInterfaceAddressPrefix=$old.ip}
    [void]$changes.Add($old)
    Add-ProjectNat @($a,$b)
    Check ($changes.Count -eq 1 -and $script:creations -eq 1) 'legacy journal awaits verified migration'
    Undo-Entry $old
    Check ($script:removals -eq 2 -and $null -eq $script:nat) 'legacy per-switch NAT still removable'
    $changes.Clear()
}



# BEGIN recovery/bridge cases
& {
    $changes.Clear()
    $nic=[pscustomobject]@{ Name='fixture internal'; InterfaceGuid=[guid]::NewGuid(); ifIndex=42 }
    $switchId=[guid]::NewGuid()
    $script:plainAddresses=@{ActiveStore=@(); PersistentStore=@()}
    $flags=@{
        ActiveStore=[pscustomobject]@{Dhcp='Enabled';Forwarding='Disabled'}
        PersistentStore=[pscustomobject]@{Dhcp='Enabled';Forwarding='Disabled'}
    }
    $writes=[Collections.ArrayList]::new()
    function Owned-Adapter($id,$guid) { $nic }
    function Get-NetIPAddress { param($PolicyStore,$AddressFamily,$InterfaceIndex,$ErrorAction)
        if (!$PolicyStore) { $PolicyStore='ActiveStore' }
        $script:plainAddresses[$PolicyStore]
    }
    function Get-NetIPInterface { param($PolicyStore,$AddressFamily,$InterfaceIndex,$ErrorAction)
        if (!$PolicyStore) { $PolicyStore='ActiveStore' }
        $flags[$PolicyStore]
    }
    function Remove-NetIPAddress { param($PolicyStore,$InterfaceIndex,$IPAddress,$Confirm)
        if ($InterfaceIndex -ne $nic.ifIndex -or $IPAddress -ne '10.77.3.1') { throw 'Unexpected address target' }
        $script:plainAddresses[$PolicyStore]=@()
        [void]$writes.Add("remove $PolicyStore")
    }
    function Set-NetIPInterface { param($AddressFamily,$InterfaceIndex,$Dhcp,$Forwarding,$Confirm)
        if ($InterfaceIndex -ne $nic.ifIndex) { throw 'Unexpected IP interface target' }
        [void]$writes.Add("DHCP=$Dhcp forwarding=$Forwarding")
    }
    function Interrupted($kind) {
        $entry=New-Entry $kind $nic 'unit-net' $switchId
        if ($kind -eq 'address') { $entry.ip='10.77.3.1'; $entry.prefix=24 }
        [void]$changes.Add($entry)
        return $entry
    }
    $manual=[pscustomobject]@{InterfaceIndex=42;IPAddress='10.77.3.1';PrefixLength=24;PrefixOrigin='Manual'}
    foreach ($kind in @('address','dhcp-client','guest-forward')) {
        $null=Interrupted $kind
        Resolve-PendingPlain
        Check ($changes.Count -eq 0) "An interrupted $kind still at baseline is dropped."
    }
    $dhcp=Interrupted 'dhcp-client'; $entry=Interrupted 'address'; $forward=Interrupted 'guest-forward'
    foreach ($store in @('ActiveStore','PersistentStore')) {
        $flags[$store].Dhcp='Disabled'; $flags[$store].Forwarding='Enabled'; $script:plainAddresses[$store]=@($manual)
    }
    Resolve-PendingPlain
    Check (!$dhcp.pending -and !$entry.pending -and !$forward.pending -and $changes.Count -eq 3) 'All three exact changes remain available for undo.'
    Check ($writes.Count -eq 0) 'Automatic reconciliation never mutates IP settings.'
    ExpectFailure { Undo-Entry $dhcp } 'another manual address'
    Undo-Entry $forward; Undo-Entry $entry; Undo-Entry $dhcp
    Check (($writes -join '|') -eq 'DHCP= forwarding=Disabled|remove PersistentStore|remove ActiveStore|DHCP=Enabled forwarding=') 'Ordinary rollback after recovery uses only the owned settings, in the safe order.'
    $changes.Clear()
    $entry=Interrupted 'address'; $script:plainAddresses.ActiveStore=@($manual)
    $status=Pending-Observation $entry
    Check ($status.state -eq 'conflict' -and $status.found -like '*PersistentStore=<none>*') 'Half-applied address names the inconsistent stores.'
    try { Resolve-PendingPlain; throw 'Expected reviewed release command.' } catch {
        $message=$_.Exception.Message
        if ($message -notmatch '-ReleasePending ([a-f0-9]{64})') { throw }
        $release=$Matches[1]
    }
    Check ($message.Contains($nic.Name) -and $message.Contains('10.77.3.1/24 Manual') -and $entry.pending) 'Conflict names the adapter and expected state, preserving its record.'
    $manual.PrefixLength=25
    ExpectFailure { Resolve-PendingPlain -ReleaseToken $release } 'observed settings changed'
    $manual.PrefixLength=24
    Resolve-PendingPlain -ReleaseToken $release
    Check ($changes.Count -eq 0 -and $script:plainAddresses.ActiveStore.Count -eq 1 -and $writes.Count -eq 4) 'Reviewed release drops only the journal claim and preserves live state.'
    $entry=Interrupted 'dhcp-client'
    $flags.ActiveStore.Dhcp='Enabled'
    Check ((Pending-Observation $entry).state -eq 'conflict') 'A reboot-dependent DHCP discrepancy is preserved.'
    $entry.adapterGuid=[guid]::NewGuid()
    Check ((Pending-Observation $entry).found -like '*GUID*differs*') 'A replacement adapter cannot inherit a journal claim.'
    $changes.Clear()
}

& {
    $changes.Clear()
    $physical=[pscustomobject]@{InterfaceGuid=[guid]::NewGuid();InterfaceType=6;Name='fixture ethernet';MacAddress='02-33-44-55-66-77';InterfaceDescription='fixture hardware'}
    $hostLink=[pscustomobject]@{InterfaceGuid=[guid]::NewGuid()}
    $switch=[pscustomobject]@{Id=[guid]::NewGuid();Name='SVM-bridge';SwitchType='External';Notes='secwiz-bridge:bridge';
        EmbeddedTeamingEnabled=$false;AllowManagementOS=$true;NetAdapterInterfaceGuid=$physical.InterfaceGuid}
    $runtime=@{ switch=$switch; guests=$false; removeCount=0; vlan='0x00'; vmq='disabled' }
    $binding=[pscustomobject]@{id='ms_tcpip';enabled=$true}
    $policy=[ordered]@{dhcp4='Enabled'}
    function Get-NetAdapter { param([switch]$Physical) if ($Physical) { $runtime.link } }
    $runtime.link=$physical
    function Get-NetAdapterAdvancedProperty { param($Name,[switch]$AllProperties)
        [pscustomobject]@{RegistryKeyword='VlanID';RegistryValue=$runtime.vlan}
        [pscustomobject]@{RegistryKeyword='VMQ';RegistryValue=$runtime.vmq}
    }
    function Get-VMSwitch { param($Id) if ($runtime.switch -and (!$Id -or $runtime.switch.Id -eq $Id)) { $runtime.switch } }
    function Get-VMNetworkAdapter { param([switch]$ManagementOS,[switch]$All)
        if ($ManagementOS) { [pscustomobject]@{SwitchId=$switch.Id;Name=$switch.Name} }
        if ($All -and $runtime.guests) { [pscustomobject]@{SwitchId=$switch.Id;IsManagementOs=$false} }
    }
    function Get-VM {}
    function Bridge-Vnic($sw) { $hostLink }
    function Bridge-Policy($link) { $policy }
    function Bridge-Bindings($link) { $binding }
    function Bridge-Bound($link) { if ($runtime.switch) { $runtime.switch } }
    function Bridge-Wait($entry,$sw) { $physical }
    function Remove-VMSwitch { param($VMSwitch,[switch]$Force,$ErrorAction)
        if ($VMSwitch.Id -ne $switch.Id -or !$Force) { throw 'Unexpected switch removal target' }
        $runtime.removeCount++; $runtime.switch=$null
    }
    $saved=[ordered]@{alias='formerly named ethernet';mac='02:33:44:55:66:77';description=$physical.InterfaceDescription;
        properties=@([pscustomobject]@{key='VlanID';value='0'},[pscustomobject]@{key='VMQ';value='enabled'})}
    $entry=[pscustomobject]@{kind='bridge';id='bridge';alias=$saved.alias;adapterGuid=$physical.InterfaceGuid;hardware=$saved;
        switchGuid=$switch.Id.ToString('D');hostGuid=$hostLink.InterfaceGuid;bound=@($binding);bindings=@($binding);policy=$policy;pending=$false;phase='ready'}
    [void]$changes.Add($entry)
    $runtime.vlan='10'
    ExpectFailure { Undo-Bridge 'bridge' } 'VLAN setting'
    $runtime.vlan='0x00'; $physical.MacAddress='02-00-00-00-00-00'
    ExpectFailure { Undo-Bridge 'bridge' } 'GUID, MAC or description'
    $physical.MacAddress='02-33-44-55-66-77'; $physical.InterfaceDescription='different'
    ExpectFailure { Undo-Bridge 'bridge' } 'GUID, MAC or description'
    $physical.InterfaceDescription='fixture hardware'; $runtime.guests=$true
    ExpectFailure { Undo-Bridge 'bridge' } 'guest or checkpoint'
    Check ($runtime.removeCount -eq 0 -and $changes.Contains($entry)) 'Identity drift and connected guests block removal without changing the journal.'
    $runtime.guests=$false
    $script:log.Clear()
    Undo-Bridge 'bridge'
    Check ($runtime.removeCount -eq 1 -and $changes.Count -eq 0) 'Real Undo-Bridge removes the one owned mock switch despite driver drift.'
    Check (@($script:log | Where-Object { $_ -like 'Driver setting VMQ*enabled*disabled*' }).Count -ge 2) 'Driver drift is audited both before and after simulated removal.'
    Check (@($script:log | Where-Object { $_ -like 'Warning: Driver setting VMQ*' }).Count -ge 2) 'The driver-property difference is also shown to the operator.'
}
# END recovery/bridge cases
