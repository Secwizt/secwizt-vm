#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    [switch] $Remove,
    [string] $ServiceExe,
    [string] $BridgeId,
    [guid] $AdapterGuid,
    [ValidatePattern('^[a-fA-F0-9]{64}$')][string] $ReleasePending
)
if ($PSVersionTable.PSEdition -ne 'Desktop') { throw 'Use Windows PowerShell 5.1 for the administrator setup.' }
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
# Load modules only from Windows PowerShell's own folder, never from a folder the user can write.
$env:PSModulePath = Join-Path $PSHOME 'Modules'
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Open an elevated PowerShell window for this setup.'
}
$ownerSid = $identity.User.Value
$programs = [Environment]::GetFolderPath([Environment+SpecialFolder]::ProgramFiles)
$journalRoot = Join-Path $programs "SecwizVM Setup\$ownerSid"
$journal = Join-Path $journalRoot 'changes.json'
$log = Join-Path $journalRoot 'admin-setup.log'
$ruleGroup = "SecwizVM $ownerSid"
$changes = [Collections.ArrayList]::new()

function Check-LocalPath([string]$path) {
    if ($path.StartsWith('\\') -or -not [IO.Path]::IsPathRooted($path)) { throw 'Use a local absolute path.' }
    $cursor = [IO.Path]::GetFullPath($path)
    while ($cursor) {
        if (Test-Path -LiteralPath $cursor) {
            $item = Get-Item -LiteralPath $cursor -Force
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw "A linked path is not eligible: $cursor" }
        }
        $cursor = [IO.Path]::GetDirectoryName($cursor)
    }
}

function Write-Snapshot([string]$file,[string]$text) {
    if ($file -notin @($journal,$log)) { throw 'Only the protected setup records can be written.' }
    Protect-JournalPath -Create
    $temp = Join-Path $journalRoot ([guid]::NewGuid().ToString() + '.tmp')
    $admins = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
    $system = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')
    $fileAcl = [Security.AccessControl.FileSecurity]::new()
    $fileAcl.SetOwner($admins)
    $fileAcl.SetAccessRuleProtection($true,$false)
    foreach ($sid in @($admins,$system)) {
        $fileAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sid,'FullControl','Allow'))
    }
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes($text)
    $stream = [IO.FileStream]::new($temp,[IO.FileMode]::CreateNew,[Security.AccessControl.FileSystemRights]::Write,
        [IO.FileShare]::None,4096,[IO.FileOptions]::None,$fileAcl)
    try {
        try {
            $stream.Write($bytes,0,$bytes.Length)
            $stream.Flush($true)
        } finally { $stream.Dispose() }
        # Publish a new directory entry. Never truncate or append to an existing file in place.
        if ([IO.File]::Exists($file)) { [IO.File]::Replace($temp,$file,[System.Management.Automation.Language.NullString]::Value) }
        else { [IO.File]::Move($temp,$file) }
    } finally { if ([IO.File]::Exists($temp)) { [IO.File]::Delete($temp) } }
}

function Protect-JournalPath([switch]$Create) {
    $admins = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
    $system = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')
    $security = [Security.AccessControl.DirectorySecurity]::new()
    $security.SetOwner($admins)
    $security.SetAccessRuleProtection($true,$false)
    foreach ($sid in @($admins,$system)) {
        $rule = [Security.AccessControl.FileSystemAccessRule]::new($sid,'FullControl','ContainerInherit,ObjectInherit','None','Allow')
        $security.AddAccessRule($rule)
    }
    $paths = @([IO.Path]::GetDirectoryName($journalRoot), $journalRoot, $journal, $log)
    foreach ($path in $paths) {
        $isRecord = $path -in @($journal,$log)
        Check-LocalPath $path
        if (-not [IO.Directory]::Exists($path) -and -not [IO.File]::Exists($path)) {
            if ($Create -and -not $isRecord) { [void][IO.Directory]::CreateDirectory($path,$security) }
            else { continue }
        }
        $item = Get-Item -LiteralPath $path -Force
        if ($item.PSIsContainer -eq $isRecord -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'A setup record or its folder has an unexpected file type.'
        }
        $linkType = $item.PSObject.Properties['LinkType']
        if ($isRecord -and $null -ne $linkType -and $linkType.Value -eq 'HardLink') {
            throw 'A protected setup record has more than one filesystem link.'
        }
        $acl = Get-Acl -LiteralPath $path
        if ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin @($admins.Value,$system.Value)) {
            throw 'A protected setup record or its folder has an unexpected owner.'
        }
        foreach ($ace in $acl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier])) {
            if ($ace.AccessControlType.ToString() -eq 'Allow' -and
                $ace.IdentityReference.Value -notin @($admins.Value,$system.Value)) {
                throw 'A protected setup record or its folder grants access to an unexpected account.'
            }
        }
    }
}

function Save-Journal {
    Write-Snapshot $journal (ConvertTo-Json -InputObject @($changes.ToArray()) -Depth 6)
}

function Record-Result([string]$message) {
    Protect-JournalPath
    $prior = if ([IO.File]::Exists($log)) { [IO.File]::ReadAllText($log) } else { '' }
    Write-Snapshot $log ($prior + [DateTimeOffset]::Now.ToString('o') + ' ' + $message + [Environment]::NewLine)
}

function Owned-Adapter([string]$id,[string]$guid) {
    if ($id -cnotmatch '^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,79}$') { throw 'Invalid project network ID.' }
    $switchName = "SVM-$id"
    $found = @(Get-VMSwitch | Where-Object { $_.Name -ieq $switchName })
    if ($found.Count -eq 0) { return $null }
    if ($found.Count -ne 1 -or $found[0].Name -cne $switchName -or
        $found[0].Id.ToString() -ine $guid -or $found[0].SwitchType.ToString() -ne 'Internal' -or
        $found[0].Notes -cne "secwiz-switch:$id") { throw "The recorded switch identity has changed for $id." }
    $vnics = @(Get-VMNetworkAdapter -ManagementOS | Where-Object { $_.SwitchId -eq $found[0].Id -and $_.Name -ceq $switchName })
    if ($vnics.Count -ne 1) { throw "The host adapter of $switchName is ambiguous." }
    $adapters = @(Get-NetAdapter -IncludeHidden | Where-Object {
        $_.Name -ceq "vEthernet ($switchName)" -and ($_.MacAddress -replace '[-:]','') -ieq $vnics[0].MacAddress
    })
    if ($adapters.Count -ne 1) { throw "The Windows adapter does not match $switchName." }
    return $adapters[0]
}

function Net-U32([string]$address) {
    $ip = [Net.IPAddress]::Parse($address)
    if ($ip.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork) { throw 'This operation requires IPv4.' }
    $b = $ip.GetAddressBytes()
    return ([uint64]$b[0]*16777216 + [uint64]$b[1]*65536 + [uint64]$b[2]*256 + $b[3])
}

function Network-Address($n) {
    $parts = @($n.subnet.Split('/'))
    if ($parts.Count -ne 2 -or $parts[1] -notmatch '^(?:[0-9]|[12][0-9]|30)$') { throw 'Invalid subnet prefix.' }
    $prefix = [int]$parts[1]
    $base = Net-U32 $parts[0]
    $length = [uint64][Math]::Pow(2,32-$prefix)
    $last = $base + $length - 1
    $gateway = Net-U32 $n.gateway
    if ($base % $length -ne 0 -or $gateway -le $base -or $gateway -ge $last) { throw 'Invalid gateway in a project network.' }
    $private = ($base -ge 167772160 -and $last -le 184549375) -or
        ($base -ge 2886729728 -and $last -le 2887778303) -or ($base -ge 3232235520 -and $last -le 3232301055)
    if (-not $private) { throw 'The setup only assigns private IPv4 subnets to internal adapters.' }
    return $prefix
}

function New-Entry([string]$kind,$adapter,[string]$id,[string]$guid) {
    return [pscustomobject]@{ kind=$kind; id=$id; switchGuid=$guid; adapterGuid=$adapter.InterfaceGuid.ToString();
        alias=$adapter.Name; ip=''; prefix=0; rule=''; program=''; pending=$true }
}

function Change($entry,[string]$description,[scriptblock]$apply) {
    Write-Host $description
    if (-not $script:setupCmdlet.ShouldProcess($entry.alias,$description)) { return }
    Record-Result "Starting: $description"
    [void]$changes.Add($entry)
    Save-Journal
    # Leave a pending record on error so an interrupted operation is never silently claimed.
    & $apply
    $entry.pending = $false
    Save-Journal
    Record-Result "Applied: $description"
}

function Pending-Observation($entry) {
    $expected = switch ($entry.kind) {
        'address' { "$($entry.ip)/$($entry.prefix) Manual" }
        'dhcp-client' { 'DHCP Disabled' }
        'guest-forward' { 'Forwarding Enabled' }
        default { throw 'Unsupported interrupted network change.' }
    }
    $found = [Collections.Generic.List[string]]::new()
    $stores = @()
    try {
        $adapter = Owned-Adapter $entry.id $entry.switchGuid
        if (!$adapter) { throw 'The recorded switch is missing.' }
        if ([guid]$adapter.InterfaceGuid -ne [guid]$entry.adapterGuid) {
            throw "Adapter GUID $($adapter.InterfaceGuid) differs from recorded $($entry.adapterGuid)."
        }
        foreach ($store in @('ActiveStore','PersistentStore')) {
            if ($entry.kind -eq 'address') {
                # An empty result is meaningful only after a successful inventory. NetTCPIP
                # can signal no matching rows as an error if an address is queried directly.
                $rows = @(Get-NetIPAddress -PolicyStore $store -AddressFamily IPv4 -ErrorAction Stop |
                    Where-Object { $_.InterfaceIndex -eq $adapter.ifIndex })
                $target = @($rows | Where-Object { $_.IPAddress -eq $entry.ip })
                $description = @($rows | ForEach-Object { "$($_.IPAddress)/$($_.PrefixLength) $($_.PrefixOrigin)" } | Sort-Object)
                $foreign = @($rows | Where-Object { $_.IPAddress -ne $entry.ip -and
                    ($store -eq 'PersistentStore' -or !$_.IPAddress.StartsWith('169.254.')) })
                if ($target.Count -eq 1 -and $target[0].PrefixLength -eq $entry.prefix -and [string]$target[0].PrefixOrigin -eq 'Manual') {
                    $state = 'applied'
                } elseif (!$target.Count -and !$foreign.Count) { $state = 'absent' } else { $state = 'conflict' }
            } else {
                $rows = @(Get-NetIPInterface -PolicyStore $store -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -ErrorAction Stop)
                $flag = if ($entry.kind -eq 'dhcp-client') { 'Dhcp' } else { 'Forwarding' }
                $desired = if ($entry.kind -eq 'dhcp-client') { 'Disabled' } else { 'Enabled' }
                $description = @($rows | ForEach-Object { [string]$_.$flag } | Sort-Object)
                $state = 'conflict'
                if ($description.Count -eq 1 -and $description[0] -in @('Enabled','Disabled')) {
                    $state = if ($description[0] -eq $desired) { 'applied' } else { 'absent' }
                }
            }
            $detail = if ($description.Count) { $description -join ', ' } else { '<none>' }
            $found.Add($store + '=' + $detail)
            $stores += $state
        }
    } catch { $found.Add($_.Exception.Message) }
    $state = if ($stores.Count -eq 2 -and $stores[0] -eq $stores[1]) { $stores[0] } else { 'conflict' }
    return [pscustomobject]@{state=$state; expected=$expected; found=($found -join '; ')}
}

function Resolve-PendingPlain([string]$ReleaseToken) {
    $problems = [Collections.Generic.List[string]]::new()
    $selected = @()
    foreach ($entry in @($changes.ToArray())) {
        if (!$entry.pending -or $entry.kind -notin @('address','dhcp-client','guest-forward')) { continue }
        $status = Pending-Observation $entry
        $name = "$($entry.kind) on $($entry.alias) ($($entry.adapterGuid))"
        if ($status.state -eq 'conflict') {
            # Bind manual release to this entry and the exact two-store observation.
            $identity = @($entry.kind,$entry.id,$entry.switchGuid,$entry.adapterGuid,$entry.ip,$entry.prefix,$status.expected,$status.found)
            $hash = [Security.Cryptography.SHA256]::Create()
            try { $token = [BitConverter]::ToString($hash.ComputeHash([Text.Encoding]::UTF8.GetBytes(
                (ConvertTo-Json -InputObject $identity -Compress)))).Replace('-','').ToLowerInvariant() }
            finally { $hash.Dispose() }
            if ($ReleaseToken) {
                if ($ReleaseToken -ieq $token) { $selected += $entry }
            } else {
                $cmd = "& '" + $script:setupPath.Replace("'","''") + "' -ReleasePending " + $token
                $problems.Add("Interrupted $name expected $($status.expected); found $($status.found). After review, keep the current network settings and clear this record with: $cmd")
            }
            continue
        }
        if ($ReleaseToken) { continue }
        $description = if ($status.state -eq 'applied') { "Mark applied: $name" } else { "Drop unapplied change: $name" }
        if (!$script:setupCmdlet.ShouldProcess($entry.alias,$description)) { continue }
        Record-Result "$description. Verified $($status.found)."
        if ($status.state -eq 'applied') { $entry.pending = $false } else { [void]$changes.Remove($entry) }
        Save-Journal
    }
    if ($ReleaseToken) {
        if ($selected.Count -ne 1) { throw 'The entry or its observed settings changed. Run setup again for the current recovery command.' }
        $entry = $selected[0]
        $action = "Release the interrupted $($entry.kind) record for $($entry.adapterGuid), preserving current network settings"
        if ($script:setupCmdlet.ShouldProcess($entry.alias,$action)) {
            Record-Result "$action. Operator reviewed observation $ReleaseToken."
            [void]$changes.Remove($entry)
            Save-Journal
        }
    } elseif ($problems.Count) { throw ($problems -join [Environment]::NewLine) }
}

function Rule-Matches($rule,$entry) {
    if ($rule.Group -cne $ruleGroup -or $rule.Name -cne $entry.rule -or $rule.Direction.ToString() -ne 'Inbound' -or
        $rule.Action.ToString() -ne 'Allow') { return $false }
    $port = $rule | Get-NetFirewallPortFilter
    $iface = $rule | Get-NetFirewallInterfaceFilter
    $addr = $rule | Get-NetFirewallAddressFilter
    $app = $rule | Get-NetFirewallApplicationFilter
    if ($entry.kind -eq 'dns-firewall') {
        return ($rule.Enabled.ToString() -eq 'True' -and $rule.Profile.ToString() -eq 'Any' -and
            $port.Protocol.ToString() -in @('UDP','17') -and (@($port.LocalPort) -join ',') -ceq '53' -and
            (@($port.RemotePort) -join ',') -ieq 'Any' -and (@($iface.InterfaceAlias) -join ',') -ceq $entry.alias -and
            (@($addr.LocalAddress) -join ',') -ceq $entry.ip -and (@($addr.RemoteAddress) -join ',') -ieq 'LocalSubnet' -and
            $app.Program -ieq $entry.program)
    }
    return (($port.Protocol.ToString() -in @('UDP','17')) -and
        (@($port.LocalPort) -join ',') -ceq '67' -and (@($iface.InterfaceAlias) -join ',') -ceq $entry.alias -and
        (@($addr.LocalAddress) -join ',') -ieq 'Any' -and (@($port.RemotePort) -join ',') -ceq '68' -and $app.Program -ieq $entry.program)
}

function Undo-Entry($entry) {
    if ($entry.pending -and $entry.kind -notin @('win-nat','host-dns','dns-firewall','firewall')) { throw 'An interrupted setup needs inspection before rollback. See the protected change journal.' }
    if ($entry.kind -eq 'win-nat') { Undo-ProjectNat $entry; return }
    if ($entry.kind -eq 'host-dns') { Undo-HostDns $entry; return }
    if ($entry.kind -in @('firewall','dns-firewall')) {
        if ($entry.rule -cnotmatch '^SecwizVM [a-f0-9-]{36}$') { throw 'Invalid firewall identity in the journal.' }
        $existing = @(Get-NetFirewallRule -PolicyStore PersistentStore | Where-Object { $_.Name -ceq $entry.rule })
        if ($existing.Count -eq 0) { return }
        if ($existing.Count -ne 1 -or -not (Rule-Matches $existing[0] $entry)) {
            throw 'The recorded firewall rule has changed. It was left in place.'
        }
        $existing[0] | Remove-NetFirewallRule -Confirm:$false
        return
    }
    if ($entry.kind -eq 'lan-forward') {
        $links = @(Get-NetAdapter -Physical | Where-Object { $_.InterfaceGuid.ToString() -ieq $entry.adapterGuid })
        if ($links.Count -eq 0) { return }
        if ($links.Count -ne 1) { throw 'The recorded physical adapter is ambiguous.' }
        $adapter = $links[0]
    } else {
        $adapter = Owned-Adapter $entry.id $entry.switchGuid
        if ($null -eq $adapter) { return }
        if ($adapter.InterfaceGuid.ToString() -ine $entry.adapterGuid) { throw 'The host adapter identity changed. No change made.' }
    }
    if ($entry.kind -eq 'address') {
        foreach ($store in @('PersistentStore','ActiveStore')) {
            $ips = @(Get-NetIPAddress -PolicyStore $store -AddressFamily IPv4 | Where-Object { $_.InterfaceIndex -eq $adapter.ifIndex -and $_.IPAddress -ceq $entry.ip })
            if ($ips.Count -eq 0) { continue }
            if ($ips.Count -ne 1 -or $ips[0].PrefixLength -ne $entry.prefix -or $ips[0].PrefixOrigin.ToString() -ne 'Manual') {
                throw 'The recorded address was reconfigured. No change made.'
            }
            Remove-NetIPAddress -PolicyStore $store -InterfaceIndex $adapter.ifIndex -IPAddress $entry.ip -Confirm:$false
        }
    } elseif ($entry.kind -in @('lan-forward','guest-forward')) {
        $iface = Get-NetIPInterface -AddressFamily IPv4 -InterfaceIndex $adapter.ifIndex
        if ($iface.Forwarding.ToString() -eq 'Enabled') {
            Set-NetIPInterface -AddressFamily IPv4 -InterfaceIndex $adapter.ifIndex -Forwarding Disabled -Confirm:$false
        }
    } elseif ($entry.kind -eq 'dhcp-client') {
        $iface = Get-NetIPInterface -AddressFamily IPv4 -InterfaceIndex $adapter.ifIndex
        if ($iface.Dhcp.ToString() -eq 'Disabled') {
            $manual = @(Get-NetIPAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 | Where-Object { $_.PrefixOrigin.ToString() -eq 'Manual' })
            if ($manual.Count -ne 0) { throw 'The adapter has another manual address. DHCP client settings were preserved.' }
            Set-NetIPInterface -AddressFamily IPv4 -InterfaceIndex $adapter.ifIndex -Dhcp Enabled -Confirm:$false
        }
    } else { throw 'Unknown change in the protected journal.' }
}

function Nat-State($nat) {
    # Compare properties controlled by administrators, excluding transient activity and sessions.
    $parts = foreach ($key in @('Name','InstanceID','InternalIPInterfaceAddressPrefix','ExternalIPInterfaceAddressPrefix',
        'InternalRoutingDomainId','TcpEstablishedConnectionTimeout','TcpTransientConnectionTimeout','TcpFilteringBehavior',
        'IcmpQueryTimeout','UdpFilteringBehavior','UdpIdleSessionTimeout','UdpInboundRefresh','Store')) {
        $field = $nat.PSObject.Properties[$key]
        if ($null -ne $field) { $key + '=' + [string]$field.Value }
    }
    return ($parts -join '|')
}

function Nat-Matches($nat,$entry) {
    $shared = $entry.rule -cmatch '^SVM-Routed-[a-f0-9]{32}$' -and
        $entry.ip -ceq '10.77.0.0/16' -and $entry.PSObject.Properties['scope'] -and $entry.scope -ceq 'routed-pool'
    $legacy = $entry.rule -cmatch '^SecwizVM-NAT-[a-f0-9]{32}$'
    if ((!$shared -and !$legacy) -or $nat.Name -cne $entry.rule -or
        $nat.InternalIPInterfaceAddressPrefix -cne $entry.ip) { return $false }
    $saved = $entry.PSObject.Properties['natState']
    return ($null -eq $saved -or !$saved.Value -or (Nat-State $nat) -ceq $saved.Value)
}

function Undo-ProjectNat($entry) {
    $owned = @(Get-NetNat -ErrorAction Stop | Where-Object { $_.Name -ieq $entry.rule })
    if ($owned.Count -eq 0) { return }
    if ($owned.Count -ne 1 -or !(Nat-Matches $owned[0] $entry)) {
        throw 'The recorded WinNAT configuration changed. It was preserved.'
    }
    $mappings = @(Get-NetNatStaticMapping -ErrorAction Stop | Where-Object { $_.NatName -ieq $entry.rule })
    $external = @(Get-NetNatExternalAddress -ErrorAction Stop | Where-Object { $_.NatName -ieq $entry.rule })
    if ($mappings.Count -or $external.Count) { throw 'Additional mappings or external addresses use this NAT. They were preserved.' }
    Remove-NetNat -Name $entry.rule -Confirm:$false -ErrorAction Stop
    if (@(Get-NetNat -ErrorAction Stop | Where-Object { $_.Name -ieq $entry.rule }).Count) { throw 'WinNAT removal was not confirmed.' }
}

function Test-RoutedNatRange($networks, $hostAddresses) {
    $first = Net-U32 '10.77.0.0'
    $last = Net-U32 '10.77.255.255'
    $gateways = @{}
    $conflicts = @()
    foreach ($n in @($networks)) {
        $prefix = Network-Address $n
        $base = Net-U32 ($n.subnet.Split('/')[0])
        $end = $base + [uint64][Math]::Pow(2,32-$prefix) - 1
        if ($end -lt $first -or $base -gt $last) { continue }
        if ($n.mode -cne 'Routed' -or $base -lt $first -or $end -gt $last) {
            $conflicts += "$($n.id) ($($n.subnet), $($n.mode))"
            continue
        }
        $adapter = Owned-Adapter $n.id ([guid]$n.switchGuid).ToString('D')
        if ($null -eq $adapter) { throw "Routed network $($n.id) has no verified host adapter." }
        $gateways[[int]$adapter.ifIndex] = @{ ip=$n.gateway; prefix=$prefix }
    }
    if ($gateways.Count -eq 0) { return $false }
    foreach ($address in @($hostAddresses)) {
        $length = [uint64][Math]::Pow(2,32-$address.PrefixLength)
        $ip = Net-U32 $address.IPAddress
        $base = $ip - ($ip % $length)
        if ($base -gt $last -or $base+$length-1 -lt $first) { continue }
        $own = $gateways[[int]$address.InterfaceIndex]
        if ($null -eq $own -or $own.ip -cne $address.IPAddress -or $own.prefix -ne $address.PrefixLength) {
            $conflicts += "$($address.InterfaceAlias) ($($address.IPAddress)/$($address.PrefixLength))"
        }
    }
    if ($conflicts.Count) {
        throw ("The routed NAT range 10.77.0.0/16 overlaps " + ($conflicts -join ', ') + ". Resolve the overlap before running setup.")
    }
    return $true
}

function Add-ProjectNat($networks) {
    $prefix = '10.77.0.0/16'
    if (!(Test-RoutedNatRange $networks @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop))) { return }
    try { $all = @(Get-NetNat -ErrorAction Stop) }
    catch { Write-Warning 'Windows could not report WinNAT. App-provided internet is unavailable.'; return }
    $saved = @($changes | Where-Object { $_.kind -eq 'win-nat' })
    if ($saved.Count) {
        if ($saved.Count -ne 1) { throw 'Multiple protected WinNAT records require inspection.' }
        $prior = $saved[0]
        if ($prior.rule -cmatch '^SecwizVM-NAT-[a-f0-9]{32}$') {
            Write-Warning "Earlier setup recorded WinNAT for $($prior.ip). To migrate, run the verified -Remove and then setup again. The existing NAT was preserved."
        } elseif ($all.Count -eq 1 -and (Nat-Matches $all[0] $prior)) {
            Write-Host "The project WinNAT for $prefix is present. Guests still need a working host connection."
        } else {
            Write-Warning 'The existing WinNAT and protected record differ. No NAT was replaced.'
        }
        return
    }
    if ($all.Count) { Write-Warning 'Another WinNAT already exists. Its configuration and mappings were preserved.'; return }
    $entry = [pscustomobject]@{ kind='win-nat'; id='routed-pool'; alias='Routed networks'; ip=$prefix;
        scope='routed-pool'; rule=('SVM-Routed-'+[guid]::NewGuid().ToString('N')); natState=''; pending=$true }
    try {
        Change $entry "Provide shared WinNAT to routed guest subnets in $prefix." {
            if (!(Test-RoutedNatRange $networks @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop))) { throw 'The routed network inventory changed.' }
            if (@(Get-NetNat -ErrorAction Stop).Count) { throw 'A NAT appeared after preflight. Its configuration was preserved.' }
            New-NetNat -Name $entry.rule -InternalIPInterfaceAddressPrefix $prefix -ErrorAction Stop -Confirm:$false | Out-Null
            $current = @(Get-NetNat -ErrorAction Stop | Where-Object { $_.Name -ceq $entry.rule })
            if ($current.Count -ne 1 -or !(Nat-Matches $current[0] $entry)) { throw 'Windows did not confirm the project WinNAT.' }
            $entry.natState = Nat-State $current[0]
        }
    } catch {
        $failure = $_
        if (!$changes.Contains($entry) -or !$entry.pending) { throw $failure }
        $left = @(Get-NetNat -ErrorAction Stop | Where-Object { $_.Name -ieq $entry.rule })
        if ($left.Count) { throw $failure }
        [void]$changes.Remove($entry); Save-Journal
        Record-Result 'WinNAT creation failed; verified no project NAT was created.'
        Write-Warning ("Local networking remains available. Windows declined WinNAT. " + $failure.Exception.Message)
    }
}

function Add-ServiceFirewall($n,$adapter,[string]$guid,[string]$kind) {
    $entry = New-Entry $kind $adapter $n.id $guid
    $entry.program=$ServiceExe; $entry.ip=$n.gateway
    $prior=@($changes | Where-Object { $_.kind -eq $kind -and $_.id -ceq $n.id -and $_.switchGuid -ieq $guid })
    if ($prior.Count) {
        if ($prior.Count -ne 1) { throw 'The protected journal contains conflicting firewall entries.' }
        $saved=$prior[0]
        $active=@(Get-NetFirewallRule -PolicyStore PersistentStore | Where-Object { $_.Name -ceq $saved.rule })
        if ($active.Count -ne 1 -or !(Rule-Matches $active[0] $saved) -or $saved.program -ine $ServiceExe -or $saved.ip -cne $n.gateway) {
            throw "The recorded $kind rule changed. It was preserved."
        }
        return
    }
    $entry.rule='SecwizVM '+[guid]::NewGuid().ToString()
    if ($kind -eq 'dns-firewall') {
        Change $entry "Allow UDP 53 for the service on $($entry.ip), on $($adapter.Name) only." {
            New-NetFirewallRule -Name $entry.rule -DisplayName ("SecwizVM DNS "+$n.id) -Group $ruleGroup -PolicyStore PersistentStore -Enabled True -Profile Any -Direction Inbound -Action Allow -Protocol UDP -LocalPort 53 -LocalAddress $entry.ip -RemoteAddress LocalSubnet -InterfaceAlias $adapter.Name -Program $ServiceExe -Confirm:$false | Out-Null
        }
    } else {
        Change $entry "Allow inbound UDP 67 for DHCP on $($adapter.Name) only." {
            # Initial DHCP discovery is a broadcast from UDP 68 with no assigned guest address.
            New-NetFirewallRule -Name $entry.rule -DisplayName ("SecwizVM DHCP "+$n.id) -Group $ruleGroup -PolicyStore PersistentStore -Enabled True -Profile Any -Direction Inbound -Action Allow -Protocol UDP -LocalPort 67 -RemotePort 68 -InterfaceAlias $adapter.Name -Program $ServiceExe -Confirm:$false | Out-Null
        }
    }
}

function Dns-ZoneIntersects($rule) {
    foreach ($zone in @($rule.Namespace)) {
        $name=([string]$zone).Trim().TrimEnd('.').TrimStart([char[]]'*.').ToLowerInvariant()
        if (!$name -or $name -eq 'lan' -or $name -eq 'vm.lan' -or $name.EndsWith('.vm.lan') -or $name.Contains('*')) { return $true }
    }
    return $false
}

function Dns-State($rule) {
    $parts=foreach ($key in @('Name','Version','Namespace','NameServers','DisplayName','Comment','NameEncoding','DirectAccessEnabled','DirectAccessDnsServers',
        'DirectAccessQueryIPsecRequired','DirectAccessQueryIPsecEncryption','DirectAccessProxyName','DirectAccessProxyType',
        'DnsSecEnabled','DnsSecValidationRequired','DnsSecQueryIPsecRequired','DnsSecQueryIPsecEncryption','IPsecCARestriction')) {
        $field=$rule.PSObject.Properties[$key]
        if ($null -ne $field) { $key+'='+(@($field.Value) -join ',') }
    }
    return ($parts -join '|')
}

function Dns-RuleMatches($rule,$entry) {
    if ($entry.rule -cnotmatch '^SecwizVM-DNS-[a-f0-9]{32}$' -or $rule.Comment -cne $entry.rule -or
        $rule.DisplayName -cne 'SecwizVM guest names' -or (@($rule.Namespace) -join ',') -ine '.vm.lan' -or
        (@($rule.NameServers) -join ',') -cne $entry.ip) { return $false }
    $saved=$entry.PSObject.Properties['dnsState']
    return ($null -eq $saved -or !$saved.Value -or (Dns-State $rule) -ceq $saved.Value)
}

function Undo-HostDns($entry) {
    $all=@(Get-DnsClientNrptRule -ErrorAction Stop)
    $ours=@($all | Where-Object { $_.Comment -ceq $entry.rule })
    if ($ours.Count -eq 0) {
        $saved=$entry.PSObject.Properties['dnsRuleId']
        if ($null -ne $saved -and $saved.Value -and @($all | Where-Object { $_.Name -ieq $saved.Value }).Count) {
            throw 'The recorded Windows name policy was edited. It was preserved.'
        }
        return
    }
    if ($ours.Count -ne 1 -or !(Dns-RuleMatches $ours[0] $entry)) { throw 'The recorded Windows name policy changed. It was preserved.' }
    Remove-DnsClientNrptRule -Name $ours[0].Name -Force -ErrorAction Stop
    if (@(Get-DnsClientNrptRule -ErrorAction Stop | Where-Object { $_.Comment -ceq $entry.rule }).Count) { throw 'Windows did not confirm name policy removal.' }
}

function Add-HostDns($networks) {
    if (@($networks).Count -eq 0) { return }
    $saved=@($changes | Where-Object { $_.kind -eq 'host-dns' })
    if ($saved.Count -gt 1) { throw 'Multiple host name policies were found in the protected journal.' }
    if ($saved.Count) {
        $entry=$saved[0]
        $target=@($networks | Where-Object { $_.id -ceq $entry.id -and $_.gateway -ceq $entry.ip -and $_.switchGuid -ieq $entry.switchGuid })
        if ($target.Count -ne 1) {
            Write-Warning 'Host lookup for vm.lan could not be verified. The saved DNS gateway is no longer configured. Remove the recorded setup before choosing a replacement.'
            return
        }
    } else {
        # The service answers the entire project zone on each gateway. Keep the first chosen gateway on later runs.
        $n=@($networks | Sort-Object id)[0]
        $guid=([guid]::Parse([string]$n.switchGuid)).ToString()
        $adapter=Owned-Adapter $n.id $guid
        if ($null -eq $adapter) { throw 'The DNS gateway adapter is unavailable.' }
        $entry=New-Entry 'host-dns' $adapter $n.id $guid
        $entry.ip=$n.gateway; $entry.rule='SecwizVM-DNS-'+[guid]::NewGuid().ToString('N')
        $entry | Add-Member -NotePropertyName dnsState -NotePropertyValue ''
        $entry | Add-Member -NotePropertyName dnsRuleId -NotePropertyValue ''
    }
    try {
        $localRules=@(Get-DnsClientNrptRule -ErrorAction Stop)
        $policies=@(Get-DnsClientNrptPolicy -Effective -ErrorAction Stop | Where-Object { Dns-ZoneIntersects $_ })
    } catch { Write-Warning 'Host name lookup is unavailable because Windows could not report its existing DNS policies. Guest DNS is configured independently.'; return }
    $foreign=@($localRules | Where-Object { (Dns-ZoneIntersects $_) -and $_.Comment -cne $entry.rule })
    $ours=@($localRules | Where-Object { $_.Comment -ceq $entry.rule })
    if ($foreign.Count -or (!$saved.Count -and $policies.Count)) {
        Write-Warning 'Windows already has a DNS policy overlapping vm.lan. It was preserved. Use the managed gateway for explicit name queries.'
        return
    }
    if ($saved.Count) {
        if ($ours.Count -ne 1 -or !(Dns-RuleMatches $ours[0] $entry)) { Write-Warning 'The recorded Windows name policy changed or is missing. It was preserved.'; return }
    } else {
        Change $entry "Resolve names ending in .vm.lan through the project DNS gateway $($entry.ip) on this host." {
            if (@(Get-DnsClientNrptRule -ErrorAction Stop | Where-Object { Dns-ZoneIntersects $_ }).Count -or
                @(Get-DnsClientNrptPolicy -Effective -ErrorAction Stop | Where-Object { Dns-ZoneIntersects $_ }).Count) {
                throw 'A name policy appeared after preflight. Its settings were preserved.'
            }
            Add-DnsClientNrptRule -Namespace '.vm.lan' -NameServers $entry.ip -Comment $entry.rule -DisplayName 'SecwizVM guest names' -Confirm:$false -ErrorAction Stop | Out-Null
            $found=@(Get-DnsClientNrptRule -ErrorAction Stop | Where-Object { $_.Comment -ceq $entry.rule })
            if ($found.Count -ne 1 -or !(Dns-RuleMatches $found[0] $entry)) { throw 'Windows did not confirm the requested host name policy.' }
            $entry.dnsRuleId=[string]$found[0].Name; $entry.dnsState=Dns-State $found[0]
        }
        if ($entry.pending) {return}
    }
    $effective=@(Get-DnsClientNrptPolicy -Effective -ErrorAction Stop | Where-Object { Dns-ZoneIntersects $_ })
    $verified=@($effective | Where-Object { (@($_.Namespace) -join ',') -ieq '.vm.lan' -and (@($_.NameServers) -join ',') -ceq $entry.ip })
    if ($effective.Count -eq 1 -and $verified.Count -eq 1) { Write-Host "Windows will ask $($entry.ip) for .vm.lan names while the service is running." }
    else { Write-Warning 'Windows did not select the project DNS policy exclusively. Guest DNS is independent; host lookup is unverified.' }
}

function Bridge-Link([string]$guid) {
    $physicalLinks = @(Get-NetAdapter -Physical | Where-Object { $_.InterfaceGuid -eq [guid]$guid })
    if ($physicalLinks.Count -ne 1 -or [int]$physicalLinks[0].InterfaceType -ne 6) { throw 'The recorded physical Ethernet adapter is unavailable.' }
    return $physicalLinks[0]
}
function Bridge-Bound($link) {
    Get-VMSwitch | Where-Object { $_.SwitchType.ToString() -eq 'External' -and
        (($_.NetAdapterInterfaceGuid -and [guid]$_.NetAdapterInterfaceGuid -eq [guid]$link.InterfaceGuid) -or
        (@($_.NetAdapterInterfaceDescriptions) -icontains $link.InterfaceDescription)) }
}
function Bridge-Bindings($link) {
    if ($link.Name.IndexOfAny([char[]]'*?[]') -ge 0) { throw 'Use a wired adapter alias without wildcard characters.' }
    return @(Get-NetAdapterBinding -Name $link.Name -AllBindings | Sort-Object ComponentID |
        ForEach-Object { [pscustomobject]@{id=$_.ComponentID; enabled=[bool]$_.Enabled} })
}
function Bridge-Registry($item,[string]$name) {
    if ($null -ne $item -and $null -ne $item.PSObject.Properties[$name]) { return [string]($item.$name -join ',') }
    return ''
}
function Bridge-AutoDns($link) {
    $token=([guid]$link.InterfaceGuid).ToString('B')
    foreach ($protocol in @('Tcpip','Tcpip6')) {
        $key='HKLM:\SYSTEM\CurrentControlSet\Services\'+$protocol+'\Parameters\Interfaces\'+$token
        if (!(Test-Path -LiteralPath $key)) { continue }
        $props=Get-ItemProperty -LiteralPath $key
        foreach ($name in @('NameServer','Domain','ProfileNameServer')) {
            if (Bridge-Registry $props $name) { throw 'Manual DNS servers or a DNS suffix require an existing shared switch.' }
        }
    }
}
function Bridge-Policy($link) {
    $v4=Get-NetIPInterface -InterfaceIndex $link.ifIndex -AddressFamily IPv4
    $v6=Get-NetIPInterface -InterfaceIndex $link.ifIndex -AddressFamily IPv6
    if ($v4.Dhcp.ToString() -ne 'Enabled' -or $v4.Forwarding.ToString() -ne 'Disabled' -or $v6.Forwarding.ToString() -ne 'Disabled') {
        throw 'Only DHCP Ethernet with forwarding disabled can be restored by this setup.'
    }
    foreach ($iface in @($v4,$v6)) {
        if ($iface.AutomaticMetric.ToString() -ne 'Enabled' -or $iface.WeakHostSend.ToString() -ne 'Disabled' -or
            $iface.WeakHostReceive.ToString() -ne 'Disabled' -or [int]$iface.NlMtu -ne 1500) {
            throw 'This adapter has custom metrics, routing, or MTU settings. Its configuration was preserved.'
        }
    }
    $manual=@(Get-NetIPAddress -InterfaceIndex $link.ifIndex | Where-Object { $_.PrefixOrigin.ToString() -eq 'Manual' })
    $routes=@(Get-NetRoute -PolicyStore PersistentStore | Where-Object { $_.InterfaceIndex -eq $link.ifIndex -and $_.Protocol.ToString() -eq 'NetMgmt' })
    if ($manual.Count -or $routes.Count) { throw 'Static addresses or persistent routes need individual restoration. Use an existing shared switch.' }
    Bridge-AutoDns $link
    $cfg=Get-CimInstance Win32_NetworkAdapterConfiguration -Filter "InterfaceIndex=$($link.ifIndex)"
    if ($null -eq $cfg -or !$cfg.IPEnabled -or $cfg.WINSPrimaryServer -or $cfg.WINSSecondaryServer -or
        $cfg.TcpipNetbiosOptions -notin @(0,$null)) { throw 'The current IP or WINS configuration cannot be restored automatically.' }
    $dns=Get-DnsClient -InterfaceIndex $link.ifIndex
    return [ordered]@{dhcp4=$v4.Dhcp.ToString();dhcp6=$v6.Dhcp.ToString();routerDiscovery=$v6.RouterDiscovery.ToString();
        registerDns=[bool]$dns.RegisterThisConnectionsAddress;suffixRegistration=[bool]$dns.UseSuffixWhenRegistering;
        metric4=$v4.AutomaticMetric.ToString();metric6=$v6.AutomaticMetric.ToString();mtu4=[int]$v4.NlMtu;mtu6=[int]$v6.NlMtu}
}
function Bridge-Hardware($link) {
    if ($link.Name.IndexOfAny([char[]]'*?[]') -ge 0) { throw 'Use a wired adapter alias without wildcard characters.' }
    $props=@(Get-NetAdapterAdvancedProperty -Name $link.Name -AllProperties | Sort-Object RegistryKeyword)
    return [ordered]@{alias=[string]$link.Name;mac=[string]$link.MacAddress;description=[string]$link.InterfaceDescription;
        properties=@($props | ForEach-Object { [pscustomobject]@{key=$_.RegistryKeyword;value=(@($_.RegistryValue) -join ',')} })}
}
function Check-BridgeHardware($entry,$link,[switch]$IdentityOnly) {
    $before=$entry.hardware
    $now=Bridge-Hardware $link
    $mac=([string]$before.mac -replace '[-:]','')
    if ([guid]$entry.adapterGuid -ne [guid]$link.InterfaceGuid -or $mac -notmatch '^[0-9A-Fa-f]{12}$' -or
        $mac -ine ([string]$now.mac -replace '[-:]','') -or !$before.description -or $before.description -cne $now.description) {
        throw 'The recorded physical adapter GUID, MAC or description changed. The journal was preserved.'
    }
    $keys=@(foreach ($property in @($before.properties)+@($now.properties)) { [string]$property.key })
    foreach ($key in @($keys | Sort-Object -Unique)) {
        $saved=@($before.properties | Where-Object { $_.key -ieq $key } | ForEach-Object { [string]$_.value } | Sort-Object)
        $current=@($now.properties | Where-Object { $_.key -ieq $key } | ForEach-Object { [string]$_.value } | Sort-Object)
        if ($key -match 'vlan.?id|pvid') {
            # Old journals carry raw driver strings. Empty, zero and hex zero all mean untagged.
            $saved=@($saved | ForEach-Object { if ($_ -match '^(?:0+|0x0+)?$') { '0' } else { $_ } })
            $current=@($current | ForEach-Object { if ($_ -match '^(?:0+|0x0+)?$') { '0' } else { $_ } })
            if (!(Bridge-Equal $saved $current)) { throw "The physical adapter VLAN setting $key changed. The journal was preserved." }
        } elseif (!$IdentityOnly -and !(Bridge-Equal $saved $current)) {
            $oldValue=if ($saved.Count) { $saved -join ', ' } else { '<absent>' }
            $newValue=if ($current.Count) { $current -join ', ' } else { '<absent>' }
            $warning="Driver setting $key on $($link.Name) changed from [$oldValue] to [$newValue]. Keeping the current driver value."
            Write-Warning $warning
            if (!$WhatIfPreference) { Record-Result $warning }
        }
    }
}
function Bridge-Equal($a,$b) {
    return ((ConvertTo-Json -InputObject $a -Depth 7 -Compress) -ceq (ConvertTo-Json -InputObject $b -Depth 7 -Compress))
}
function Bridge-Vnic($switch) {
    $hostNics=@(Get-VMNetworkAdapter -ManagementOS | Where-Object { $_.SwitchId -eq $switch.Id })
    if (!$switch.AllowManagementOS -or $hostNics.Count -ne 1) { throw 'Expected exactly one shared host network adapter.' }
    $nic=$hostNics[0]
    $vlan=Get-VMNetworkAdapterVlan -VMNetworkAdapter $nic
    if ($vlan.OperationMode.ToString() -ne 'Untagged') { throw 'The host adapter has VLAN settings. The bridge was preserved.' }
    $links=@(Get-NetAdapter -IncludeHidden | Where-Object { $_.Name -ceq ('vEthernet ('+$nic.Name+')') -and
        ($_.MacAddress -replace '[-:]','') -ieq $nic.MacAddress })
    if ($links.Count -ne 1) { throw 'The shared Windows network adapter could not be verified.' }
    return $links[0]
}
function Bridge-Online($link) {
    $ips=@(Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.InterfaceIndex -eq $link.ifIndex -and
        $_.PrefixOrigin.ToString() -eq 'Dhcp' -and $_.AddressState.ToString() -eq 'Preferred' -and !$_.IPAddress.StartsWith('169.254.') })
    $gateways=@(Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' | Where-Object { $_.InterfaceIndex -eq $link.ifIndex })
    $dns=(Get-DnsClientServerAddress -InterfaceIndex $link.ifIndex -AddressFamily IPv4).ServerAddresses
    return ($link.Status.ToString() -eq 'Up' -and $ips.Count -gt 0 -and $gateways.Count -gt 0 -and @($dns | Where-Object { $_ }).Count -gt 0)
}
function Bridge-Wait($entry,$switch) {
    $clock=[Diagnostics.Stopwatch]::StartNew()
    $reason='Waiting for a DHCP address, default route and DNS.'
    do {
        try {
            $link=if ($switch) { Bridge-Vnic $switch } else { Bridge-Link $entry.adapterGuid }
            if ((Bridge-Online $link) -and (Bridge-Equal $entry.policy (Bridge-Policy $link))) { return $link }
        } catch { $reason=$_.Exception.Message }
        Start-Sleep -Milliseconds 500
    } while ($clock.Elapsed.TotalSeconds -lt 40)
    throw "Windows has not confirmed the expected LAN settings. The protected journal was kept. $reason"
}
function Bridge-Identity($entry,$sw) {
    if ($sw.Id.ToString('D') -ine $entry.switchGuid -or $sw.Name -cne ('SVM-'+$entry.id) -or
        $sw.SwitchType.ToString() -ne 'External' -or $sw.Notes -cne ('secwiz-bridge:'+$entry.id) -or
        $sw.EmbeddedTeamingEnabled -or !$sw.AllowManagementOS -or
        !($sw.NetAdapterInterfaceGuid) -or [guid]$sw.NetAdapterInterfaceGuid -ne [guid]$entry.adapterGuid) {
        throw 'The recorded external switch or physical adapter identity changed. It was left untouched.'
    }
}
function Bridge-VerifyOwner {
    $localData=[Environment]::GetFolderPath([Environment+SpecialFolder]::LocalApplicationData)
    $homePath=if ($env:SVM_HOME) { [IO.Path]::GetFullPath($env:SVM_HOME) } else { Join-Path $localData 'SecwizVM' }
    $cred=Join-Path $homePath 'api-token'
    Check-LocalPath $cred
    if (!([IO.File]::Exists($cred)) -or (Get-Acl -LiteralPath $cred).GetOwner([Security.Principal.SecurityIdentifier]).Value -ne $ownerSid) {
        throw 'Elevate the same Windows account that owns the running service. Another administrator cannot provision this account''s bridge.'
    }
}
function Bridge-Record($entry,[string]$phase) {
    $entry.phase=$phase; Save-Journal; Record-Result ("Bridge "+$entry.id+" on "+$entry.alias+": "+$phase)
}
function New-Bridge([string]$id,[string]$adapterId) {
    Bridge-VerifyOwner
    $link=Bridge-Link $adapterId
    $name='SVM-'+$id
    if (@(Get-VMSwitch | Where-Object { $_.Name -ieq $name }).Count -or @(Bridge-Bound $link).Count) {
        throw 'A switch already exists on this adapter or with this name. Select a compatible existing switch in the app.'
    }
    if (@($changes | Where-Object { $_.pending -or ($_.kind -eq 'bridge' -and ($_.id -ieq $id -or $_.adapterGuid -ieq $adapterId)) }).Count) {
        throw 'The protected setup journal already has a matching or unfinished operation. Use its recorded undo before provisioning.'
    }
    $bindings=@(Bridge-Bindings $link)
    if (@($bindings | Where-Object { $_.enabled -and ($_.id -notmatch '^ms_' -or $_.id -in @('vms_pp','ms_bridge','ms_implat')) }).Count -or
        @($bindings | Where-Object { $_.enabled -and $_.id -in @('ms_tcpip','ms_tcpip6') }).Count -ne 2) {
        throw 'A team, bridge, third-party binding, or disabled IP protocol prevents automatic restoration. Use an existing shared switch.'
    }
    $policy=Bridge-Policy $link; $hardware=Bridge-Hardware $link
    foreach ($vlan in @($hardware.properties | Where-Object { $_.key -match 'vlan.?id|pvid' })) {
        if ($vlan.value -notmatch '^(?:0+|0x0+)?$') { throw 'The physical adapter has a configured VLAN. Use an existing external switch.' }
    }
    if (!(Bridge-Online $link)) { throw 'Select a connected wired Ethernet adapter with working DHCP, a default route and DNS.' }
    $entry=[pscustomobject]@{kind='bridge';id=$id;alias=$link.Name;adapterGuid=([guid]$link.InterfaceGuid).ToString('D');
        switchGuid='';hostGuid='';hardware=$hardware;bindings=$bindings;policy=$policy;bound=$null;phase='planned';pending=$true}
    $plan="Create $name on $($link.Name), keeping Windows connected. The host network will disconnect briefly."
    Write-Host $plan
    if (!$script:setupCmdlet.ShouldProcess($link.Name,$plan)) { return }
    $link=Bridge-Link $adapterId
    if (!(Bridge-Equal $entry.hardware (Bridge-Hardware $link)) -or !(Bridge-Equal $entry.bindings @(Bridge-Bindings $link)) -or
        !(Bridge-Equal $entry.policy (Bridge-Policy $link)) -or !(Bridge-Online $link) -or
        @(Bridge-Bound $link).Count -or @(Get-VMSwitch | Where-Object { $_.Name -ieq $name }).Count) {
        throw 'The selected adapter or switch changed since confirmation. No network settings were changed.'
    }
    [void]$changes.Add($entry); Bridge-Record $entry 'planned'
    $s=New-VMSwitch -Name $name -NetAdapterName $link.Name -AllowManagementOS $true -Notes ('secwiz-bridge:'+$id) -ErrorAction Stop
    $entry.switchGuid=$s.Id.ToString('D'); Bridge-Record $entry 'created'
    Bridge-Identity $entry $s
    $hostLink=Bridge-Wait $entry $s
    $entry.hostGuid=([guid]$hostLink.InterfaceGuid).ToString('D'); $entry.bound=@(Bridge-Bindings (Bridge-Link $adapterId))
    $entry.pending=$false; Bridge-Record $entry 'ready'
    Write-Host "Shared external switch $name is ready. Return to the app and refresh the adapters."
}
function Bridge-NoGuests($switch) {
    $connected=@(Get-VMNetworkAdapter -All | Where-Object { !$_.IsManagementOs -and $_.SwitchId -eq $switch.Id })
    foreach ($machine in @(Get-VM)) {
        foreach ($snapshot in @(Get-VMSnapshot -VM $machine)) {
            $connected+=@(Get-VMNetworkAdapter -VMSnapshot $snapshot | Where-Object { $_.SwitchId -eq $switch.Id })
        }
    }
    if ($connected.Count) { throw 'A guest or checkpoint still uses this switch. Disconnect it before removing the bridge.' }
}
function Undo-Bridge([string]$id) {
    $records=@($changes | Where-Object { $_.kind -eq 'bridge' -and $_.id -ceq $id })
    if ($records.Count -ne 1) { throw 'This account has no unique protected creation record for that bridge. Existing switches are preserved.' }
    $entry=$records[0]; $link=Bridge-Link $entry.adapterGuid
    Check-BridgeHardware $entry $link
    $sw=@(Get-VMSwitch | Where-Object { $_.Name -ieq ('SVM-'+$id) -or $_.Id.ToString('D') -ieq $entry.switchGuid })
    if ($sw.Count -gt 1) { throw 'The recorded switch identity is ambiguous.' }
    if ($sw.Count) {
        Bridge-Identity $entry $sw[0]
        $hostNics=@(Get-VMNetworkAdapter -ManagementOS | Where-Object { $_.SwitchId -eq $sw[0].Id })
        if ($entry.hostGuid -or $entry.bound) {
            $nic=Bridge-Vnic $sw[0]
            if ($nic.InterfaceGuid -ne [guid]$entry.hostGuid) { throw 'The Windows host network adapter changed. The bridge was preserved.' }
            if (!(Bridge-Equal $entry.bound @(Bridge-Bindings $link))) { throw 'Physical network bindings changed after provisioning. The bridge was preserved.' }
            if (!(Bridge-Equal $entry.policy (Bridge-Policy $nic))) { throw 'The host IP policy changed after provisioning. The bridge was preserved.' }
        } else {
            # A newly created switch may never have acquired a working host IP configuration.
            if ($hostNics.Count -gt 1 -or ($hostNics.Count -eq 1 -and $hostNics[0].Name -cne $sw[0].Name)) {
                throw 'The incomplete bridge has unexpected host adapters. Inspect the protected record.'
            }
            if ($hostNics.Count) {
                $hostLinks=@(Get-NetAdapter -IncludeHidden | Where-Object { $_.Name -ceq ('vEthernet ('+$sw[0].Name+')') })
                if ($hostLinks.Count -gt 1) { throw 'The host adapter is ambiguous.' }
                if ($hostLinks.Count) {
                    $idx=$hostLinks[0].ifIndex
                    $manual=@(Get-NetIPAddress | Where-Object { $_.InterfaceIndex -eq $idx -and $_.PrefixOrigin.ToString() -eq 'Manual' })
                    if ($manual.Count) { throw 'The incomplete bridge now has a manual host address. Inspect the protected record.' }
                    Bridge-AutoDns $hostLinks[0]
                }
            }
        }
        Bridge-NoGuests $sw[0]
    } elseif (@(Bridge-Bound $link).Count) { throw 'Another external switch now uses this adapter. No network settings were changed.' }
    $plan="Undo $id on $($link.Name) and verify the original network settings. The LAN may briefly disconnect."
    Write-Host $plan
    if (!$script:setupCmdlet.ShouldProcess($link.Name,$plan)) { return }
    if ($sw.Count) {
        $target=Get-VMSwitch -Id ([guid]$entry.switchGuid)
        Check-BridgeHardware $entry (Bridge-Link $entry.adapterGuid) -IdentityOnly
        Bridge-Identity $entry $target; Bridge-NoGuests $target
        if ($entry.hostGuid) {
            $nic=Bridge-Vnic $target
            if ($nic.InterfaceGuid -ne [guid]$entry.hostGuid -or !(Bridge-Equal $entry.policy (Bridge-Policy $nic)) -or
                !(Bridge-Equal $entry.bound @(Bridge-Bindings (Bridge-Link $entry.adapterGuid)))) { throw 'The active bridge changed since confirmation.' }
        }
        Bridge-Record $entry 'removing'
        Remove-VMSwitch -VMSwitch $target -Force -ErrorAction Stop
    }
    $link=Bridge-Link $entry.adapterGuid
    Check-BridgeHardware $entry $link -IdentityOnly
    if (@(Bridge-Bound $link).Count) { throw 'An external switch is still bound. Network settings were preserved.' }
    if ($entry.phase -ne 'removing' -and $entry.phase -ne 'restoring') {
        if (!(Bridge-Equal $entry.bindings @(Bridge-Bindings $link))) { throw 'The recorded switch is missing and the physical bindings differ. Inspect the journal.' }
    }
    Bridge-Record $entry 'restoring'
    $current=@(Bridge-Bindings $link)
    if ((@($current.id) -join '|') -cne (@($entry.bindings.id) -join '|')) { throw 'The installed binding components changed. The journal was kept.' }
    foreach ($binding in $entry.bindings) {
        $now=@($current | Where-Object { $_.id -ceq $binding.id })[0]
        if ($now.enabled -eq $binding.enabled) { continue }
        if ($binding.id -notin @('ms_tcpip','ms_tcpip6','ms_msclient','ms_server','ms_pacer','ms_lldp','ms_lltdio','ms_rspndr','vms_pp')) {
            throw 'Windows did not restore an additional network component. Inspect the journal before changing it.'
        }
        $adjust=if ($binding.enabled) { 'Enable-NetAdapterBinding' } else { 'Disable-NetAdapterBinding' }
        & $adjust -Name $link.Name -ComponentID $binding.id -Confirm:$false -ErrorAction Stop | Out-Null
    }
    $original=Bridge-Wait $entry $null
    Check-BridgeHardware $entry $original
    if (!(Bridge-Equal $entry.bindings @(Bridge-Bindings $original))) {
        throw 'Windows has not restored the original physical adapter settings. The protected record was kept.'
    }
    Record-Result ("Verified removal and original DHCP policy, Ethernet settings and bindings for "+$id)
    [void]$changes.Remove($entry); Save-Journal
    Write-Host "Removed the owned bridge and verified the original network configuration for $($link.Name)."
}

$script:setupCmdlet = $PSCmdlet
$script:setupPath = $PSCommandPath
$setupMutex=[Threading.Mutex]::new($false,'Global\SecwizVM-Admin-Setup')
$setupHeld=$false
try {
try { $setupHeld=$setupMutex.WaitOne(10000) } catch [Threading.AbandonedMutexException] { $setupHeld=$true }
if (!$setupHeld) { throw 'Another administrator setup for this account is still in progress.' }
Write-Host 'Elevate the same Windows account that runs the service. Choosing another administrator uses a different profile and a separate rollback journal.'
Write-Host "Protected setup and audit folder: $journalRoot"
Protect-JournalPath
if ([IO.File]::Exists($journal)) {
    $stored = [IO.File]::ReadAllText($journal) | ConvertFrom-Json
    foreach ($entry in @($stored)) { if ($null -ne $entry) { [void]$changes.Add($entry) } }
}
if ($PSBoundParameters.ContainsKey('ReleasePending')) {
    if ($Remove -or $ServiceExe -or $PSBoundParameters.ContainsKey('BridgeId') -or $PSBoundParameters.ContainsKey('AdapterGuid')) {
        throw 'Run -ReleasePending by itself to release one interrupted journal entry.'
    }
    Resolve-PendingPlain -ReleaseToken $ReleasePending
    return
}
Resolve-PendingPlain
if ($PSBoundParameters.ContainsKey('BridgeId') -or $PSBoundParameters.ContainsKey('AdapterGuid')) {
    if ($BridgeId -cnotmatch '^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,79}$' -or $BridgeId.Contains('..') -or $ServiceExe) { throw 'Supply a valid project bridge ID.' }
    if ($Remove -eq $PSBoundParameters.ContainsKey('AdapterGuid')) { throw 'Use -BridgeId and -AdapterGuid to create, or -Remove and -BridgeId to undo.' }
    $bridgeGate=[Threading.Mutex]::new($false,'Global\SecwizVM-HyperV-Management'); $bridgeHeld=$false
    try {
        try { $bridgeHeld=$bridgeGate.WaitOne(10000) } catch [Threading.AbandonedMutexException] { $bridgeHeld=$true }
        if (!$bridgeHeld) { throw 'Another Hyper-V management operation is in progress.' }
        if ($Remove) { Undo-Bridge $BridgeId } else { New-Bridge $BridgeId ($AdapterGuid.ToString('D')) }
    } finally { if ($bridgeHeld) { $bridgeGate.ReleaseMutex() }; $bridgeGate.Dispose() }
    return
}
if ($Remove) {
    if ($changes.Count -eq 0) { Write-Host "No setup changes are recorded for this account in $journal." }
    for ($index = $changes.Count - 1; $index -ge 0; $index--) {
        $entry = $changes[$index]
        if ($entry.kind -eq 'bridge') { Write-Host "To remove the recorded bridge, use -Remove -BridgeId $($entry.id)."; continue }
        $plan = "Undo the recorded $($entry.kind) change on $($entry.alias)."
        Write-Host $plan
        if (-not $PSCmdlet.ShouldProcess($entry.alias,$plan)) { continue }
        Record-Result "Starting: $plan"
        Undo-Entry $entry
        $changes.RemoveAt($index)
        Save-Journal
        Record-Result "Completed: $plan"
    }
    return
}

$local = [Environment]::GetFolderPath([Environment+SpecialFolder]::LocalApplicationData)
$dataRoot = if ($env:SVM_HOME) { [IO.Path]::GetFullPath($env:SVM_HOME) } else { Join-Path $local 'SecwizVM' }
$networkFile = Join-Path $dataRoot 'networks.json'
Write-Host "Service data folder for this run: $dataRoot"
Check-LocalPath $networkFile
if (-not [IO.File]::Exists($networkFile)) {
    throw "No network manifest at $networkFile. Check the elevated account and SVM_HOME, then start the service under its owner account."
}
# Windows svmd creates api-token with an owner-only ACL. Check its owner without reading the credential.
$credentialPath = Join-Path $dataRoot 'api-token'
Check-LocalPath $credentialPath
if ([IO.File]::Exists($credentialPath)) {
    try { $recordOwner = (Get-Acl -LiteralPath $credentialPath).GetOwner([Security.Principal.SecurityIdentifier]) }
    catch { throw 'The service owner could not be verified. Check SVM_HOME and use the same account for service and elevated setup.' }
    if ($recordOwner.Value -ne $ownerSid) { throw 'The service data belongs to a different account. Elevate the account that owns the service.' }
}

if (@($changes | Where-Object { $_.pending }).Count -gt 0) { throw 'Resolve the interrupted operation in the protected journal first.' }
if (-not $ServiceExe) {
    $command = Get-Command svmd.exe -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($null -ne $command) { $ServiceExe = $command.Source }
}
if (-not $ServiceExe -or -not [IO.Path]::IsPathRooted($ServiceExe) -or
    [IO.Path]::GetFileName($ServiceExe) -ine 'svmd.exe' -or -not [IO.File]::Exists($ServiceExe)) {
    throw 'Pass -ServiceExe with the full path to the built svmd.exe.'
}
$ServiceExe = [IO.Path]::GetFullPath($ServiceExe)
Check-LocalPath $ServiceExe
$networks = [IO.File]::ReadAllText($networkFile) | ConvertFrom-Json
# Recheck both the manifest and the live host at elevation. Service-time observations may now be stale.
$ranges = @()
$manifestIds=@{}
$allHostAddresses = @(Get-NetIPAddress -AddressFamily IPv4)
foreach ($candidate in @($networks)) {
    if ($null -eq $candidate -or $candidate.mode -in @('NAT','Bridged','Link-local')) { continue }
    if ($candidate.mode -cnotin @('Routed','Host-only','Isolated segment')) { throw 'Unexpected internal network mode.' }
    if ($manifestIds.ContainsKey($candidate.id)) { throw 'Duplicate network ID in the manifest.' }
    $manifestIds[$candidate.id]=$true
    $cidr = Network-Address $candidate
    $candidateGuid = ([guid]::Parse([string]$candidate.switchGuid)).ToString()
    $candidateAdapter = Owned-Adapter $candidate.id $candidateGuid
    if ($null -eq $candidateAdapter) { throw 'A project host adapter is missing.' }
    $lower = Net-U32 ($candidate.subnet.Split('/')[0])
    $upper = $lower + [uint64][Math]::Pow(2,32-$cidr) - 1
    foreach ($range in $ranges) {
        if ($lower -le $range.upper -and $upper -ge $range.lower) { throw 'The managed network ranges overlap.' }
    }
    $ranges += [pscustomobject]@{ lower=$lower; upper=$upper }
    foreach ($other in $allHostAddresses) {
        if ($other.InterfaceIndex -eq $candidateAdapter.ifIndex) { continue }
        $length = [uint64][Math]::Pow(2,32-$other.PrefixLength)
        $numeric = Net-U32 $other.IPAddress
        $start = $numeric - ($numeric % $length)
        if ($lower -lt ($start+$length) -and $upper -ge $start) { throw 'A managed subnet overlaps an existing host interface.' }
    }
}
$managed=@($networks | Where-Object { $null -ne $_ -and $_.mode -cin @('Routed','Host-only','Isolated segment') })
$useRoutedNat = Test-RoutedNatRange $managed $allHostAddresses
if (@($changes | Where-Object { $_.kind -in @('lan-forward','guest-forward') }).Count) {
    Write-Host 'An earlier setup enabled IPv4 forwarding. Those original journal entries remain available for -Remove. WinNAT makes no physical-adapter change.'
}
foreach ($n in @($networks)) {
    if ($null -eq $n -or $n.mode -in @('NAT','Bridged','Link-local')) { continue }
    $prefix = Network-Address $n
    $guid = ([guid]::Parse([string]$n.switchGuid)).ToString()
    $adapter = Owned-Adapter $n.id $guid
    if ($null -eq $adapter) { throw "The switch for $($n.id) is missing." }
    $addresses = @(Get-NetIPAddress -AddressFamily IPv4 -InterfaceIndex $adapter.ifIndex)
    $existing = @($addresses | Where-Object { $_.IPAddress -ceq $n.gateway })
    if ($existing.Count -gt 0 -and @($existing | Where-Object { $_.PrefixLength -ne $prefix }).Count -gt 0) {
        throw 'The gateway is present with a different prefix. Existing addresses were preserved.'
    }
    if ($existing.Count -eq 0) {
        $savedAddresses = @(Get-NetIPAddress -PolicyStore PersistentStore -AddressFamily IPv4 | Where-Object { $_.InterfaceIndex -eq $adapter.ifIndex })
        if ($savedAddresses.Count -gt 0) { throw 'This adapter already has persistent addresses. Existing settings were preserved.' }
        $other = @($addresses | Where-Object { -not $_.IPAddress.StartsWith('169.254.') })
        if ($other.Count -gt 0) { throw 'The owned switch has other configured IPv4 addresses. Existing addresses were preserved.' }
        # New-NetIPAddress implicitly disables the DHCP client. Track and reverse that change separately.
        $ipif = Get-NetIPInterface -AddressFamily IPv4 -InterfaceIndex $adapter.ifIndex
        if ($ipif.Dhcp.ToString() -eq 'Enabled') {
            $dhcpEntry = New-Entry 'dhcp-client' $adapter $n.id $guid
            Change $dhcpEntry "Disable the IPv4 DHCP client on $($adapter.Name) before assigning the saved address." {
                Set-NetIPInterface -AddressFamily IPv4 -InterfaceIndex $adapter.ifIndex -Dhcp Disabled -Confirm:$false
            }
        }
        $entry = New-Entry 'address' $adapter $n.id $guid
        $entry.ip = $n.gateway; $entry.prefix = $prefix
        Change $entry "Assign $($entry.ip)/$prefix to $($adapter.Name)." {
            New-NetIPAddress -AddressFamily IPv4 -InterfaceIndex $adapter.ifIndex -IPAddress $entry.ip -PrefixLength $prefix -Confirm:$false | Out-Null
        }
    }
    Add-ServiceFirewall $n $adapter $guid 'firewall'
    Add-ServiceFirewall $n $adapter $guid 'dns-firewall'
}

if ($useRoutedNat) { Add-ProjectNat $managed }
Add-HostDns $managed

} finally { if ($setupHeld) { $setupMutex.ReleaseMutex() }; $setupMutex.Dispose() }
