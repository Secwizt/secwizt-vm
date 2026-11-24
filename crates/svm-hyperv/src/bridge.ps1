function BridgeSetupReasons($link) {
    # Check each independent setting, even when another one already rules out creating a switch.
    $idx=[int]$link.ifIndex
    $bindings=$null
    if ($link.Name.IndexOfAny([char[]]'*?[]') -ge 0) { 'The adapter name contains wildcard characters.' }
    else {
        try {
            $bindings=@(Get-NetAdapterBinding -Name $link.Name -AllBindings -ErrorAction Stop | Where-Object Enabled)
            foreach ($binding in $bindings) {
                $id=[string]$binding.ComponentID
                if ($id -in @('vms_pp','ms_bridge','ms_implat')) { "A switch, bridge or team binding is enabled ($id)." }
                elseif ($id -notmatch '^ms_') { "A third-party binding is enabled ($id)." }
            }
            foreach ($pair in @(@('ms_tcpip','IPv4'),@('ms_tcpip6','IPv6'))) {
                if ($bindings.ComponentID -notcontains $pair[0]) { "$($pair[1]) is not bound ($($pair[0]))." }
            }
        } catch { 'Windows could not verify the adapter bindings.' }
        try {
            $props=Get-NetAdapterAdvancedProperty -Name $link.Name -AllProperties -ErrorAction Stop
            foreach ($prop in $props) {
                if ($prop.RegistryKeyword -match 'vlan.?id|pvid' -and (@($prop.RegistryValue) -join ',') -notmatch '^(?:0+|0x0+)?$') {
                    "A VLAN is configured ($($prop.RegistryKeyword))."
                }
            }
        } catch { 'Windows could not verify the physical VLAN configuration.' }
    }
    foreach ($family in 'IPv4','IPv6') {
        try {
            $iface=Get-NetIPInterface -InterfaceIndex $idx -AddressFamily $family -ErrorAction Stop
            if (@($iface).Count -ne 1 -or $null -eq $iface) { throw 'Interface unavailable.' }
            if ($family -eq 'IPv4' -and [string]$iface.Dhcp -ne 'Enabled') { 'IPv4 DHCP is disabled.' }
            if ([string]$iface.Forwarding -ne 'Disabled') { "$family forwarding is enabled." }
            if ([string]$iface.AutomaticMetric -ne 'Enabled') { "$family uses a custom interface metric." }
            if ($iface.NlMtu -ne 1500) { "$family uses a custom MTU ($($iface.NlMtu))." }
            if ([string]$iface.WeakHostSend -ne 'Disabled' -or [string]$iface.WeakHostReceive -ne 'Disabled') { "$family uses weak-host routing." }
        } catch { if ($null -eq $bindings -or $bindings.ComponentID -contains $(if ($family -eq 'IPv4') {'ms_tcpip'} else {'ms_tcpip6'})) {
            "Windows could not verify the $family interface policy."
        } }
    }
    try {
        $ips=@(Get-NetIPAddress -InterfaceIndex $idx -ErrorAction Stop)
        if (@($ips | Where-Object { [string]$_.PrefixOrigin -eq 'Manual' }).Count) { 'The adapter has a static IP address.' }
        if (!@($ips | Where-Object { [string]$_.AddressFamily -eq 'IPv4' -and [string]$_.PrefixOrigin -eq 'Dhcp' -and
            [string]$_.AddressState -eq 'Preferred' -and !$_.IPAddress.StartsWith('169.254.') }).Count) { 'No preferred IPv4 DHCP address is available.' }
    } catch { 'Windows could not verify the adapter IP addresses.' }
    try {
        if (@(Get-NetRoute -PolicyStore PersistentStore -ErrorAction Stop | Where-Object { $_.InterfaceIndex -eq $idx -and [string]$_.Protocol -eq 'NetMgmt' }).Count) {
            'The adapter has a persistent static route.'
        }
    } catch { 'Windows could not verify the persistent adapter routes.' }
    try {
        if (!@(Get-NetRoute -AddressFamily IPv4 -ErrorAction Stop | Where-Object { $_.InterfaceIndex -eq $idx -and $_.DestinationPrefix -eq '0.0.0.0/0' }).Count) {
            'The adapter has no default IPv4 route.'
        }
    } catch { 'Windows could not verify the adapter routes.' }
    foreach ($protocol in 'Tcpip','Tcpip6') {
        try {
            $key='HKLM:\SYSTEM\CurrentControlSet\Services\'+$protocol+'\Parameters\Interfaces\'+([guid]$link.InterfaceGuid).ToString('B')
            if (Test-Path -LiteralPath $key -ErrorAction Stop) {
                $settings=Get-ItemProperty -LiteralPath $key -ErrorAction Stop
                if (($settings.NameServer -join ',') -or ($settings.ProfileNameServer -join ',')) { 'The adapter has a static DNS server.' }
                if ($settings.Domain -join ',') { 'The adapter has a static DNS suffix.' }
            }
        } catch { "Windows could not verify the saved DNS settings for $protocol." }
    }
    try {
        $dns=Get-DnsClientServerAddress -InterfaceIndex $idx -AddressFamily IPv4 -ErrorAction Stop
        if (!@($dns.ServerAddresses | Where-Object { $_ }).Count) { 'The adapter has no IPv4 DNS server.' }
        $null=Get-DnsClient -InterfaceIndex $idx -ErrorAction Stop
    } catch { 'Windows could not verify the adapter DNS client.' }
    try {
        $cfg=Get-CimInstance Win32_NetworkAdapterConfiguration -Filter "InterfaceIndex=$idx" -ErrorAction Stop
        if (!$cfg.IPEnabled -or $cfg.WINSPrimaryServer -or $cfg.WINSSecondaryServer -or $cfg.TcpipNetbiosOptions -notin @(0,$null)) {
            'The IP, WINS or NetBIOS configuration cannot be restored automatically.'
        }
    } catch { 'Windows could not verify the IP and WINS configuration.' }
}
function BridgeSwitches($link,$external) {
    foreach ($s in $external) {
        if ($s.NetAdapterInterfaceGuid -and ([guid]$s.NetAdapterInterfaceGuid) -eq ([guid]$link.InterfaceGuid)) { $s }
        elseif (@($s.NetAdapterInterfaceDescriptions) -icontains $link.InterfaceDescription) {
            # A team or a switch with incomplete GUID metadata must never look like an unbound adapter.
            $s
        }
    }
}
function BridgeStatus($link,$external) {
    $guid=([guid]$link.InterfaceGuid).ToString('D')
    $bound=@(BridgeSwitches $link $external)
    $result=@{id=$guid;name=[string]$link.Name;bound=($bound.Count -gt 0);switchGuid=$null;switchName=$null}
    $issues=@(if ([int]$link.InterfaceType -ne 6) { 'Only physical wired Ethernet is supported.' }
        else {
            if ([string]$link.Status -ne 'Up') { 'The wired adapter is disconnected.' }
            if (!$bound.Count) { BridgeSetupReasons $link }
            elseif ($bound.Count -ne 1 -or $bound[0].EmbeddedTeamingEnabled -or
                !$bound[0].NetAdapterInterfaceGuid -or [guid]$bound[0].NetAdapterInterfaceGuid -ne [guid]$guid) {
                'The external switch uses a team or an unidentified physical adapter.'
            } else {
                if (!$bound[0].AllowManagementOS) { 'The external switch does not share the adapter with Windows.' }
                try {
                    $hostNics=@(Get-VMNetworkAdapter -ManagementOS -ErrorAction Stop | Where-Object { $_.SwitchId -eq $bound[0].Id })
                    if ($hostNics.Count -ne 1) { 'The external switch needs one verified Windows host adapter.' }
                } catch { 'Windows could not verify the external switch host adapter.' }
            }
        }
    )
    $result.reasons=@($issues | Select-Object -Unique)
    $result.reason=$result.reasons -join ' '
    $result.available=($issues.Count -eq 0)
    if ($result.available -and $bound.Count) { $result.switchGuid=$bound[0].Id.ToString('D'); $result.switchName=$bound[0].Name }
    elseif ($result.available) { $result.reason='Administrator setup must create a shared external switch. Ethernet may briefly disconnect.' }
    return $result
}
function BridgeAdapters {
    $external=@(Get-VMSwitch | Where-Object { $_.SwitchType.ToString() -eq 'External' })
    $items=@(foreach ($link in Get-NetAdapter -Physical) { BridgeStatus $link $external })
    return @{adapters=$items}
}
function ResolveBridge($p) {
    CheckId $p.networkId
    $adapter=[guid]::Empty
    if (![guid]::TryParseExact([string]$p.adapterId,'D',[ref]$adapter) -or $adapter -eq [guid]::Empty) { Refuse 'Choose a physical Ethernet adapter.' }
    $links=@(Get-NetAdapter -Physical | Where-Object { ([guid]$_.InterfaceGuid) -eq $adapter })
    if ($links.Count -ne 1) { Refuse 'This physical adapter is unavailable.' }
    $external=@(Get-VMSwitch | Where-Object { $_.SwitchType.ToString() -eq 'External' })
    $info=BridgeStatus $links[0] $external
    if (!$info.available -or !$info.switchGuid) {
        $issues=$info.reasons
        if ($info.available -and $p.switchGuid) { $issues=@('The recorded external switch is missing.') }
        if (!$info.bound -and @(Get-VMSwitch | Where-Object { $_.Name -ieq ('SVM-'+$p.networkId) }).Count) {
            $issues+=@('The requested switch name is already in use.')
        }
        return @{guid=$null;canSetup=($info.available -and !$info.bound -and !$p.switchGuid -and !$issues.Count);reasons=$issues}
    }
    if ($p.switchGuid -and $info.switchGuid -ine $p.switchGuid) { Refuse 'The external switch identity changed. Select the adapter again.' }
    $s=@($external | Where-Object { $_.Id.ToString('D') -ieq $info.switchGuid })[0]
    if (@(Get-VMSwitch | Where-Object { $_.Name -ieq $s.Name }).Count -ne 1) { Refuse 'The external switch name is ambiguous.' }
    $owned=($s.Name -ceq ('SVM-'+$p.networkId) -and $s.Notes -ceq ('secwiz-bridge:'+$p.networkId))
    if (!$owned -and ($s.Name -ilike 'SVM-*' -or $s.Notes -ilike 'secwiz-bridge:*')) { Refuse 'The external switch has a different project identity.' }
    return @{guid=$s.Id.ToString('D');name=$s.Name;owned=$owned}
}
function Dispatch($p) {
    if ($p.op -ceq 'bridgeAdapters') { return BridgeAdapters }
    if ($p.op -ceq 'resolveBridge') { return ResolveBridge $p }
    Refuse 'Unknown bridge operation.'
}
