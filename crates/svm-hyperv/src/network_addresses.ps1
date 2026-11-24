& {
    $ErrorActionPreference = 'Stop'
    $ProgressPreference = 'SilentlyContinue'
    [Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
    try {
        $owned = @{}
        $adapters = @(Get-NetAdapter -IncludeHidden)
        $hostNics = @(Get-VMNetworkAdapter -ManagementOS)
        foreach ($sw in @(Get-VMSwitch)) {
            if ($sw.Name -cnotmatch '^SVM-([A-Za-z0-9][A-Za-z0-9_.-]{0,79})$') { continue }
            if ($sw.SwitchType.ToString() -ne 'Internal' -or $sw.Notes -cne ('secwiz-switch:' + $sw.Name.Substring(4))) { continue }
            $vnic = @($hostNics | Where-Object { $_.SwitchId -eq $sw.Id -and $_.Name -ceq $sw.Name })
            if ($vnic.Count -ne 1) { continue }
            $adapter = @($adapters | Where-Object {
                $_.Name -ceq ('vEthernet (' + $sw.Name + ')') -and
                ($_.MacAddress -replace '[-:]','') -ieq $vnic[0].MacAddress
            })
            if ($adapter.Count -eq 1) { $owned[[int]$adapter[0].ifIndex] = $sw.Id.ToString() }
        }
        # An empty list means Windows reported no NAT. Null means access or enumeration failed.
        $natRules = $null
        try {
            $natRules = @(Get-NetNat -ErrorAction Stop | ForEach-Object {
                [pscustomobject]@{ name=[string]$_.Name; prefix=[string]$_.InternalIPInterfaceAddressPrefix }
            })
        } catch { $natRules = $null }
        $resolvers = @{}
        foreach ($route in @(Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Sort-Object RouteMetric)) {
            $idx = [int]$route.InterfaceIndex
            if (!$owned.ContainsKey($idx) -and !$resolvers.ContainsKey($idx)) {
                $dns = Get-DnsClientServerAddress -InterfaceIndex $idx -AddressFamily IPv4 -ErrorAction SilentlyContinue
                $resolvers[$idx] = @($dns.ServerAddresses | Where-Object { $_ })
            }
        }
        $rows = @(foreach ($ip in @(Get-NetIPAddress -AddressFamily IPv4)) {
            [pscustomobject]@{ address=$ip.IPAddress; prefix=[int]$ip.PrefixLength;
                alias=$ip.InterfaceAlias; natRules=$natRules; preferred=($ip.AddressState.ToString() -eq 'Preferred');
                switchGuid=$owned[[int]$ip.InterfaceIndex]; resolvers=@($resolvers[[int]$ip.InterfaceIndex] | Where-Object { $_ }) }
        })
        [Console]::Out.Write((ConvertTo-Json -InputObject $rows -Compress -Depth 5))
    } catch {
        [Console]::Error.Write((ConvertTo-Json -InputObject @{ error=$_.Exception.Message; id=$_.FullyQualifiedErrorId } -Compress))
        exit 3
    }
}
