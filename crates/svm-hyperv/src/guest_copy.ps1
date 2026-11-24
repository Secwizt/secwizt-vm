$mutex = $null
$held = $false
try {
    $env:PSModulePath = [IO.Path]::Combine($PSHOME, 'Modules')
    Import-Module Hyper-V -ErrorAction Stop
    $p = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($env:SVM_PARAMS)) | ConvertFrom-Json
    $mutex = [Threading.Mutex]::new($false, 'Global\SecwizVM-HyperV-Management')
    try { $held = $mutex.WaitOne(10000) } catch [Threading.AbandonedMutexException] { $held = $true }
    if (!$held) { Refuse 'The verified Hyper-V registration could not be locked.' }
    $vm = OwnedVM $p
    if (!$p.guid -or $vm.State.ToString() -ne 'Running') { Refuse 'Start the verified Hyper-V guest before sending a file.' }
    $serviceId = 'Microsoft:{0}\6C09BB55-D683-4DA0-8931-C9BF705F6480' -f $vm.Id
    $services = @(Get-VMIntegrationService -VM $vm | Where-Object { $_.Id -eq $serviceId })
    if ($services.Count -ne 1 -or !$services[0].Enabled) { Refuse 'Enable Guest Service Interface for this machine before sending a file.' }
    if ($p.op -ceq 'preflight') {
        [Console]::Out.WriteLine((ConvertTo-Json -InputObject @{ token = [guid]::NewGuid().ToString('N') } -Compress))
        return
    }
    if ($p.op -cne 'copy' -or !$p.source -or !$p.destination -or $p.source.Contains('%') -or $p.destination.Contains('%')) {
        Refuse 'Hyper-V Guest Services requires literal paths without percent signs.'
    }
    $source = ExactPath $p.source
    if (!(Test-Path -LiteralPath $source -PathType Leaf)) { Refuse 'The source file is no longer available.' }
    # Cancel and status requests must be able to inspect the machine during the native copy.
    $mutex.ReleaseMutex()
    $held = $false
    try {
        $null = Copy-VMFile -VM $vm -SourcePath $source -DestinationPath ([string]$p.destination) -FileSource Host -ErrorAction Stop
    } catch {
        if (AccessDenied $_) { throw 'SVM_PERMISSION: Hyper-V denied the guest file copy.' }
        Refuse 'Hyper-V Guest Services could not write the private guest upload. Check that the Hyper-V file copy daemon or service is running inside the guest.'
    }
    [Console]::Out.WriteLine('{"ok":true}')
} catch {
    $errorText = $_.Exception.Message
    if ($errorText -cnotmatch '^SVM_(REFUSED|PERMISSION|MISSING):') {
        $errorText = 'SVM_REFUSED: Hyper-V could not prepare the guest file copy.'
    }
    [Console]::Error.WriteLine((ConvertTo-Json -InputObject @{ error = $errorText } -Compress))
    exit 3
} finally {
    if ($held) { $mutex.ReleaseMutex() }
    if ($mutex) { $mutex.Dispose() }
}
}
