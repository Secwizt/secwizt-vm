# The receipt is created before a new disk's first attachment, then bound to its registration.
# Comparing physical file bytes includes the VHDX allocation tables without mounting it.
function InstallerReason($p,$v,$folder,$receiptPath) {
    if ($v.State.ToString() -ne 'Off' -or $v.Generation -ne 2) { return 'The installer key requires an off generation 2 machine.' }
    if (![IO.File]::Exists($receiptPath)) { return 'The installer key requires an unused Windows machine with a new empty disk.' }
    try {
        $receipt = [IO.File]::ReadAllText($receiptPath) | ConvertFrom-Json
        if ($receipt.guid -ine $v.Id.ToString() -or $receipt.sha256 -notmatch '^[a-fA-F0-9]{64}$') { return 'The empty-disk record does not match this machine.' }
        $system = Get-CimInstance -Namespace 'root\virtualization\v2' -ClassName Msvm_ComputerSystem -Filter ("Name='" + $v.Id.ToString('D') + "'") -OperationTimeoutSec 3
        if (!$system -or $system.EnabledState -ne 3 -or (StateStamp $system) -cne [string]$receipt.stateStamp) { return 'The machine has changed power state since its disk was created.' }
        $disks = @(Get-VMHardDiskDrive -VM $v)
        $expected = ExactPath ([IO.Path]::Combine($folder,'system.vhdx'))
        if ($disks.Count -ne 1 -or !$disks[0].Path -or (ExactPath $disks[0].Path) -ine $expected) { return 'The new empty disk is no longer the only attached disk.' }
        $dvd = @(Get-VMDvdDrive -VM $v)
        $order = @((Get-VMFirmware -VM $v).BootOrder)
        if ($dvd.Count -ne 1 -or !$dvd[0].Path -or !(Test-Path -LiteralPath $dvd[0].Path -PathType Leaf) -or
            !$order.Count -or [string]$order[0].BootType -ne 'Drive' -or $null -eq $order[0].Device -or
            $order[0].Device.GetType().Name -ne 'DvdDrive' -or $order[0].Device.Id -ne $dvd[0].Id -or
            @($order | Where-Object { [string]$_.BootType -eq 'File' }).Count) { return 'Attach the installer image, set it first, and use a machine without an installed-system boot entry.' }
        if ((Get-Item -LiteralPath $expected).Length -ne $receipt.length -or (Get-FileHash -LiteralPath $expected -Algorithm SHA256).Hash -ine $receipt.sha256) { return 'The disk has changed since it was created empty.' }
        return $null
    } catch { return 'The empty disk and its installer boot order could not be verified.' }
}

function InstallerKeys($v) {
    $ns = 'root\virtualization\v2'
    $clock = [Diagnostics.Stopwatch]::StartNew()
    $sent = 0
    $retried = $false
    $keyboard = $null
    $failure = $null
    try {
        $system = Get-CimInstance -Namespace $ns -ClassName Msvm_ComputerSystem -Filter ("Name='" + $v.Id.ToString('D') + "'") -OperationTimeoutSec 2
        if (!$system -or $system.Name -ine $v.Id.ToString('D')) { throw 'The Hyper-V machine identity changed.' }
        while ($clock.ElapsedMilliseconds -lt 12000) {
            if (!$keyboard) {
                $found = @(Get-CimAssociatedInstance -InputObject $system -Association Msvm_SystemDevice -ResultClassName Msvm_Keyboard -OperationTimeoutSec 2)
                if ($found.Count -gt 1) { throw 'The Hyper-V keyboard could not be identified.' }
                if ($found.Count -eq 1) { $keyboard = $found[0] }
            }
            if ($keyboard -and $clock.ElapsedMilliseconds -lt 12000) {
                $result = Invoke-CimMethod -InputObject $keyboard -MethodName TypeKey -Arguments @{KeyCode=[uint32]13} -OperationTimeoutSec 2
                if ($null -eq $result.ReturnValue) { throw 'Hyper-V returned an unknown keyboard result.' }
                if ($result.ReturnValue -eq 0) { $sent++ }
                elseif ($result.ReturnValue -eq 32775) { $retried = $true }
                else { throw "Hyper-V refused Enter (status $($result.ReturnValue))." }
            } else { $retried = $true }
            $delay = [Math]::Min(300,12000-$clock.ElapsedMilliseconds)
            if ($delay -gt 0) { Start-Sleep -Milliseconds $delay }
        }
    } catch { $failure = $_.Exception.Message }
    $message = "Machine started. Enter sent to the machine $sent times during the installer boot window."
    if ($failure) { $message += " Keyboard window ended early: $failure" }
    elseif ($sent -eq 0) { $message += ' The keyboard did not become ready within 12 seconds.' }
    return @{sent=$sent;retried=$retried;message=$message}
}

function Dispatch($p) {
    $v = OwnedVM $p
    $folder = Bundle $p
    $file = ExactPath ([IO.Path]::Combine($folder,'installer-first-boot.json'))
    $reason = InstallerReason $p $v $folder $file
    if ($p.op -eq 'installerBootStatus') { return @{available=(!$reason);reason=$reason} }
    if ($p.op -ne 'installerStart') { Refuse 'Unknown installer operation.' }
    if ($v.State.ToString() -notin @('Off','Saved','FastSaved','Hibernated')) { Refuse 'Start requires an off or saved machine.' }
    if ($p.pressKeyAtBoot -eq $true -and $reason) { Refuse $reason }
    $assist = (!$reason -and $p.pressKeyAtBoot -ne $false)
    # Consume before starting, even if the caller opts out. A lost response cannot replay the window.
    if ([IO.File]::Exists($file)) {
        try { [IO.File]::Delete($file) } catch {
            if ($p.pressKeyAtBoot -eq $true) { Refuse 'The first-start record could not be consumed. Use a normal start.' }
            $assist = $false
        }
    }
    $v = OwnedVM $p
    if ($assist -and $v.State.ToString() -ne 'Off') { Refuse 'The machine changed state before starting.' }
    Start-VM -VM $v -ErrorAction Stop
    if ($assist) { return @{bootKey=(InstallerKeys $v)} }
    return @{bootKey=$null}
}
