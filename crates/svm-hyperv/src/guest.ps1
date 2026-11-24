function GuestSystem($v) {
    $guid = ([guid]$v.Id).ToString('D')
    $systems = @(Get-CimInstance -Namespace 'root\virtualization\v2' -ClassName Msvm_ComputerSystem -Filter "Name='$guid'" -OperationTimeoutSec 4)
    if ($systems.Count -ne 1 -or $systems[0].Name -ine $guid) { Refuse 'The owned guest registration could not be identified.' }
    $systems[0]
}
function ShutdownReason($components) {
    if ($components.Count -ne 1) { return 'Hyper-V could not identify one shutdown integration component for this guest.' }
    $component = $components[0]
    if ($component.EnabledState -ne 2) { return 'The Hyper-V shutdown integration service is disabled for this machine.' }
    $status = @($component.OperationalStatus)
    if ($status.Count) {
        switch ($status[0]) {
            2 { return $null }
            3 { return $null } # The guest negotiated a compatible protocol.
            12 { return 'The guest shutdown integration service is absent or has not contacted Hyper-V yet.' }
            13 { return 'Hyper-V lost contact with the guest shutdown integration service.' }
            7 { return 'The guest shutdown integration service has an incompatible protocol.' }
        }
    }
    return 'The guest shutdown integration service is not ready.'
}
function SendNativeKey($keyboard, [string]$method, [uint32]$code, $report, $clock) {
    $call = @{InputObject=$keyboard; MethodName=$method; OperationTimeoutSec=3; ErrorAction='Stop'}
    if ($method -ne 'TypeCtrlAltDel') { $call.Arguments = @{KeyCode=$code} }
    while ($true) {
        $result = Invoke-CimMethod @call
        if ($null -eq $result.ReturnValue) { throw 'Hyper-V did not return a key status.' }
        if ($result.ReturnValue -eq 0) { return }
        if ($result.ReturnValue -ne 32775) { throw "Hyper-V refused the key (status $($result.ReturnValue))." }
        if ($clock.ElapsedMilliseconds + 300 -ge 12000) { throw 'The keyboard did not become ready within 12 seconds (status 32775).' }
        Start-Sleep -Milliseconds 300
        if ($clock.ElapsedMilliseconds -ge 12000) { throw 'The keyboard did not become ready within 12 seconds (status 32775).' }
        $report.retried = $true
    }
}
function SendGuestKeys($keyboard, $strokes) {
    if ($strokes.Count -lt 1 -or $strokes.Count -gt 64) { Refuse 'Send 1 to 64 guest keys.' }
    $report = @{ sent=0; retried=$false; error=$null }
    foreach ($stroke in $strokes) {
        $clock = [Diagnostics.Stopwatch]::StartNew()
        try {
            if ($stroke.shift) {
                # Releasing on an ambiguous PressKey result avoids stranding Shift in the guest.
                try {
                    SendNativeKey $keyboard 'PressKey' 16 $report $clock
                    SendNativeKey $keyboard 'TypeKey' $stroke.code $report $clock
                    $report.sent++
                } finally {
                    try { SendNativeKey $keyboard 'ReleaseKey' 16 $report $clock }
                    catch { throw "Check the Shift key in the guest. Hyper-V could not confirm its release. $($_.Exception.Message)" }
                }
            } else {
                $method = if ($stroke.code -eq 0) { 'TypeCtrlAltDel' } else { 'TypeKey' }
                SendNativeKey $keyboard $method $stroke.code $report $clock
                $report.sent++
            }
        } catch {
            $report.error = $_.Exception.Message
            break
        }
    }
    return $report
}
function Dispatch($p) {
    $v = OwnedVM $p
    if ($v.State.ToString() -ne 'Running') { Refuse 'Start or resume the machine before using guest controls.' }
    $system = GuestSystem $v
    if ($p.op -in @('guestStatus','keys')) {
        try {
            $keyboards = @(Get-CimAssociatedInstance -InputObject $system -Association Msvm_SystemDevice -ResultClassName Msvm_Keyboard -OperationTimeoutSec 4)
            $keyReason = $null
            if ($keyboards.Count -ne 1) { $keyReason = 'Hyper-V could not identify one virtual keyboard for this guest.' }
        } catch {
            if ($p.op -ne 'guestStatus') { throw }
            $keyReason = 'Hyper-V could not read the virtual keyboard for this guest.'
        }
        if ($p.op -eq 'keys') {
            if ($keyReason) { return @{sent=0; retried=$false; error=$keyReason} }
            return SendGuestKeys $keyboards[0] @($p.strokes)
        }
    }
    try {
        $components = @(Get-CimAssociatedInstance -InputObject $system -Association Msvm_SystemDevice -ResultClassName Msvm_ShutdownComponent -OperationTimeoutSec 4)
        $reason = $null
        $observed = ShutdownReason $components
        if ($observed) { $reason = [string]$observed }
    } catch {
        if ($p.op -ne 'guestStatus') { throw }
        $reason = 'Hyper-V could not read the guest shutdown integration service.'
    }
    if ($p.op -eq 'guestStatus') {
        return @{
            powerReason=$reason
            keyReason=$keyReason
            enhancedSessionModeState=$system.EnhancedSessionModeState
        }
    }
    if ($p.op -notin @('shutdown','restart')) { Refuse 'Unknown guest operation.' }
    if ($reason) { Refuse $reason }
    $method = if ($p.op -eq 'shutdown') { 'InitiateShutdown' } else { 'InitiateReboot' }
    $clock = [Diagnostics.Stopwatch]::StartNew()
    try {
        $result = Invoke-CimMethod -InputObject $components[0] -MethodName $method -Arguments @{Force=$false;Reason='Requested by the machine owner.'} -OperationTimeoutSec 25
    } catch {
        if ($_.CategoryInfo.Category -eq 'OperationTimeout' -or $clock.Elapsed.TotalSeconds -ge 25) { return @{power='timeout'} }
        throw
    }
    if ($result.ReturnValue -eq 32772) { return @{power='timeout'} }
    if ($result.ReturnValue -eq 32769) { throw 'SVM_PERMISSION: Hyper-V denied access to the guest shutdown integration service.' }
    if ($result.ReturnValue -eq 32781) { Refuse 'The guest is locked and declined the request. Unlock it or choose Power off.' }
    if ($null -eq $result.ReturnValue -or $result.ReturnValue -notin @(0,4096)) { Refuse "The guest declined the power request (Hyper-V status $($result.ReturnValue))." }
    if ($p.op -eq 'restart' -and $result.ReturnValue -eq 0) { return @{power='accepted'} }
    $restarting = $false
    while ($clock.Elapsed.TotalSeconds -lt 25) {
        $current = GuestSystem $v
        if ($p.op -eq 'shutdown' -and $current.EnabledState -eq 3) { return @{power='off'} }
        if ($p.op -eq 'restart') {
            if ($current.EnabledState -in @(3,10)) { $restarting=$true }
            $uptimeReset=$null -ne $current.OnTimeInMilliseconds -and $null -ne $system.OnTimeInMilliseconds -and
                $current.OnTimeInMilliseconds -lt $system.OnTimeInMilliseconds
            if ($current.EnabledState -eq 2 -and ($restarting -or $uptimeReset)) { return @{power='accepted'} }
        }
        Start-Sleep -Milliseconds 400
    }
    return @{power='timeout'}
}
