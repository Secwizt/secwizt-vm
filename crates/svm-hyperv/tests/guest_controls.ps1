$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSHOME 'Modules\Microsoft.PowerShell.Utility\Microsoft.PowerShell.Utility.psd1')
$PSModuleAutoLoadingPreference='None'
. ([scriptblock]::Create([IO.File]::ReadAllText($env:SVM_GUEST_SOURCE)))
$fixture = [pscustomobject]@{Id=[guid]::NewGuid();State='Running'}
$systemState = 2
$nativeEnhancedSession = $null
$component = [pscustomobject]@{ EnabledState=2; OperationalStatus=@(2) }
$methods = [Collections.Generic.List[string]]::new()
$codes = [Collections.Generic.List[uint32]]::new()
$resultCode = 0
$returns = [Collections.Generic.Queue[uint32]]::new()
$delays = [Collections.Generic.List[int]]::new()
function Start-Sleep { param($Milliseconds); $script:delays.Add($Milliseconds) }
function OwnedVM($p) { $script:fixture }
function Refuse([string]$message) { throw $message }
function Get-CimInstance { param($Namespace,$ClassName,$Filter,$OperationTimeoutSec)
    if ($Namespace -ne 'root\virtualization\v2' -or $ClassName -ne 'Msvm_ComputerSystem' -or $Filter -ne "Name='$($script:fixture.Id)'") {throw 'Wrong registration'}
    $properties = @{Name=$script:fixture.Id.ToString();EnabledState=$script:systemState;OnTimeInMilliseconds=10000}
    if ($null -ne $script:nativeEnhancedSession) {
        $properties.EnhancedSessionModeState = $script:nativeEnhancedSession
    }
    [pscustomobject]$properties
}
function Get-CimAssociatedInstance { param($InputObject,$Association,$ResultClassName,$OperationTimeoutSec)
    if ($InputObject.Name -ne $script:fixture.Id.ToString() -or $Association -ne 'Msvm_SystemDevice') {throw 'Wrong guest'}
    if ($ResultClassName -eq 'Msvm_ShutdownComponent') {$script:component}
    elseif ($ResultClassName -eq 'Msvm_Keyboard') {[pscustomobject]@{DeviceID='mock keyboard'}}
    else {throw 'Unexpected device query'}
}
function Invoke-CimMethod { param($InputObject,$MethodName,$Arguments,$OperationTimeoutSec)
    if ($MethodName -in @('InitiateShutdown','InitiateReboot')) {
        if ($null -eq $Arguments.Force -or $Arguments.Force) { throw 'A graceful operation tried to force power.' }
        if ($MethodName -eq 'InitiateShutdown' -and !$script:resultCode) { $script:systemState=3 }
    } elseif ($MethodName -in @('TypeKey','PressKey','ReleaseKey')) { $script:codes.Add($Arguments.KeyCode) }
    elseif ($MethodName -ne 'TypeCtrlAltDel') { throw 'Unexpected guest method.' }
    $script:methods.Add($MethodName)
    $status = if ($script:returns.Count) { $script:returns.Dequeue() } else { $script:resultCode }
    [pscustomobject]@{ReturnValue=$status}
}
function Check([bool]$ok,[string]$message) {if (!$ok) {throw $message}}
$ready=Dispatch @{op='guestStatus'}
$nativeEnhancedSession=2
Check ((Dispatch @{op='guestStatus'}).enhancedSessionModeState -eq 2) 'The guest status did not report Enhanced Session availability.'
$nativeEnhancedSession=$null
$component.OperationalStatus=@(12)
Check ((Dispatch @{op='guestStatus'}).powerReason -like '*has not contacted*') 'Missing shutdown integration was advertised.'
$component.OperationalStatus=@(2)
$component.EnabledState=3
Check ((Dispatch @{op='guestStatus'}).powerReason -like '*disabled*') 'Disabled integration was advertised.'
$component.EnabledState=2
Check ((Dispatch @{op='restart'}).power -eq 'accepted') 'Restart acknowledgment lost.'
Check ((Dispatch @{op='shutdown'}).power -eq 'off') 'Power off was not independently observed.'
$systemState=2
$resultCode=32772
Check ((Dispatch @{op='shutdown'}).power -eq 'timeout') 'Guest timeout was reported as success.'
$resultCode=0
$strokes = @(@{code=65;shift=$false},@{code=191;shift=$true},@{code=0;shift=$false})
foreach ($status in @(0,0,32775,0,0,0)) { $returns.Enqueue($status) }
$r = Dispatch @{op='keys';strokes=$strokes}
Check ($r.sent -eq 3 -and $r.retried -and !$r.error) 'Incorrect count or missing retry flag.'
Check (($methods -join ',') -ceq 'InitiateReboot,InitiateShutdown,InitiateShutdown,TypeKey,PressKey,TypeKey,TypeKey,ReleaseKey,TypeCtrlAltDel') 'Wrong method order or replayed a confirmed key.'
Check (($codes -join ',') -eq '65,16,191,191,16') 'Keys or Shift were sent in the wrong order.'
Check (($delays -join ',') -eq '300') 'Not-ready status requires a 300 ms retry.'
$methods.Clear()
$delays.Clear()
foreach ($status in @(0,0,32771,0)) { $returns.Enqueue($status) }
$r = Dispatch @{op='keys';strokes=$strokes}
Check ($r.sent -eq 1 -and !$r.retried -and $r.error -like '*32771*') 'A real refusal must retain the confirmed count and stop.'
Check (($methods -join ',') -ceq 'TypeKey,PressKey,TypeKey,ReleaseKey' -and !$delays.Count) 'Shift stayed pressed or a real refusal was retried.'
$methods.Clear()
foreach ($status in @(0,0,0,32771)) { $returns.Enqueue($status) }
$r = Dispatch @{op='keys';strokes=$strokes}
Check ($r.sent -eq 2 -and $r.error -like '*release*') 'A failed modifier release hid a confirmed key.'
$progress = @{sent=0;retried=$true}
$returns.Enqueue(32775)
$expired = $false
try { SendNativeKey $fixture 'TypeKey' 13 $progress ([pscustomobject]@{ElapsedMilliseconds=11900}) }
catch { $expired = $_.Exception.Message -like '*12 seconds*' }
Check ($expired -and !$delays.Count) 'An exhausted retry window attempted another key.'
[Console]::Out.Write((ConvertTo-Json -InputObject $ready -Compress))
