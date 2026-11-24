$ErrorActionPreference='Stop'
$PSModuleAutoLoadingPreference='None'
$env:PSModulePath = [IO.Path]::Combine($PSHOME,'Modules')
Import-Module Microsoft.PowerShell.Utility
Import-Module Microsoft.PowerShell.Management
. $env:SVM_INSTALLER_SOURCE
class DvdDrive { [string]$Id }
function ExactPath($path) { [string]$path }
function StateStamp($system) { $system.stamp }
function OwnedVM($p) { $script:vm }
function Bundle($p) { $script:folder }
function Refuse($s) { throw $s }
function Get-CimInstance { param($Namespace,$ClassName,$Filter,$OperationTimeoutSec) $script:sys }
function Get-VMHardDiskDrive { param($VM) [pscustomobject]@{Path=$script:disk} }
function Get-VMDvdDrive { param($VM) [pscustomobject]@{Id='dvd';Path=$script:iso} }
function Get-VMFirmware { param($VM) [pscustomobject]@{BootOrder=$script:order} }
function Get-CimAssociatedInstance { param($InputObject,$Association,$ResultClassName,$OperationTimeoutSec) @('keyboard') }
function Invoke-CimMethod {
    param($InputObject,$MethodName,$Arguments,$OperationTimeoutSec)
    if ($Arguments.KeyCode -ne 13) { throw 'Unexpected virtual key' }
    $script:strokes++
    return @{ ReturnValue=@(32775,0,32776)[$script:strokes-1] }
}
function Start-Sleep { param($Milliseconds) }
function Start-VM { param($VM,$ErrorAction) $script:starts++; $VM.State='Running' }
function Check($ok,$message) { if (!$ok) { throw $message } }
$script:vm=[pscustomobject]@{Id=[guid]::NewGuid();State='Off';Generation=2}
$script:sys=[pscustomobject]@{Name=$vm.Id.ToString();EnabledState=3;stamp='original'}
$script:folder=[IO.Directory]::CreateDirectory([IO.Path]::Combine([IO.Path]::GetTempPath(),[guid]::NewGuid().ToString())).FullName
$script:disk=[IO.Path]::Combine($folder,'system.vhdx')
$script:iso=[IO.Path]::Combine($folder,'setup.iso')
$mark=[IO.Path]::Combine($folder,'installer-first-boot.json')
try {
    [IO.File]::WriteAllText($disk,'AAA')
    [IO.File]::WriteAllText($iso,'image')
    $dvd=[DvdDrive]::new(); $dvd.Id='dvd'
    $entry=[pscustomobject]@{BootType='Drive';Device=$dvd}
    $script:order=@($entry)
    $p=@{op='installerBootStatus';pressKeyAtBoot=$true}
    $recipe=@{guid=$vm.Id.ToString();sha256=(Get-FileHash -LiteralPath $disk).Hash;length=3;stateStamp='original'}
    Check (!(Dispatch $p).available) 'Missing record allowed a boot key'
    [IO.File]::WriteAllText($mark,($recipe|ConvertTo-Json))
    Check ((Dispatch $p).available) 'Unchanged new disk was refused'
    $sys.stamp='externally restarted'
    Check (!(Dispatch $p).available) 'External power cycle allowed a first-start key'
    $sys.stamp='original'
    [IO.File]::WriteAllText($disk,'BBB')
    Check (!(Dispatch $p).available) 'Equal-size but modified disk allowed a key'
    [IO.File]::WriteAllText($disk,'AAA')
    $script:order=@($entry,[pscustomobject]@{BootType='File'})
    Check (!(Dispatch $p).available) 'Installed firmware entry allowed a key'
    $script:order=@($entry)
    $script:starts=0
    $script:strokes=0
    $p.op='installerStart'
    $reply=Dispatch $p
    Check ($starts -eq 1 -and $strokes -eq 3 -and $reply.bootKey.sent -eq 1 -and $reply.bootKey.retried) 'Boot key count, refusal or retry was lost'
    Check ($reply.bootKey.message -match '32776') 'Startup result hid the keyboard refusal'
    Check (![IO.File]::Exists($mark)) 'First start left a reusable record'
} finally {
    foreach ($f in @($disk,$iso,$mark)) { if ([IO.File]::Exists($f)) { [IO.File]::Delete($f) } }
    [IO.Directory]::Delete($folder)
}
