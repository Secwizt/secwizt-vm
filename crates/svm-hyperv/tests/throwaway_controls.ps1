# Exercise the production throwaway dispatcher against an in-memory Hyper-V provider and real temporary files.
$ErrorActionPreference = 'Stop'
$PSModuleAutoLoadingPreference = 'None'
Import-Module Microsoft.PowerShell.Management, Microsoft.PowerShell.Utility
. ([scriptblock]::Create([IO.File]::ReadAllText($env:SVM_THROWAWAY_SOURCE)))

function Check($condition, [string]$what) { if (!$condition) { throw "Check failed: $what" } }
function Fails([scriptblock]$action, [string]$expected) {
    try { $null = & $action } catch {
        if ($_.Exception.Message -like "*$expected*") { return }
        throw "Unexpected refusal: $($_.Exception.Message)"
    }
    throw "Expected a refusal containing: $expected"
}

$root = Join-Path ([IO.Path]::GetTempPath()) ('svm-throwaway-fixture-' + [guid]::NewGuid().ToString('N'))
$folder = Join-Path $root 'fixture.swvm'
$templateFolder = Join-Path $root 'template.swvm'
$null = New-Item -ItemType Directory -Path $folder, $templateFolder
$base = Join-Path $folder 'system.vhdx'
$leaf = Join-Path $folder '.svm-throwaway.vhdx'
$journal = Join-Path $folder 'hyperv-throwaway.json'
$template = Join-Path $templateFolder 'system.vhdx'
[IO.File]::WriteAllBytes($base, [byte[]](1..64))
[IO.File]::WriteAllBytes($template, [byte[]](1..16))
$baseBytes = [Convert]::ToBase64String([IO.File]::ReadAllBytes($base))
(Get-Item -LiteralPath $base).IsReadOnly = $true   # throwaway mode is on
$settingsAtAttach = $null

$vm = [pscustomobject]@{ Name='svm-fixture'; Id=[guid]::NewGuid(); State='Off'; ConfigurationLocation=(Join-Path $folder 'Virtual Machines'); Path=$folder
    AutomaticStartAction='StartIfRunning'; AutomaticStopAction='Save'; CheckpointType='Production' }
$drive = [pscustomobject]@{ Path=$base }
$disks = @{}
$disks[$base] = @{ type='Dynamic'; parent=$null }
$snapshots = @()
$tpm = $false
$failStart = $false
$grants = 0
$journalAtAttach = $null
$savedRemoved = 0
$failReattach = $false
$p = [pscustomobject]@{ id='fixture'; op=''; bundle=$folder; templateDisk=$null }
function Record([string]$id) {
    @{ id=$id; guid=$script:vm.Id.ToString(); original='system.vhdx'; overlay='.svm-throwaway.vhdx'; auto=@('StartIfRunning','Save','Production') } | ConvertTo-Json -Compress
}

function Refuse([string]$message) { throw $message }
function OwnedVM($p) { $script:vm }
function ExactPath([string]$path) { $path }
function IsBelow([string]$path, [string]$root) { $path.StartsWith(($root.TrimEnd('\') + '\'), [StringComparison]::OrdinalIgnoreCase) }
function Bundle($p) { $script:folder }
function GrantChainAccess($vm) { $script:grants++ }
function Get-VMHardDiskDrive { param($VM) @($script:drive) }
function Get-VMSnapshot { param($VM) $script:snapshots }
function Get-VMSecurity { param($VM) [pscustomobject]@{ TpmEnabled=$script:tpm } }
function Get-VHD {
    param($Path)
    $row = $script:disks[$Path]
    if (!$row) { throw "Unknown fixture disk $Path" }
    [pscustomobject]@{ Path=$Path; VhdFormat='VHDX'; VhdType=$row.type; ParentPath=$row.parent }
}
function New-VHD {
    param($Path, $ParentPath, [switch]$Differencing)
    [IO.File]::WriteAllBytes($Path, [byte[]](9, 9, 9))
    $script:disks[$Path] = @{ type='Differencing'; parent=$ParentPath }
}
function Set-VMHardDiskDrive {
    param($VMHardDiskDrive, $Path)
    if ($Path -eq $script:leaf) { $script:journalAtAttach = Test-Path -LiteralPath $script:journal; $script:settingsAtAttach = Own 'Nothing' 'TurnOff' 'Disabled' }
    if ($Path -eq $script:base -and (Get-Item -LiteralPath $script:base).IsReadOnly) { throw 'Hyper-V cannot attach a read-only disk.' }
    if ($Path -eq $script:base -and $script:failReattach) { throw 'Fixture reattach failure.' }
    $VMHardDiskDrive.Path = $Path
}
function Set-VM {
    param($VM, $AutomaticStartAction, $AutomaticStopAction, $CheckpointType)
    if ($null -ne $AutomaticStartAction) { $script:vm.AutomaticStartAction = $AutomaticStartAction }
    if ($null -ne $AutomaticStopAction) { $script:vm.AutomaticStopAction = $AutomaticStopAction }
    if ($null -ne $CheckpointType) { $script:vm.CheckpointType = $CheckpointType }
}
function Own([string]$start, [string]$stop, [string]$checkpoints) {
    $script:vm.AutomaticStartAction -ceq $start -and $script:vm.AutomaticStopAction -ceq $stop -and $script:vm.CheckpointType -ceq $checkpoints
}
function Remove-VMSavedState { param($VM) $script:savedRemoved++; $script:vm.State = 'Off' }
function Start-VM {
    param($VM)
    if ($script:failStart) { throw 'Fixture start failure.' }
    $script:vm.State = 'Running'
}

try {
    # A start writes its record before the swap and runs the guest on the temporary disk.
    $p.op = 'throwawayStart'
    Check ((Dispatch $p).started -eq $true) 'the start is confirmed'
    Check ($journalAtAttach -eq $true) 'the record exists before the temporary disk is attached'
    Check ($settingsAtAttach -eq $true) 'the run settings are in place before the temporary disk is attached'
    Check ($drive.Path -eq $leaf -and (Test-Path -LiteralPath $leaf)) 'the temporary disk is attached'
    Check ($grants -eq 1 -and $vm.State -eq 'Running') 'the disk chain is made readable before the guest starts'
    $record = [IO.File]::ReadAllText($journal) | ConvertFrom-Json
    Check ($record.id -ceq 'fixture' -and $record.guid -ieq $vm.Id.ToString() -and $record.original -ceq 'system.vhdx' -and $record.overlay -ceq '.svm-throwaway.vhdx') 'the record names this run'
    Check (($record.auto -join ',') -ceq 'StartIfRunning,Save,Production') 'the record keeps the machine''s own automatic actions and checkpoint type'
    Check (Own 'Nothing' 'TurnOff' 'Disabled') 'a host restart can neither save, resume nor boot the run, and no checkpoint can be taken'

    # Nothing is recovered while the guest runs, and a second start is refused.
    $p.op = 'throwawayRecover'
    Check ((Dispatch $p).recovered -eq $false) 'a running guest keeps its temporary disk'
    Check ($drive.Path -eq $leaf -and (Test-Path -LiteralPath $journal)) 'the running attachment is untouched'
    $p.op = 'throwawayStart'
    Fails { Dispatch $p } 'recover the previous throwaway run'

    # Power-off: the original disk returns and the temporary disk is deleted.
    $vm.State = 'Off'
    $p.op = 'throwawayRecover'
    Check ((Dispatch $p).recovered -eq $true) 'power-off restores the original disk'
    Check ($drive.Path -eq $base -and !(Test-Path -LiteralPath $leaf) -and !(Test-Path -LiteralPath $journal)) 'nothing temporary remains'
    Check ([Convert]::ToBase64String([IO.File]::ReadAllBytes($base)) -ceq $baseBytes) 'the original disk bytes are unchanged'
    Check (Own 'StartIfRunning' 'Save' 'Production') 'recovery restores the machine''s own settings'
    Check ((Get-Item -LiteralPath $base).IsReadOnly) 'the original disk is read-only again before the record goes'
    Check ((Dispatch $p).recovered -eq $false) 'a repeated recovery finds nothing to do'

    # A guest saved by a Windows shutdown cannot resume on its temporary disk, so saving ends the run.
    $p.op = 'throwawayStart'
    $null = Dispatch $p
    $vm.State = 'Saved'
    $p.op = 'throwawayRecover'
    Check ((Dispatch $p).recovered -eq $true) 'a saved throwaway guest is recovered'
    Check ($savedRemoved -eq 1 -and $vm.State -eq 'Off') 'its saved state is discarded first'
    Check ($drive.Path -eq $base -and !(Test-Path -LiteralPath $leaf) -and !(Test-Path -LiteralPath $journal)) 'the original disk is back'

    # A session saved on the ORIGINAL disk is not part of a run: it is kept, and recovery says why.
    [IO.File]::WriteAllText($journal, (Record 'fixture'))
    $vm.State = 'Saved'
    Fails { Dispatch $p } 'saved on the original disk'
    Check ($savedRemoved -eq 1 -and (Test-Path -LiteralPath $journal) -and $vm.State -eq 'Saved') 'no saved state was discarded'
    # A stale record never discards a saved session either.
    [IO.File]::WriteAllText($journal, (Record 'another'))
    $p.op = 'throwawayStart'
    $drive.Path = $leaf
    [IO.File]::WriteAllBytes($leaf, [byte[]](9, 9, 9))
    $p.op = 'throwawayRecover'
    Fails { Dispatch $p } 'does not match this machine'
    Check ($savedRemoved -eq 1 -and $vm.State -eq 'Saved' -and $drive.Path -eq $leaf) 'a stale record changes nothing'
    $vm.State = 'Off'
    [IO.File]::WriteAllText($journal, (Record 'fixture'))
    Check ((Dispatch $p).recovered -eq $true) 'the matching record recovers the run'

    # Every Hyper-V saved variant ends the run the same way.
    $p.op = 'throwawayStart'
    $null = Dispatch $p
    $vm.State = 'FastSaved'
    $p.op = 'throwawayRecover'
    Check ((Dispatch $p).recovered -eq $true -and $savedRemoved -eq 2 -and $drive.Path -eq $base) 'a fast-saved throwaway guest is recovered too'

    # A failed reattach keeps the record and the temporary disk, and a later retry succeeds.
    $p.op = 'throwawayStart'
    $null = Dispatch $p
    $vm.State = 'Off'
    $failReattach = $true
    $p.op = 'throwawayRecover'
    Fails { Dispatch $p } 'Fixture reattach failure'
    Check ((Test-Path -LiteralPath $journal) -and (Test-Path -LiteralPath $leaf) -and $drive.Path -eq $leaf) 'nothing is deleted when the reattach fails'
    Check (Own 'Nothing' 'TurnOff' 'Disabled') 'the run settings stay until recovery succeeds'
    Check ((Get-Item -LiteralPath $base).IsReadOnly) 'a failed reattach puts the read-only flag back'
    $failReattach = $false
    Check ((Dispatch $p).recovered -eq $true) 'the retry recovers'
    Check ($drive.Path -eq $base -and !(Test-Path -LiteralPath $leaf) -and !(Test-Path -LiteralPath $journal)) 'the retry leaves nothing behind'
    Check ((Get-Item -LiteralPath $base).IsReadOnly) 'the retry leaves the original disk read-only'

    # A failed start rolls the swap back.
    $failStart = $true
    $p.op = 'throwawayStart'
    Fails { Dispatch $p } 'Fixture start failure'
    Check ($drive.Path -eq $base -and !(Test-Path -LiteralPath $leaf) -and !(Test-Path -LiteralPath $journal) -and $vm.State -eq 'Off') 'a failed start leaves the machine as it was'
    Check (Own 'StartIfRunning' 'Save' 'Production') 'a failed start restores the machine''s own settings'
    Check ((Get-Item -LiteralPath $base).IsReadOnly) 'a failed start leaves the original disk read-only'
    $failStart = $false

    # Power cut after the swap: the temporary file is gone, but the attachment still points at it.
    $null = Dispatch $p
    $vm.State = 'Off'
    [IO.File]::Delete($leaf)
    $p.op = 'throwawayRecover'
    Check ((Dispatch $p).recovered -eq $true) 'recovery works without the temporary file'
    Check ($drive.Path -eq $base -and !(Test-Path -LiteralPath $journal)) 'the original disk is attached again'

    # Power cut between the record and the swap: only the record exists.
    [IO.File]::WriteAllText($journal, (Record 'fixture'))
    Check ((Dispatch $p).recovered -eq $true) 'a record without a swap is cleared'
    Check ($drive.Path -eq $base -and !(Test-Path -LiteralPath $journal)) 'the original disk stayed attached'

    # A record without the machine's saved settings is refused, so they are never lost.
    [IO.File]::WriteAllText($journal, (@{ id='fixture'; guid=$vm.Id.ToString(); original='system.vhdx'; overlay='.svm-throwaway.vhdx' } | ConvertTo-Json -Compress))
    Fails { Dispatch $p } 'does not match this machine'
    Check (Test-Path -LiteralPath $journal) 'an incomplete record stays for inspection'
    [IO.File]::Delete($journal)

    # A changed attachment or a foreign record is refused, and nothing is deleted.
    [IO.File]::WriteAllText($journal, (Record 'fixture'))
    $drive.Path = Join-Path $folder 'other.vhdx'
    Fails { Dispatch $p } 'changed outside the throwaway run'
    Check (Test-Path -LiteralPath $journal) 'the record stays for a later recovery'
    $drive.Path = $base
    [IO.File]::WriteAllText($journal, (Record 'another'))
    Fails { Dispatch $p } 'does not match this machine'
    Check ((Test-Path -LiteralPath $journal) -and $drive.Path -eq $base) 'a foreign record changes nothing'
    [IO.File]::Delete($journal)

    # Start refusals leave no record and no temporary disk behind.
    $p.op = 'throwawayStart'
    $snapshots = @([pscustomobject]@{ Name='kept' })
    Fails { Dispatch $p } 'Remove the checkpoints'
    $snapshots = @()
    $tpm = $true
    Fails { Dispatch $p } 'disabled virtual TPM'
    $tpm = $false
    $vm.State = 'Running'
    Fails { Dispatch $p } 'Power off and recover'
    $vm.State = 'Off'
    $disks[$base] = @{ type='Differencing'; parent=$template }
    Fails { Dispatch $p } 'standalone VHDX'
    Check (!(Test-Path -LiteralPath $journal) -and !(Test-Path -LiteralPath $leaf) -and $drive.Path -eq $base) 'refusals change nothing'

    # A linked clone starts only against its read-only template.
    $p.templateDisk = $template
    Fails { Dispatch $p } 'read-only template'
    (Get-Item -LiteralPath $template).IsReadOnly = $true
    Check ((Dispatch $p).started -eq $true) 'a linked clone may run as a throwaway machine'
    $vm.State = 'Off'
    $p.op = 'throwawayRecover'
    Check ((Dispatch $p).recovered -eq $true) 'the linked clone returns to its own disk'
    Check ($drive.Path -eq $base -and !(Test-Path -LiteralPath $leaf)) 'the linked clone keeps only its own disk'
} finally {
    if (Test-Path -LiteralPath $template) { (Get-Item -LiteralPath $template).IsReadOnly = $false }
    Remove-Item -LiteralPath $root -Recurse -Force
}
