# Exercise the production storage dispatcher against an in-memory Hyper-V provider.
$ErrorActionPreference = 'Stop'
$PSModuleAutoLoadingPreference = 'None'
. ([scriptblock]::Create([IO.File]::ReadAllText($env:SVM_STORAGE_SOURCE)))

class HardDiskDrive { [string]$Id; [string]$Path }
class DvdDrive { [string]$Id; [object]$Path }

$vm = [pscustomobject]@{ Name='fixture'; Id=[guid]::NewGuid(); Generation=2; State='Off' }
$disk = [HardDiskDrive]::new()
$disk.Id = 'shared-identifier'
$disk.Path = 'C:\fixtures\system.vhdx'
$dvd = [DvdDrive]::new()
$dvd.Id = $disk.Id
$iso = 'C:\fixtures\installer.iso'
$dvd.Path = $iso
$diskSource = [pscustomobject]@{ Device=$disk; FirmwarePath='disk' }
$dvdSource = [pscustomobject]@{ Device=$dvd; FirmwarePath='dvd' }
$networkSource = [pscustomobject]@{ Device=$null; FirmwarePath='network' }
$order = @($dvdSource, $networkSource, $diskSource)
$firmwareWrites = 0
$mediaWrites = 0
$ignoreWrites = $false
$emptyPath = ''
$lagReadsAfterEject = 0
$pendingEjectReads = 0
function OwnedVM($p) { $script:vm }
function ExactPath([string]$path) { $path }
function Refuse([string]$message) { throw $message }
function Get-VMHardDiskDrive { param($VM) $script:disk }
function Get-VMDvdDrive {
    param($VM)
    if ($script:pendingEjectReads -gt 0) {
        $script:pendingEjectReads--
        if ($script:pendingEjectReads -eq 0) { $script:dvd.Path = $script:emptyPath }
    }
    if ($null -ne $script:dvd) { $script:dvd }
}
function Get-VMFirmware {
    param($VMName,$VM,$ErrorAction)
    [pscustomobject]@{ VMId=$script:vm.Id; BootOrder=$script:order }
}
function Get-VHD { param($Path) [pscustomobject]@{ Path=$Path; Size=100L; FileSize=12L; ParentPath=$null } }
function Test-Path { param($LiteralPath,$PathType) $LiteralPath -eq $script:iso }
function Set-VMFirmware {
    param($VM,$BootOrder,$FirstBootDevice,$ErrorAction)
    $script:firmwareWrites++
    if (!$script:ignoreWrites -and $null -ne $BootOrder) { $script:order = @($BootOrder) }
}
function Set-VMDvdDrive {
    param($VMDvdDrive,$Path,$ErrorAction)
    $script:mediaWrites++
    if ($script:ignoreWrites) { return }
    if ($null -eq $Path -and $script:lagReadsAfterEject) {
        $script:pendingEjectReads = $script:lagReadsAfterEject
    } else {
        $VMDvdDrive.Path = if ([string]::IsNullOrEmpty($Path)) { $script:emptyPath } else { $Path }
    }
}
function Add-VMDvdDrive { throw 'Unexpected creation of a new DVD slot.' }
function Start-Sleep { param($Milliseconds) }
function Check([bool]$ok,[string]$context) { if (!$ok) { throw $context } }
function ExpectRefusal([scriptblock]$operation,[string]$reason) {
    try { $null = & $operation } catch {
        if ($_.Exception.Message -like "*$reason*") { return }
        throw
    }
    throw "Expected refusal: $reason"
}
function Edit($field,$value) {
    $p = @{op='setStorage'; edit=$field; value=$value}
    $null = Dispatch $p
    $p.op = 'confirmStorage'
    $read = Dispatch $p
    if (!$read.confirmed) { throw 'did not confirm' }
    return $read.storage
}

Check ((Dispatch @{op='storage'}).bootFirst -eq 'image') 'Fresh DVD-first firmware misreported as disk.'
$result = Edit 'bootFirst' 'disk'
Check ($result.bootFirst -eq 'disk' -and ($order.FirmwarePath -join ',') -ceq 'disk,dvd,network') 'Disk first did not preserve the remaining firmware entries.'
$result = Edit 'bootFirst' 'disk'
Check ($firmwareWrites -eq 1) 'Repeated disk-first selection rewrote firmware.'
$result = Edit 'bootFirst' 'image'
Check ($result.bootFirst -eq 'image' -and ($order.FirmwarePath -join ',') -ceq 'dvd,disk,network') 'Image first did not change the actual firmware order.'
$ignoreWrites = $true
ExpectRefusal { Edit 'bootFirst' 'disk' } 'did not confirm'
ExpectRefusal { Edit 'isoPath' $null } 'did not confirm'
$ignoreWrites = $false

foreach ($empty in @($null, '', '  ')) {
    $emptyPath = $empty
    $dvd.Path = $iso
    $result = Edit 'isoPath' $null
    Check ($null -eq $result.isoPath -and [string]::IsNullOrWhiteSpace([string]$dvd.Path)) 'Eject failed to recognize empty media.'
    $writesBeforeRepeat = $mediaWrites
    $result = Edit 'isoPath' $null
    Check ($mediaWrites -eq $writesBeforeRepeat) 'A second eject touched an empty drive.'
}
$result = Edit 'isoPath' $iso
Check ($result.isoPath -ceq $iso -and $dvd.Path -ceq $iso) 'Reattaching media reported the wrong path.'
$lagReadsAfterEject = 2
$null = Dispatch @{op='setStorage'; edit='isoPath'; value=$null}
$probe = @{op='confirmStorage'; edit='isoPath'; value=$null}
Check (!(Dispatch $probe).confirmed) 'A stale DVD path was accepted as ejected.'
$fresh = Dispatch $probe
Check ($fresh.confirmed -and $null -eq $fresh.storage.isoPath -and $pendingEjectReads -eq 0) 'Fresh empty DVD state was refused.'
$dvd = $null
$result = Edit 'isoPath' $null
Check ($null -eq $result.isoPath) 'A machine without a DVD drive already has no media.'

# A guest-created UEFI file entry can refer to its disk. It must keep its place among the other entries.
$system = [pscustomobject]@{BootType='File'; Description='debian'; Device=$disk; FirmwarePath='efi-file'}
$dvd = [DvdDrive]::new()
$dvd.Path = $iso
$order = @($system,$dvdSource,$networkSource,$diskSource)
$read = Dispatch @{op='storage'}
Check ($read.bootFirst -ceq 'system' -and $read.bootDescription -ceq 'debian') 'Installed operating system entry was not reported.'
$read = Edit 'bootFirst' 'disk'
Check ($read.bootFirst -ceq 'disk' -and ($order.FirmwarePath -join ',') -ceq 'disk,efi-file,dvd,network') 'Disk selection lost the UEFI file entry.'
$read = Edit 'bootFirst' 'image'
Check ($read.bootFirst -ceq 'image' -and ($order.FirmwarePath -join ',') -ceq 'dvd,disk,efi-file,network') 'Image selection lost the UEFI file entry.'
