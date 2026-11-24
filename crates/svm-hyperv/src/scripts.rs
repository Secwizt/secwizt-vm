// Compile-time fragments keep each fixed UTF-16 command within the Windows process command-line limit.
macro_rules! command_start { () => { r#"& {
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$WarningPreference = 'SilentlyContinue'
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
function Refuse([string]$message) { throw ('SVM_REFUSED: ' + $message) }
function AccessDenied($record) {
    return ($record.CategoryInfo.Category -in @('PermissionDenied','SecurityError') -or
        $record.Exception -is [UnauthorizedAccessException] -or
        $record.Exception.Message -match '(?i)access (is )?denied|required permission|privilege is not held|requires elevation')
}
function CheckId([string]$id) {
    if ($id -cnotmatch '^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,79}$') { Refuse 'Invalid project ID.' }
}
"# }; }
macro_rules! owned_vm { () => { concat!(command_start!(), r#"function Machines([string]$name) { Get-VM | Where-Object { $_.Name -ieq $name } }
function OwnedVM($p) {
    CheckId $p.id
    $name = 'svm-' + $p.id
    $items = @(Machines $name)
    if ($items.Count -eq 0) { throw ('SVM_MISSING: ' + $p.id) }
    if ($items.Count -ne 1 -or $items[0].Name -cne $name -or $items[0].Notes -cne ('secwiz-vm:' + $p.id)) {
        Refuse 'The machine name and ownership marker do not identify one project machine.'
    }
    if ($p.guid -and $items[0].Id.ToString() -ine $p.guid) { Refuse 'The machine registration changed during this request.' }
    return $items[0]
}
"#) }; }
macro_rules! common { () => { concat!(owned_vm!(), r#"function Switches([string]$name) { Get-VMSwitch | Where-Object { $_.Name -ieq $name } }
function IsOurSwitch($s) {
    if ($s.Name -cnotmatch '^SVM-([a-zA-Z0-9][a-zA-Z0-9_.-]{0,79})$') { return $false }
    return ($s.SwitchType.ToString() -eq 'Internal' -and $s.Notes -ceq ('secwiz-switch:' + $s.Name.Substring(4)))
}
function ProjectSwitch([string]$id, [bool]$create) {
    CheckId $id
    $name = 'SVM-' + $id
    $items = @(Switches $name)
    if ($items.Count -eq 0) {
        if (!$create) { throw ('SVM_MISSING: ' + $name) }
        return New-VMSwitch -Name $name -SwitchType Internal -Notes ('secwiz-switch:' + $id)
    }
    if ($items.Count -ne 1 -or $items[0].Name -cne $name -or !(IsOurSwitch $items[0])) {
        Refuse 'An existing switch lacks the expected name, internal type or project marker.'
    }
    return $items[0]
}
"#) }; }
macro_rules! paths { () => { r#"function ExactPath([string]$name) {
    # Canonical paths returned by Rust on Windows can carry a verbatim local drive prefix.
    if ($name.StartsWith('\\?\', [StringComparison]::Ordinal)) { $name = $name.Substring(4) }
    if ($name -notmatch '^[a-zA-Z]:[\\/]') { Refuse 'Choose an absolute local drive path.' }
    $path = [IO.Path]::GetFullPath($name)
    for ($part = $path; $part; $part = [IO.Path]::GetDirectoryName($part)) {
        if (Test-Path -LiteralPath $part) {
            if ((Get-Item -LiteralPath $part -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) {
                Refuse 'A managed path crosses a link or junction.'
            }
        }
    }
    return $path.TrimEnd('\')
}
function IsBelow([string]$path, [string]$root) {
    return $path.StartsWith(($root.TrimEnd('\') + '\'), [StringComparison]::OrdinalIgnoreCase)
}
function Bundle($p) {
    $folder = ExactPath $p.bundle
    if (!(Test-Path -LiteralPath $folder -PathType Container) -or [IO.Path]::GetExtension($folder) -ine '.swvm') {
        Refuse 'An existing machine bundle folder is required.'
    }
    $record = ExactPath ([IO.Path]::Combine($folder,'vm.json'))
    if (!(Test-Path -LiteralPath $record -PathType Leaf)) { Refuse 'The bundle has no VM library definition.' }
    $definition = [IO.File]::ReadAllText($record) | ConvertFrom-Json
    if ($definition.id -cne $p.id) { Refuse 'The library bundle belongs to a different machine.' }
    return $folder
}
"# }; }
macro_rules! finish { () => { r#"$mutex = $null
$held = $false
try {
    $env:PSModulePath = [IO.Path]::Combine($PSHOME,'Modules')
    Import-Module Hyper-V -ErrorAction Stop
    $p = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($env:SVM_PARAMS)) | ConvertFrom-Json
    $mutex = [Threading.Mutex]::new($false,'Global\SecwizVM-HyperV-Management')
    try { $held = $mutex.WaitOne(10000) } catch [Threading.AbandonedMutexException] { $held = $true }
    if (!$held) { throw 'Another project management operation is still in progress.' }
    $result = Dispatch $p
    [Console]::Out.WriteLine((ConvertTo-Json -InputObject $result -Compress -Depth 6))
} catch {
    $message = $_.Exception.Message
    if (AccessDenied $_) {
        if (!$message.StartsWith('SVM_TPM_PERMISSION:')) { $message = 'SVM_PERMISSION: ' + $message }
    }
    [Console]::Error.WriteLine((@{ error=$message; id=$_.FullyQualifiedErrorId } | ConvertTo-Json -Compress))
    exit 3
} finally {
    if ($held) { $mutex.ReleaseMutex() }
    if ($mutex) { $mutex.Dispose() }
}
}

"# }; }

macro_rules! external { () => { r#"function Bridge($p) {
    $b=$p.bridge
    if (!$b.switchGuid) { Refuse 'Verify the bridged network in Networks first.' }
    $a=@(Get-NetAdapter -Physical | Where-Object { $_.InterfaceGuid -eq [guid]$b.adapterId -and [int]$_.InterfaceType -eq 6 })
    $s=Get-VMSwitch -Id ([guid]$b.switchGuid)
    if ($a.Count -ne 1 -or $s.SwitchType -ne 'External' -or $s.EmbeddedTeamingEnabled -or !$s.AllowManagementOS -or @($s.NetAdapterInterfaceGuid) -notcontains [guid]$b.adapterId -or ($b.owned -and $s.Notes -cne ('secwiz-bridge:'+$p.networkId))) { Refuse 'The recorded shared Ethernet switch changed.' }
    return $s
}
"# }; }

macro_rules! boot_stamp { () => { r#"function StateStamp($system) {
    if ($null -ne $system.TimeOfLastStateChange) { return $system.TimeOfLastStateChange.ToUniversalTime().Ticks.ToString() }
    return 'none'
}
"# }; }

pub(crate) const LINKED_DISK: &str = concat!(common!(), paths!(), include_str!("linked_disk.ps1"), finish!());
// Hyper-V grants a VM's own account access to its attached disk only. A differencing disk we created
// also needs read access to each parent (a template or the throwaway base), or the guest can't power on.
// Both commands use the same ordered list of parent disks supplied by the library.
#[cfg(all(test, windows))]
pub(crate) const FIXTURE_PATHS: &str = paths!();

pub(crate) const THROWAWAY: &str = concat!(owned_vm!(), paths!(), include_str!("chain_access.ps1"), include_str!("throwaway.ps1"), finish!());

pub(crate) const DEFINITION: &str = concat!(common!(), paths!(), external!(), boot_stamp!(), r#"function Media([string]$value, [string]$folder, [string]$extension) {
    $path = if ([IO.Path]::IsPathRooted($value)) { ExactPath $value } else { ExactPath ([IO.Path]::Combine($folder,$value)) }
    if ([IO.Path]::GetExtension($path) -ine $extension -or !(Test-Path -LiteralPath $path -PathType Leaf)) { Refuse 'The requested media file is unavailable or has the wrong format.' }
    if ($extension -eq '.vhdx' -and !(IsBelow $path $folder)) { Refuse 'The writable disk must be inside the machine bundle.' }
    return $path
}
function DefineMachine($p) {
    CheckId $p.id
    $name = 'svm-' + $p.id
    if (@(Machines $name).Count) { Refuse 'A registration with this machine name already exists.' }
    $folder = Bundle $p
    $runtime = ExactPath ([IO.Path]::Combine($folder,'hyperv'))
    $disk = $null
    $iso = $null
    if ($p.diskPath) { $disk = Media $p.diskPath $folder '.vhdx' }
    if ($p.isoPath) { $iso = Media $p.isoPath $folder '.iso' }
    if ($p.diskGb) {
        if ($disk) { Refuse 'Choose an existing disk or a new disk size.' }
        $disk = ExactPath ([IO.Path]::Combine($folder,'system.vhdx'))
        if (Test-Path -LiteralPath $disk) { Refuse 'The new disk path is already occupied.' }
    }
    if ($p.networkMode -eq 'NAT') {
        $switches = @(Switches 'Default Switch')
        if ($switches.Count -ne 1) { Refuse 'The Windows Default Switch is unavailable.' }
        $s = $switches[0]
    } elseif ($p.networkMode -eq 'Bridged') { $s = Bridge $p } else {
        if ($p.networkMode -notin @('Routed','Host-only','Isolated segment','Link-local')) { Refuse 'This network mode is unavailable in this driver.' }
        $s = ProjectSwitch $p.networkId $false
    }
    $nv = @{ Name=$name; Generation=2; Path=$runtime; MemoryStartupBytes=([int64]$p.ramGb * 1GB); SwitchName=$s.Name; NoVHD=$true }
    $null = [IO.Directory]::CreateDirectory($runtime)
    $v = New-VM @nv
    $marked = $false
    $createdDisk = $false
    $blank = $null
    try {
        Set-VM -VM $v -Notes ('secwiz-vm:' + $p.id)
        $marked = $true
        $p | Add-Member -NotePropertyName guid -NotePropertyValue ($v.Id.ToString())
        $v = OwnedVM $p
        Set-VM -VM $v -AutomaticCheckpointsEnabled $false -SnapshotFileLocation $runtime -SmartPagingFilePath $runtime
        Set-VMMemory -VM $v -DynamicMemoryEnabled $false -StartupBytes ([int64]$p.ramGb * 1GB)
        Set-VMProcessor -VM $v -Count $p.vcpu
        Get-VMNetworkAdapter -VM $v | Set-VMNetworkAdapter -StaticMacAddress $p.mac
        if ($p.secureBoot) {
            Set-VMFirmware -VM $v -EnableSecureBoot On -SecureBootTemplate $p.template
        } else { Set-VMFirmware -VM $v -EnableSecureBoot Off }
        if ($p.tpm) {
            try {
                Set-VMKeyProtector -VM $v -NewLocalKeyProtector
                Enable-VMTPM -VM $v
            } catch {
                if (AccessDenied $_) { throw ('SVM_TPM_PERMISSION: ' + $_.Exception.Message) }
                throw
            }
        }
        if ($p.diskGb) {
            $null = New-VHD -Path $disk -Dynamic -SizeBytes ([int64]$p.diskGb * 1GB)
            $createdDisk = $true
            if ($p.windowsInstaller) {
                # Fingerprint before attachment: the guest has never been able to write this file.
                try { $blank = @{sha256=(Get-FileHash -LiteralPath $disk -Algorithm SHA256).Hash;length=(Get-Item -LiteralPath $disk).Length;guid=$v.Id.ToString()} }
                catch { $blank = $null }
            }
        }
        if ($disk) { Add-VMHardDiskDrive -VM $v -Path $disk }
        if ($p.linkedParent) {
            $v = OwnedVM $p
            $drives = @(Get-VMHardDiskDrive -VM $v -ErrorAction Stop)
            if ($v.State.ToString() -ne 'Off' -or $drives.Count -ne 1 -or !$drives[0].Path -or (ExactPath $drives[0].Path) -ine $disk) {
                Refuse 'Hyper-V could not confirm the attached disk of the stopped clone.'
            }
            $leaf = Get-VHD -Path $disk -ErrorAction Stop
            if ($leaf.VhdFormat -ne 'VHDX' -or $leaf.VhdType -ne 'Differencing' -or !$leaf.ParentPath -or
                (ExactPath $leaf.ParentPath) -ine (ExactPath $p.linkedParent)) {
                Refuse 'The clone disk does not point to the verified template VHDX.'
            }
        }
        if ($iso) {
            $dvd = Add-VMDvdDrive -VM $v -Path $iso -PassThru
            if ($p.bootFirst -ne 'disk') { Set-VMFirmware -VM $v -FirstBootDevice $dvd }
        }
        if ($disk -and $p.bootFirst -eq 'disk') { Set-VMFirmware -VM $v -FirstBootDevice (@(Get-VMHardDiskDrive -VM $v)[0]) }
        if ($blank) {
            try {
                $system = Get-CimInstance -Namespace 'root\virtualization\v2' -ClassName Msvm_ComputerSystem -Filter ("Name='" + $v.Id.ToString('D') + "'") -OperationTimeoutSec 3
                if ($system.EnabledState -eq 3) {
                    $blank.stateStamp = StateStamp $system
                    $receipt = ExactPath ([IO.Path]::Combine($folder,'installer-first-boot.json'))
                    $stream = [IO.File]::Open($receipt,[IO.FileMode]::CreateNew)
                    try { $bytes=[Text.Encoding]::UTF8.GetBytes(($blank | ConvertTo-Json -Compress)); $stream.Write($bytes,0,$bytes.Length); $stream.Flush($true) } finally { $stream.Dispose() }
                }
            } catch { $blank = $null } # Normal starts remain available when the first-boot evidence cannot be saved.
        }
        return @{ guid=$v.Id.ToString() }
    } catch {
        $failure = $_
        if ($marked) {
            $owned = OwnedVM $p
            Remove-VM -VM $owned -Force
            if ($createdDisk) { Remove-Item -LiteralPath $disk -ErrorAction Stop }
        }
        throw $failure
    }
}
function Dispatch($p) { return DefineMachine $p }
"#, finish!());

pub(crate) const MANAGEMENT: &str = concat!(common!(), paths!(), include_str!("chain_access.ps1"), r#"function HasOurLink($v) {
    $links = @(Get-VMNetworkAdapter -VM $v)
    $ours = @(Get-VMSwitch | Where-Object { IsOurSwitch $_ })
    foreach ($nic in $links) {
        foreach ($s in $ours) { if ($s.Id -eq $nic.SwitchId) { return $true } }
    }
    return $false
}
function OwnedSnapshot($v, [string]$id) {
    $found = @(Get-VMSnapshot -VM $v | Where-Object { $_.Id.ToString() -ieq $id })
    if ($found.Count -ne 1) { throw ('SVM_MISSING: ' + $id) }
    return $found[0]
}
function StopOwned($p,$v) {
    $state = $v.State.ToString()
    if ($state -eq 'Off') { return }
    if ($state -eq 'Paused') {
        Resume-VM -VM $v -Confirm:$false
        $v = OwnedVM $p
        $state = $v.State.ToString()
    }
    if ($state -notin @('Running','Saved','FastSaved','Hibernated')) {
        Refuse 'Wait for the machine to reach a stable state before powering it off.'
    }
    $v = OwnedVM $p
    if ($v.State.ToString() -ne 'Off') { Stop-VM -VM $v -TurnOff -Confirm:$false }
}
function Thumbnail($v) {
    if ($v.State.ToString() -notin @('Running','Paused')) { Refuse 'The machine has no active display.' }
    $ns = 'root\virtualization\v2'
    $systems = @(Get-CimInstance -Namespace $ns -ClassName Msvm_ComputerSystem | Where-Object { $_.Name -ieq $v.Id.ToString() })
    if ($systems.Count -ne 1) { Refuse 'The current display could not be identified.' }
    $settings = @(Get-CimAssociatedInstance -InputObject $systems[0] -ResultClassName Msvm_VirtualSystemSettingData | Where-Object { $_.VirtualSystemType -eq 'Microsoft:Hyper-V:System:Realized' })
    if ($settings.Count -ne 1) { Refuse 'The current display settings are unavailable.' }
    $svc = Get-CimInstance -Namespace $ns -ClassName Msvm_VirtualSystemManagementService
    $argsMap = @{ TargetSystem=$settings[0]; WidthPixels=[uint16]320; HeightPixels=[uint16]240 }
    $image = Invoke-CimMethod -InputObject $svc -MethodName GetVirtualSystemThumbnailImage -Arguments $argsMap
    if ($image.ReturnValue -ne 0) { return @{ returnValue=[int]$image.ReturnValue } }
    return @{ returnValue=0; width=320; height=240; pixels=[BitConverter]::ToString($image.ImageData).Replace('-','') }
}
function Dispatch($p) {
    switch -CaseSensitive ($p.op) {
        'ensureSwitch' {
            CheckId $p.networkId
            $existing = @(Switches ('SVM-' + $p.networkId))
            $s = ProjectSwitch $p.networkId $true
            return @{ created=($existing.Count -eq 0); guid=$s.Id.ToString() }
        }
        'removeSwitch' {
            $s = ProjectSwitch $p.networkId $false
            if ($p.guid -and $s.Id.ToString() -ine $p.guid) { Refuse 'The switch registration changed.' }
            $attached = @(Get-VMNetworkAdapter -All | Where-Object { $_.SwitchId -eq $s.Id -and (!$_.IsManagementOs -or $_.Name -cne $s.Name) })
            if ($attached.Count) { Refuse 'Disconnect attached machines and extra host adapters before removing the switch.' }
            Remove-VMSwitch -VMSwitch $s -Force
            return @{ ok=$true }
        }
        'listSwitches' {
            return Get-VMSwitch | Where-Object { IsOurSwitch $_ } | Select-Object Name,Id,SwitchType,Notes
        }
        'defaultSwitchInfo' {
            $items = @(Switches 'Default Switch')
            if ($items.Count -ne 1) { Refuse 'The Windows Default Switch is unavailable.' }
            $s = $items[0]
            return @{ id=$s.Id.ToString(); name=$s.Name; type=$s.SwitchType.ToString(); notes=$s.Notes; management=$s.AllowManagementOS }
        }
    }
    $v = OwnedVM $p
    switch -CaseSensitive ($p.op) {
        'inspect' {
            $linked = $false
            $external = $null
            if ($p.probeLink) {
                $linked = HasOurLink $v
                $nics = @(Get-VMNetworkAdapter -VM $v)
                if ($nics.Count -eq 1 -and $nics[0].SwitchId) {
                    $sw = Get-VMSwitch -Id $nics[0].SwitchId -ErrorAction SilentlyContinue
                    if ($sw -and $sw.SwitchType -eq 'External' -and $sw.AllowManagementOS) { $external = $sw.Id.ToString() }
                }
            }
            $ips=@()
            if ($p.addressMac -and $v.State.ToString() -eq 'Running') {
                try {
                    $nic=@(Get-VMNetworkAdapter -VM $v -ErrorAction Stop | Where-Object { $_.MacAddress -ieq $p.addressMac -and $_.SwitchId })
                    if ($nic.Count -eq 1) { $ips=@($nic[0].IPAddresses | Where-Object { $_ } | ForEach-Object { [string]$_ }) }
                } catch { $ips=@() }
            }
            return @{ name=$v.Name; notes=$v.Notes; guid=$v.Id.ToString(); state=[int]$v.State; stateName=$v.State.ToString(); ownLink=$linked; externalGuid=$external; addresses=$ips }
        }
        'start' { GrantChainAccess $v $p; Start-VM -VM $v }
        'throwawayDisk' {
            $d = @(Get-VMHardDiskDrive -VM $v)
            if ($d.Count -ne 1 -or (ExactPath $d[0].Path) -ine [IO.Path]::Combine((Bundle $p),'system.vhdx')) { Refuse 'Throwaway mode needs the bundle system.vhdx as the only disk.' }
            return @{ok=$true}
        }
        'stop' { StopOwned $p $v }
        'pause' { Suspend-VM -VM $v -Confirm:$false }
        'resume' { Resume-VM -VM $v -Confirm:$false }
        # A state read is satisfied directly by the verified inspection.
        'thumbnail' { return Thumbnail $v }
        'revert' { Restore-VMSnapshot -VMSnapshot (OwnedSnapshot $v $p.snapshotId) -Confirm:$false }
        'deleteSnapshot' { Remove-VMSnapshot -VMSnapshot (OwnedSnapshot $v $p.snapshotId) -Confirm:$false }
        default { Refuse 'Unknown management operation.' }
    }
    return @{ ok=$true }
}
"#, finish!());

pub(crate) const TRASH: &str = concat!(common!(), paths!(), r#"function Located($p,$folder) {
    $items = @(Machines ('svm-' + $p.id))
    if ($items.Count -eq 0) { return $false }
    $v = OwnedVM $p
    $location = if ($v.ConfigurationLocation) { $v.ConfigurationLocation } else { $v.Path }
    if (!(IsBelow (ExactPath $location) $folder)) { Refuse 'A registration with this identity lives in another folder.' }
    return $true
}
function Detached($p,$folder) {
    if (@(Machines ('svm-' + $p.id)).Count) { Refuse 'A machine with this identity is still registered.' }
    foreach ($other in @(Get-VM -ErrorAction Stop)) {
        foreach ($path in @($other.Path,$other.ConfigurationLocation,$other.SnapshotFileLocation,$other.SmartPagingFilePath)) {
            if ($path -and ((ExactPath $path) -ieq $folder -or (IsBelow (ExactPath $path) $folder))) {
                Refuse 'A registered machine still uses this folder.'
            }
        }
        $attached = @(Get-VMHardDiskDrive -VM $other -ErrorAction Stop)
        $dvds = @(Get-VMDvdDrive -VM $other -ErrorAction Stop)
        foreach ($snap in @(Get-VMSnapshot -VM $other -ErrorAction Stop)) {
            $attached += @(Get-VMHardDiskDrive -VMSnapshot $snap -ErrorAction Stop)
            $dvds += @(Get-VMDvdDrive -VMSnapshot $snap -ErrorAction Stop)
        }
        foreach ($dvd in $dvds) {
            if ($dvd.Path -and (IsBelow (ExactPath $dvd.Path) $folder)) { Refuse 'A registered DVD drive still uses this folder.' }
        }
        $seen = @{}
        foreach ($drive in $attached) {
            $path = $drive.Path
            while ($path) {
                $path = ExactPath $path
                if ($seen.ContainsKey($path)) { break }
                if (IsBelow $path $folder) { Refuse 'A registered disk or checkpoint still uses this folder.' }
                $seen[$path] = $true
                $path = (Get-VHD -Path $path -ErrorAction Stop).ParentPath
            }
        }
    }
}
function Dispatch($p) {
    CheckId $p.id
    $folder = Bundle $p
    if ($p.op -ceq 'trashDetached') { Detached $p $folder; return @{ok=$true} }
    if ($p.op -ceq 'restoreRegistration') { return (Located $p $folder) }
    if ($p.op -cne 'importRetained') { Refuse 'Unknown trash operation.' }
    if (Located $p $folder) { Refuse 'This machine is already registered.' }
    if ($p.retained -cnotmatch '^retained/[a-z0-9][a-z0-9._-]{0,79}$') { Refuse 'Invalid export location.' }
    $archive = ExactPath ([IO.Path]::Combine($folder,$p.retained))
    if (!(IsBelow $archive $folder)) { Refuse 'The export must be inside this machine bundle.' }
    $exportRoot = ExactPath ([IO.Path]::Combine($archive,('svm-'+$p.id)))
    $exported = ExactPath ([IO.Path]::Combine($exportRoot,'Virtual Machines'))
    $configs = @(Get-ChildItem -LiteralPath $exported -File -Filter '*.vmcx' -ErrorAction Stop)
    if ($configs.Count -ne 1) { Refuse 'The retained export must contain one machine configuration.' }
    $config = ExactPath $configs[0].FullName
    # Each retry uses a fresh destination, preserving both the export and original disks.
    $work = ExactPath ([IO.Path]::Combine($folder,('imported-'+[guid]::NewGuid().ToString('N'))))
    $disks = [IO.Path]::Combine($work,'Disks')
    $argsForImport = @{Path=$config; Copy=$true; VirtualMachinePath=$work; SnapshotFilePath=$work; SmartPagingFilePath=$work; VhdDestinationPath=$disks}
    $sourceDisks = ExactPath ([IO.Path]::Combine($exportRoot,'Virtual Hard Disks'))
    if (Test-Path -LiteralPath $sourceDisks -PathType Container) { $argsForImport.VhdSourcePath = $sourceDisks }
    $report = Compare-VM @argsForImport -ErrorAction Stop
    if ($report.VM.Name -cne ('svm-'+$p.id) -or $report.VM.Notes -cne ('secwiz-vm:'+$p.id)) { Refuse 'The retained export does not belong to this machine.' }
    if (@($report.Incompatibilities | Where-Object { $_ }).Count) { Refuse 'Hyper-V found an incompatible export. The disks and checkpoint history were kept.' }
    $v = Import-VM -CompatibilityReport $report -ErrorAction Stop
    if ($null -eq $v -or !(Located $p $folder)) { Refuse 'Hyper-V could not verify the restored registration.' }
    return @{ok=$true}
}
"#, finish!());

pub(crate) const SERVICE: &str = concat!(common!(), paths!(), external!(), r#"function RemovePlan($p,$v) {
    $folder = Bundle $p
    $location = if ($v.ConfigurationLocation) { $v.ConfigurationLocation } else { $v.Path }
    if (!(IsBelow (ExactPath $location) $folder)) { Refuse 'The registration is outside the supplied bundle.' }
    $state = $v.State.ToString()
    if ($state -notin @('Off','Saved','FastSaved','Hibernated')) { Refuse 'Removal requires a confirmed off or saved machine.' }
    try {
        $snaps = @(Get-VMSnapshot -VM $v -ErrorAction Stop | ForEach-Object { $_.Id.ToString() } | Sort-Object)
        $sec = Get-VMSecurity -VM $v -ErrorAction Stop
        if ($null -eq $sec -or $null -eq $sec.TpmEnabled) { throw 'No virtual TPM result.' }
    } catch { Refuse 'Hyper-V could not verify the checkpoint history and virtual TPM; the bundle was kept.' }
    $tpm = [bool]$sec.TpmEnabled
    # Keep the imported configuration.
    $imported = (ExactPath $location).Substring($folder.Length + 1) -like 'imported-*'
    return @{ required=($state -ne 'Off' -or $tpm -or $snaps.Count -gt 0 -or $imported); guid=$v.Id.ToString(); stamp=($state+'|'+$tpm+'|'+($snaps -join ',')) }
}
function RemoveOwned($p,$v) {
    $plan = RemovePlan $p $v
    if ($p.stamp -and $p.stamp -cne $plan.stamp) { Refuse 'The state to preserve changed; request removal again.' }
    if ($plan.required -and !$p.keepCopy) { Refuse 'A retained copy is required before this registration can be removed.' }
    $folder = Bundle $p
    $rel = $null; $size = $null
    if ($p.keepCopy) {
        $rel = 'retained/' + [guid]::NewGuid().ToString('N')
        $archive = ExactPath ([IO.Path]::Combine($folder,$rel))
        $null = [IO.Directory]::CreateDirectory($archive)
        Export-VM -VM $v -Path $archive -ErrorAction Stop
        $size = [long]0
        $files = @(Get-ChildItem -LiteralPath $archive -Recurse -File -Force -ErrorAction Stop)
        foreach ($file in $files) { $size += $file.Length }
        if ($size -le 0) { Refuse 'Hyper-V returned an empty export; the registration was kept.' }
    }
    $v = OwnedVM $p
    $now = RemovePlan $p $v
    if ($plan.stamp -cne $now.stamp) { Refuse 'The machine changed during export; the registration was kept.' }
    Remove-VM -VM $v -Force
    if (@(Machines ('svm-'+$p.id)).Count) { Refuse 'Hyper-V could not confirm that the registration was removed.' }
    $receipt = @{ id=$p.id; retained=$rel; bytes=$size }
    $marker = ExactPath ([IO.Path]::Combine($folder,'removal-complete.json'))
    $temp = ExactPath ([IO.Path]::Combine($folder,[guid]::NewGuid().ToString('N')+'.tmp'))
    $bytes = [Text.Encoding]::UTF8.GetBytes(($receipt | ConvertTo-Json -Compress))
    $stream = [IO.File]::Open($temp,[IO.FileMode]::CreateNew)
    try {
        $stream.Write($bytes,0,$bytes.Length)
        $stream.Flush($true)
    } finally { $stream.Dispose() }
    if ([IO.File]::Exists($marker)) { [IO.File]::Replace($temp,$marker,$null) } else { [IO.File]::Move($temp,$marker) }
    return $receipt
}
function CopyDisk($p,$v) {
    if ($v.State.ToString() -ne 'Off') { Refuse 'The source machine must be off to make an independent clone.' }
    if ((Get-VMSecurity -VM $v).TpmEnabled) { Refuse 'This engine cannot copy a sealed virtual TPM to a new machine identity.' }
    $source = Bundle $p
    CheckId $p.targetId
    if ($p.targetId -ieq $p.id) { Refuse 'A clone needs a new identity.' }
    $target = Bundle @{id=$p.targetId; bundle=$p.targetBundle}
    $disks = @(Get-VMHardDiskDrive -VM $v)
    if ($disks.Count -eq 0) { return @{ copied=$false } }
    if ($disks.Count -ne 1 -or !$disks[0].Path) { Refuse 'Only a single bundle-backed virtual disk can be cloned in this version.' }
    $sourceDisk = ExactPath $disks[0].Path
    $part = $sourceDisk
    $chain = @{}
    while ($part) {
        $part = ExactPath $part
        if (!(IsBelow $part $source) -or $chain.ContainsKey($part)) { Refuse 'The source disk chain must stay inside its own bundle.' }
        $chain[$part] = $true
        $part = (Get-VHD -Path $part).ParentPath
    }
    $disk = ExactPath ([IO.Path]::Combine($target,'system.vhdx'))
    if (Test-Path -LiteralPath $disk) { Refuse 'The clone disk path already exists.' }
    Convert-VHD -Path $sourceDisk -DestinationPath $disk -VHDType Dynamic -ErrorAction Stop
    return @{ copied=$true }
}
function Configure($p,$v) {
    if ($v.State.ToString() -ne 'Off') { Refuse 'The machine must be off to change its hardware.' }
    if (@(Get-VMSnapshot -VM $v).Count) { Refuse 'Remove checkpoints before changing hardware that they could restore.' }
    $nics = @(Get-VMNetworkAdapter -VM $v)
    if ($nics.Count -ne 1) { Refuse 'This configuration needs exactly one VM adapter.' }
    if ($p.networkMode -eq 'NAT') {
        $switches = @(Switches 'Default Switch')
        if ($switches.Count -ne 1) { Refuse 'The Windows Default Switch is unavailable.' }
        $s = $switches[0]
    } elseif ($p.networkMode -eq 'Bridged') { $s = Bridge $p } else { $s = ProjectSwitch $p.networkId $false }
    $beforeRam = $v.MemoryStartup
    $beforeCpu = $v.ProcessorCount
    try {
        Set-VM -VM $v -ProcessorCount ([int]$p.vcpu) -MemoryStartupBytes ([long]$p.ramGb * 1GB)
        Connect-VMNetworkAdapter -VMNetworkAdapter $nics[0] -SwitchName $s.Name
    } catch {
        Set-VM -VM (OwnedVM $p) -ProcessorCount $beforeCpu -MemoryStartupBytes $beforeRam
        throw
    }
    return @{ ok=$true }
}
function Dispatch($p) {
    $v = OwnedVM $p
    switch -CaseSensitive ($p.op) {
        'removePlan' { return RemovePlan $p $v }
        'remove' { return RemoveOwned $p $v }
        'copyDisk' { return CopyDisk $p $v }
        'configure' { return Configure $p $v }
        'snapshots' {
            $items = @(foreach ($item in Get-VMSnapshot -VM $v) {
                $parent = $null
                if ($item.ParentSnapshotId -and $item.ParentSnapshotId -ne [guid]::Empty) { $parent = $item.ParentSnapshotId.ToString() }
                $stored = $item.State.ToString()
                if ($stored -notin @('Off','Running','Paused','Saved','FastSaved','Hibernated')) { Refuse 'The checkpoint memory state is unknown.' }
                @{ id=$item.Id.ToString(); name=$item.Name; parent=$parent; withMemory=($stored -ne 'Off') }
            })
            return @{ items=$items }
        }
        default { Refuse 'Unknown machine configuration operation.' }
    }
}
"#, finish!());

pub(crate) const BRIDGE: &str = concat!(command_start!(), include_str!("bridge.ps1"), finish!());

pub(crate) const STORAGE: &str = concat!(common!(), paths!(), include_str!("storage.ps1"), finish!());
pub(crate) const INSTALLER_BOOT: &str = concat!(common!(), paths!(), boot_stamp!(), include_str!("installer_boot.ps1"), finish!());
pub(crate) const GUEST: &str = concat!(common!(), include_str!("guest.ps1"), finish!());
pub(crate) const FILE_GUEST_SERVICE: &str = concat!(common!(), include_str!("file_guest_service.ps1"), finish!());

pub(crate) const HOST: &str = concat!(common!(), r#"function Dispatch($p) {
    if ($p.op -ne 'host') { Refuse 'Unknown host operation.' }
    $cpu = @(Get-CimInstance Win32_Processor)
    $system = Get-CimInstance Win32_ComputerSystem
    $logical = [int]$system.NumberOfLogicalProcessors
    $physical = [int][Math]::Floor($system.TotalPhysicalMemory / 1GB)
    if ($logical -lt 1 -or $logical -gt 65535 -or $physical -lt 1) { Refuse 'The host processor or memory count is unavailable.' }
    # The API records are variable length. Read only the documented CPU-set fields, then advance by Size.
    Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;
public static class SvmCpuClasses {
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool GetSystemCpuSetInformation(IntPtr data, uint size, out uint length, IntPtr process, uint flags);
    public static int[] Read(int count) {
        uint size;
        GetSystemCpuSetInformation(IntPtr.Zero,0,out size,IntPtr.Zero,0);
        if (size==0 || size>16777216) throw new InvalidOperationException("No CPU set data.");
        IntPtr data=Marshal.AllocHGlobal(checked((int)size));
        try {
            uint length;
            if (!GetSystemCpuSetInformation(data,size,out length,IntPtr.Zero,0)) throw new Win32Exception();
            var result=new List<int>();
            for(int i=0;i<count;i++) result.Add(-1);
            for(int pos=0;pos<length;) {
                int record=Marshal.ReadInt32(data,pos);
                if (record<8 || record>length-pos) throw new InvalidOperationException("Invalid CPU set record.");
                if (Marshal.ReadInt32(data,pos+4)==0) {
                    if (record<20) throw new InvalidOperationException("Short CPU set.");
                    int group=(ushort)Marshal.ReadInt16(data,pos+12);
                    int id=group*64+Marshal.ReadByte(data,pos+14);
                    if (id>=count || result[id]!=-1) throw new InvalidOperationException("Unsupported CPU groups.");
                    result[id]=Marshal.ReadByte(data,pos+18);
                }
                pos+=record;
            }
            if (result.Contains(-1)) throw new InvalidOperationException("Incomplete CPU set.");
            return result.ToArray();
        } finally { Marshal.FreeHGlobal(data); }
    }
}
'@
    $classes = [SvmCpuClasses]::Read($logical)
    $kinds = @($classes | Sort-Object -Unique)
    $e = @(1,0); $pr = @(0,($logical-1)); $topology = 'uniform'
    if ($kinds.Count -gt 1) {
        $fast = $kinds[-1]
        $performance = @(for ($i=0;$i -lt $logical;$i++) { if ($classes[$i] -eq $fast) { $i } })
        $efficiency = @(for ($i=0;$i -lt $logical;$i++) { if ($classes[$i] -ne $fast) { $i } })
        if (($performance[-1]-$performance[0]+1 -ne $performance.Count) -or ($efficiency[-1]-$efficiency[0]+1 -ne $efficiency.Count)) {
            Refuse 'This host has a non-contiguous core topology that Host Guard cannot model.'
        }
        $pr = @($performance[0],$performance[-1]); $e = @($efficiency[0],$efficiency[-1]); $topology = 'hybrid'
    }
    $hostKey=try { ([guid](Get-ItemPropertyValue -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Cryptography' -Name MachineGuid -ErrorAction Stop)).ToString('D') } catch { $null }
    return @{ cpu=($cpu.Name -join ', '); hostKey=$hostKey; logical=$logical; pCores=$pr; eCores=$e; ramGb=$physical; topology=$topology }
}
"#, finish!());

pub(crate) const GUEST_COPY: &str = concat!(common!(), paths!(), include_str!("guest_copy.ps1"));
pub(crate) const GUEST_UPLOAD: &str = concat!(common!(), include_str!("guest_upload.ps1"));

pub(crate) const GUEST_EXEC: &str = concat!(common!(), include_str!("guest_exec.ps1"));

pub(crate) const CHECKPOINT: &str = concat!(common!(), r#"function Dispatch($p) {
    $v = OwnedVM $p
    switch -CaseSensitive ($p.op) {
        'snapshot' {
            $state = $v.State.ToString()
            if ($p.withMemory -and $state -notin @('Running','Paused')) { Refuse 'A memory checkpoint requires a running or paused machine.' }
            $before = $v.CheckpointType
            $kind = if ($p.withMemory) { 'Standard' } else { 'ProductionOnly' }
            $priorIds = @(Get-VMSnapshot -VM $v -ErrorAction Stop | ForEach-Object { $_.Id })
            try {
                Set-VM -VM $v -CheckpointType $kind -ErrorAction Stop
                try {
                    $snap = Checkpoint-VM -VM $v -SnapshotName $p.label -Passthru -ErrorAction Stop
                } catch {
                    $detail = $_.Exception.Message
                    if ($kind -ne 'ProductionOnly' -or $state -ne 'Running' -or (AccessDenied $_) -or
                        $detail -notmatch '(?i)production checkpoints? (?:cannot be created|could not be created|are not supported)|guest[^.\r\n]{0,110}(?:refused|could not be quiesced|not ready|did not respond)|0x800423(?:f2|f3|f4)') { throw }
                    $v = OwnedVM $p
                    if ($v.State.ToString() -ne 'Running' -or
                        @(Get-VMSnapshot -VM $v -ErrorAction Stop | Where-Object { $priorIds -notcontains $_.Id }).Count) { throw }
                    $kind = 'Standard'
                    Set-VM -VM $v -CheckpointType $kind -ErrorAction Stop
                    $snap = Checkpoint-VM -VM $v -SnapshotName $p.label -Passthru -ErrorAction Stop
                }
            } finally { Set-VM -VM (OwnedVM $p) -CheckpointType $before }
            if (!$snap.Id -or $snap.Id -eq [guid]::Empty) { Refuse 'Hyper-V did not confirm the new checkpoint identity.' }
            $parent = $null
            if ($snap.ParentSnapshotId -and $snap.ParentSnapshotId -ne [guid]::Empty) { $parent = $snap.ParentSnapshotId.ToString() }
            $stored = $snap.State.ToString()
            if ($stored -notin @('Off','Running','Paused','Saved','FastSaved','Hibernated')) { Refuse 'The checkpoint memory state is unknown.' }
            $label = if ($kind -eq 'Standard') { 'standard' } else { 'hyperv-production' }
            return @{ Id=$snap.Id.ToString(); Name=$snap.Name; ParentSnapshotId=$parent; SnapshotType=[int]$snap.SnapshotType; Created=$snap.CreationTime.ToUniversalTime().ToString("o"); WithMemory=($stored -ne 'Off'); Consistency=$label }
        }
        default { Refuse 'Unknown checkpoint operation.' }
    }
}
"#, finish!());
