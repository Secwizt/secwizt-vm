function BootEntries($v) {
    if ($v.Generation -ne 2) { return }
    $firmware = Get-VMFirmware -VMName $v.Name -ErrorAction Stop
    if ($firmware.VMId -ne $v.Id) { Refuse 'The firmware registration changed.' }
    $firmware.BootOrder
}
function BootMode($source) {
    if ($null -ne $source -and [string]$source.BootType -eq 'File') { return 'system' }
    if ($null -ne $source -and $null -ne $source.Device) {
        switch ($source.Device.GetType().Name) {
            'HardDiskDrive' { return 'disk' }
            'DvdDrive' { return 'image' }
        }
    }
    return 'other'
}
function MountedImage($drives) {
    if ($drives.Count -eq 1 -and ![string]::IsNullOrWhiteSpace([string]$drives[0].Path)) {
        return [string]$drives[0].Path
    }
    return $null
}
function StorageInfo($v, [ref]$dvdList) {
    $diskDrives = @(Get-VMHardDiskDrive -VM $v)
    $drives = @(Get-VMDvdDrive -VM $v)
    if ($null -ne $dvdList) { $dvdList.Value = $drives }
    $disks = @(foreach ($d in $diskDrives) {
        if (!$d.Path) { Refuse 'A physical disk has no virtual disk size to report.' }
        $path = ExactPath $d.Path
        $info = Get-VHD -Path $path
        $bytes = [long]0
        $part = $info
        $seen = @{}
        while ($part) {
            $file = ExactPath $part.Path
            if ($seen.ContainsKey($file)) { Refuse 'The disk chain could not be measured.' }
            $seen[$file] = $true
            $bytes += [long]$part.FileSize
            $part = if ($part.ParentPath) { Get-VHD -Path (ExactPath $part.ParentPath) } else { $null }
        }
        @{ path=$path; maximumBytes=[long]$info.Size; hostBytes=$bytes }
    })
    $order = @(BootEntries $v)
    $mode = BootMode $order[0]
    $description = $null
    if ($mode -eq 'system') { $description = ([string]$order[0].Description).Trim() }
    $iso = MountedImage $drives
    $off = $v.State.ToString() -eq 'Off'
    $running = $v.State.ToString() -eq 'Running'
    $media = ($off -or ($running -and ($drives.Count -eq 1 -or $v.Generation -eq 2))) -and $drives.Count -le 1
    $boot = $off -and $v.Generation -eq 2 -and $drives.Count -le 1 -and $diskDrives.Count -le 1
    return @{disks=$disks; isoPath=$iso; bootFirst=$mode; bootDescription=$description; canEditMedia=$media; canEditBoot=$boot;
        mediaReason='Media changes require an off or running machine with at most one virtual DVD drive.'; bootReason='Boot order changes require an off generation 2 machine with at most one disk and one DVD drive.'}
}
function Dispatch($p) {
    if ($p.op -eq 'capacity') {
        $dir = Get-Item -LiteralPath (ExactPath $p.path)
        Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
public static class SvmLibraryVolume {
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    private static extern bool GetDiskFreeSpaceEx(string directory, out ulong available, out ulong total, out ulong free);
    public static ulong Available(string directory) {
        ulong available, total, free;
        if (!GetDiskFreeSpaceEx(directory, out available, out total, out free))
            throw new Win32Exception(Marshal.GetLastWin32Error());
        return available;
    }
}
'@
        $free = [SvmLibraryVolume]::Available($dir.FullName)
        $ram = (Get-CimInstance Win32_OperatingSystem).FreePhysicalMemory
        $commands = @(Get-Command -Name Set-VMKeyProtector,Enable-VMTPM -ErrorAction SilentlyContinue)
        return @{freeBytes=$free; freeRamGb=[long][Math]::Floor($ram / 1MB); tpmCommands=($commands.Count -eq 2)}
    }
    $v = OwnedVM $p
    if ($p.op -eq 'storage') { return StorageInfo $v }
    $dvd = @()
    $read = StorageInfo $v ([ref]$dvd)
    if ($p.op -eq 'confirmStorage') {
        if ($p.edit -eq 'bootFirst') {
            $confirmed = $read.bootFirst -ceq $p.value
        } elseif ($p.edit -eq 'isoPath' -and $null -eq $p.value) {
            $confirmed = $dvd.Count -le 1 -and [string]::IsNullOrWhiteSpace([string]$read.isoPath)
        } elseif ($p.edit -eq 'isoPath') {
            $confirmed = $dvd.Count -eq 1 -and $null -ne $read.isoPath -and
                [string]::Equals((ExactPath $read.isoPath),(ExactPath $p.value),[StringComparison]::OrdinalIgnoreCase)
        } else { Refuse 'Choose one storage change.' }
        return @{ confirmed=$confirmed; storage=$read }
    }
    if ($p.op -ne 'setStorage') { Refuse 'Unknown storage operation.' }
    if ($p.edit -eq 'isoPath') {
        if (!$read.canEditMedia) { Refuse $read.mediaReason }
        $iso = $null
        if ($p.value) {
            $iso = ExactPath $p.value
            if ([IO.Path]::GetExtension($iso) -ine '.iso' -or !(Test-Path -LiteralPath $iso -PathType Leaf)) { Refuse 'Choose an existing local installer image.' }
        }
        if ($dvd.Count -and ($iso -or (MountedImage $dvd))) {
            Set-VMDvdDrive -VMDvdDrive $dvd[0] -Path $iso -ErrorAction Stop
        } elseif (!$dvd.Count -and $iso) { Add-VMDvdDrive -VM $v -Path $iso -ErrorAction Stop }
    } elseif ($p.edit -eq 'bootFirst') {
        if (!$read.canEditBoot) { Refuse $read.bootReason }
        if ($p.value -eq 'disk') { $target = @(Get-VMHardDiskDrive -VM $v) }
        elseif ($p.value -eq 'image' -and $read.isoPath) { $target = $dvd }
        else { Refuse 'Attach an installer image before choosing image first.' }
        if ($target.Count -ne 1) { Refuse 'The selected boot device is unavailable.' }
        $order = @(BootEntries $v)
        if ((BootMode $order[0]) -ne $p.value) {
            # BootOrder accepts both firmware entries and attached drives. Keep every other entry in order.
            $index = -1
            for ($i=0; $i -lt $order.Count; $i++) {
                if ((BootMode $order[$i]) -eq $p.value) { $index=$i; break }
            }
            $first = if ($index -ge 0) { $order[$index] } else { $target[0] }
            $next = @($first; for ($i=0; $i -lt $order.Count; $i++) { if ($i -ne $index) { $order[$i] } })
            Set-VMFirmware -VM $v -BootOrder $next -ErrorAction Stop
        }
    } else { Refuse 'Choose one storage change.' }
    # The caller verifies this mutation with a fresh Hyper-V PowerShell process.
    return $true
}
