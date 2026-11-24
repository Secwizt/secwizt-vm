function StandaloneDisk($description) {
    $v = OwnedVM $description
    $folder = Bundle $description
    $location = if ($v.ConfigurationLocation) { $v.ConfigurationLocation } else { $v.Path }
    if ($v.State.ToString() -ne 'Off' -or !$location -or !(IsBelow (ExactPath $location) $folder)) {
        Refuse 'A template requires its exact stopped Hyper-V registration inside its own bundle.'
    }
    if (@(Get-VMSnapshot -VM $v -ErrorAction Stop).Count) {
        Refuse 'Remove checkpoints from the template machine first.'
    }
    $security = Get-VMSecurity -VM $v -ErrorAction Stop
    if ($null -eq $security -or $null -eq $security.TpmEnabled -or $security.TpmEnabled) {
        Refuse 'A template requires a machine with a confirmed disabled virtual TPM.'
    }
    $drives = @(Get-VMHardDiskDrive -VM $v -ErrorAction Stop)
    if ($drives.Count -ne 1 -or !$drives[0].Path) {
        Refuse 'A Hyper-V template requires exactly one standalone VHDX.'
    }
    $disk = ExactPath $drives[0].Path
    if ([IO.Path]::GetDirectoryName($disk) -ine $folder -or [IO.Path]::GetExtension($disk) -ine '.vhdx' -or
        !(Test-Path -LiteralPath $disk -PathType Leaf)) {
        Refuse 'The template disk must be a VHDX directly inside its own bundle.'
    }
    $info = Get-VHD -Path $disk -ErrorAction Stop
    if (!$info.Path -or (ExactPath $info.Path) -ine $disk -or $info.VhdFormat -ne 'VHDX' -or
        $info.VhdType -notin @('Fixed','Dynamic') -or $info.ParentPath) {
        Refuse 'The template must use a standalone VHDX without a parent disk.'
    }
    return $disk
}

function Dispatch($p) {
    if ($p.op -ceq 'templateDisk') { return (StandaloneDisk $p) }
    if ($p.op -cne 'prepareLinkedDisk') { Refuse 'Unknown linked disk operation.' }
    CheckId $p.id
    if ($p.id -ieq $p.source.id -or @(Machines ('svm-' + $p.id)).Count) {
        Refuse 'A linked clone requires a fresh Hyper-V registration identity.'
    }
    $folder = Bundle $p
    $parent = StandaloneDisk $p.source
    if ((ExactPath $p.source.parent) -ine $parent) { Refuse 'The verified template disk changed.' }
    $parentFile = Get-Item -LiteralPath $parent -Force -ErrorAction Stop
    if (!($parentFile.Attributes -band [IO.FileAttributes]::ReadOnly)) {
        Refuse 'The template disk must be read-only before creating a linked clone.'
    }
    $disk = ExactPath ([IO.Path]::Combine($folder, 'system.vhdx'))
    if (Test-Path -LiteralPath $disk) { Refuse 'The linked clone disk path is already occupied.' }
    $null = New-VHD -Path $disk -ParentPath $parent -Differencing -ErrorAction Stop
    return @{ created=$true }
}
