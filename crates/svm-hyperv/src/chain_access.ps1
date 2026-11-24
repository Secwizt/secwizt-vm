function DiskReader($id) {
    [Security.Principal.NTAccount]::new('NT VIRTUAL MACHINE', "$id".ToUpperInvariant()).Translate([Security.Principal.SecurityIdentifier])
}
function GrantChainAccess($vm, $p) {
    if (!$p.parents) { return }
    $root = [IO.Path]::GetDirectoryName((Bundle $p))
    $sid = DiskReader $vm.Id
    $r = [Security.AccessControl.FileSystemRights]'Read, Synchronize'
    foreach ($d in @(Get-VMHardDiskDrive -VM $vm)) {
        $f = ExactPath $d.Path
        foreach ($expected in $p.parents) {
            $f = (Get-VHD -Path $f).ParentPath
            if (!$f) { break }
            $f = ExactPath $f
            if (!(IsBelow $f $root) -or !$f.Equals((ExactPath $expected), [StringComparison]::OrdinalIgnoreCase)) { break }
            $a = Get-Acl -LiteralPath $f
            if (!@($a.GetAccessRules(1, 1, [Security.Principal.SecurityIdentifier]) | ? { $_.IdentityReference -eq $sid -and $_.AccessControlType -eq 'Allow' -and ($_.FileSystemRights -band $r) -eq $r }).Count) {
                $a.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($sid, $r, 'Allow'))
                Set-Acl -LiteralPath $f -AclObject $a
            }
        }
    }
}
