$ErrorActionPreference = 'Stop'
$path = $env:SVM_SSH_DIRECTORY
$user = [Security.Principal.WindowsIdentity]::GetCurrent().User
function Verify-Private([string]$name, [bool]$directory) {
    $item = Get-Item -LiteralPath $name -Force
    if ($item.PSIsContainer -ne $directory -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { exit 4 }
    $acl = Get-Acl -LiteralPath $name
    if ($acl.GetOwner([Security.Principal.SecurityIdentifier]) -ne $user) { exit 4 }
    $rules = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))
    if ($rules.Count -ne 1 -or $rules[0].IdentityReference -ne $user -or
        $rules[0].AccessControlType -ne 'Allow' -or $rules[0].FileSystemRights -ne 'FullControl') { exit 4 }
    if (!$acl.AreAccessRulesProtected) { exit 4 }
}
for ($part = [IO.Path]::GetDirectoryName($path); $part; $part = [IO.Path]::GetDirectoryName($part)) {
    if ((Get-Item -LiteralPath $part -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { exit 4 }
}
if ($env:SVM_SSH_CREATE -eq 'yes') {
    if (Test-Path -LiteralPath $path) { exit 4 }
    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $acl.SetOwner($user)
    $acl.SetAccessRuleProtection($true, $false)
    $rule = [Security.AccessControl.FileSystemAccessRule]::new(
        $user, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
    $acl.AddAccessRule($rule)
    $null = [IO.Directory]::CreateDirectory($path, $acl)
}
Verify-Private $path $true
if ($env:SVM_SSH_CREATE -ne 'yes') {
    foreach ($entry in @('id_ed25519','id_ed25519.pub')) {
        $file = [IO.Path]::Combine($path, $entry)
        if ($env:SVM_SSH_CREATE -eq 'seal') {
            $item = Get-Item -LiteralPath $file -Force
            if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { exit 4 }
            if ((Get-Acl -LiteralPath $file).GetOwner([Security.Principal.SecurityIdentifier]) -ne $user) { exit 4 }
            $acl = [Security.AccessControl.FileSecurity]::new()
            $acl.SetOwner($user)
            $acl.SetAccessRuleProtection($true, $false)
            $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new($user, 'FullControl', 'Allow'))
            # Create the replacement with its restrictive DACL already set. This needs no audit privilege.
            $sealed = $file + '.sealed'
            $output = [IO.FileStream]::new($sealed, [IO.FileMode]::CreateNew,
                [Security.AccessControl.FileSystemRights]::FullControl, [IO.FileShare]::None,
                4096, [IO.FileOptions]::None, $acl)
            try {
                $source = [IO.File]::OpenRead($file)
                try { $source.CopyTo($output); $output.Flush($true) } finally { $source.Dispose() }
            } finally { $output.Dispose() }
            Verify-Private $sealed $false
            [IO.File]::Delete($file)
            [IO.File]::Move($sealed, $file)
        }
        Verify-Private $file $false
    }
}
