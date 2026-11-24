$ErrorActionPreference = 'Stop'
$path = $env:SVM_GUEST_AGENT_DIRECTORY
$owner = [Security.Principal.WindowsIdentity]::GetCurrent().User
$system = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')
$acl = [Security.AccessControl.DirectorySecurity]::new()
$acl.SetOwner($owner)
$acl.SetAccessRuleProtection($true, $false)
foreach ($identity in @($owner, $system)) {
    $rule = [Security.AccessControl.FileSystemAccessRule]::new(
        $identity, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
    $acl.AddAccessRule($rule)
}
if ($env:SVM_DIRECTORY_ACL_MODE -eq 'new') {
    # CreateDirectoryW refuses existing names and applies the descriptor in the creation call.
    Add-Type -TypeDefinition @"
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
public static class SvmPrivateDirectory {
    [StructLayout(LayoutKind.Sequential)]
    private struct Attributes { public int Length; public IntPtr Descriptor; public int Inherit; }
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true, ExactSpelling = true)]
    private static extern bool CreateDirectoryW(string path, ref Attributes security);
    public static void Create(string path, byte[] descriptor) {
        var handle = GCHandle.Alloc(descriptor, GCHandleType.Pinned);
        try {
            var security = new Attributes { Length = Marshal.SizeOf(typeof(Attributes)), Descriptor = handle.AddrOfPinnedObject() };
            if (!CreateDirectoryW(path, ref security)) throw new Win32Exception(Marshal.GetLastWin32Error());
        } finally { handle.Free(); }
    }
}
"@
    [SvmPrivateDirectory]::Create($path, $acl.GetSecurityDescriptorBinaryForm())
}
$folder = Get-Item -LiteralPath $path
if (!$folder.PSIsContainer -or ($folder.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
    throw 'The private directory is invalid.'
}
if ($env:SVM_DIRECTORY_ACL_MODE -eq 'protect') { Set-Acl -LiteralPath $path -AclObject $acl }
$actual = Get-Acl -LiteralPath $path
if (!$actual.AreAccessRulesProtected -or $actual.GetOwner([Security.Principal.SecurityIdentifier]) -ne $owner) {
    throw 'The private directory must be owned by the current user.'
}
$rules = @($actual.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))
if ($rules.Count -ne @($owner.Value, $system.Value | Select-Object -Unique).Count -or
    $owner.Value -notin $rules.IdentityReference.Value -or $system.Value -notin $rules.IdentityReference.Value) {
    throw 'Unexpected private directory permission.'
}
foreach ($rule in $rules) {
    if ($rule.IsInherited -or $rule.AccessControlType -ne 'Allow' -or $rule.FileSystemRights -ne 'FullControl' -or
        $rule.InheritanceFlags -ne 'ContainerInherit,ObjectInherit' -or $rule.PropagationFlags -ne 'None' -or
        ($rule.IdentityReference -ne $owner -and $rule.IdentityReference -ne $system)) {
        throw 'Unexpected private directory permission.'
    }
}
