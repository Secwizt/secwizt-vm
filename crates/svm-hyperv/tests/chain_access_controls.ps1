$ErrorActionPreference = 'Stop'
. ([scriptblock]::Create([IO.File]::ReadAllText($env:SVM_CHAIN_SOURCE)))

# The provider, VM account lookup and ACL store are in memory. ExactPath and the grant code are real.
$folder = 'C:\library\child.swvm'
$leaf = "$folder\.svm-throwaway.vhdx"
$base = "$folder\system.vhdx"
$template = 'C:\library\template.swvm\system.vhdx'
$sibling = 'C:\library\sibling.swvm\system.vhdx'
$outside = 'C:\library-other\template.swvm\system.vhdx'
$vm = @{ Id = [guid]::NewGuid() }
$reader = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-545')
function DiskReader($id) {
    if ($id -ne $vm.Id) { throw 'Wrong VM account' }
    $reader
}
function Bundle($p) { $folder }
function Refuse($message) { throw $message }
function Test-Path($LiteralPath) { return $LiteralPath -eq $link }
function Get-Item($LiteralPath, [switch]$Force) { @{ Attributes = [IO.FileAttributes]::ReparsePoint } }
function Get-VMHardDiskDrive($VM) { @{ Path = $leaf } }
function Get-VHD($Path) {
    $script:reads += $Path
    @{ ParentPath = $chain[$Path] }
}
function Get-Acl($LiteralPath) { [Security.AccessControl.FileSecurity]::new() }
function Set-Acl($LiteralPath, $AclObject) {
    $rules = @($AclObject.GetAccessRules(1, 1, [Security.Principal.SecurityIdentifier]))
    if ($rules.Count -ne 1 -or $rules[0].IdentityReference -ne $reader -or
        $rules[0].AccessControlType -ne 'Allow' -or
        $rules[0].FileSystemRights -ne [Security.AccessControl.FileSystemRights]'Read, Synchronize') { throw 'Wrong ACL' }
    $script:grants += $LiteralPath
}
function CheckRun($parents, $expectGrants, $expectReads, [bool]$refuseLink = $false) {
    $script:grants = @()
    $script:reads = @()
    $blocked = $false
    try { GrantChainAccess $vm @{ parents = $parents } }
    catch { if ($_.Exception.Message -notlike '*crosses a link*') { throw }; $blocked = $true }
    if ($blocked -ne $refuseLink -or ($grants -join ';') -ne ($expectGrants -join ';') -or
        ($reads -join ';') -ne ($expectReads -join ';')) { throw "Unexpected walk: reads $reads, grants $grants, blocked $blocked" }
}
$link = $null
$chain = @{ $leaf = $base; $base = $template; $template = $sibling }
CheckRun @($base, $template) @($base, $template) @($leaf, $base)
CheckRun @($base) @($base) @($leaf)
CheckRun @() @() @()
CheckRun @($template, $base) @() @($leaf)
$chain[$leaf] = $sibling
CheckRun @($base, $template) @() @($leaf)
$chain[$leaf] = $outside
CheckRun @($outside) @() @($leaf)
$chain[$leaf] = $base
$link = [IO.Path]::GetDirectoryName($template)
CheckRun @($base, $template) @($base) @($leaf, $base) $true
$link = $leaf
CheckRun @($base) @() @() $true
