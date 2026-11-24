$session = $null
$mutex = $null
$held = $false
$phase = 'request'
try {
    [Console]::InputEncoding = [Text.UTF8Encoding]::new($false)
    $null = [Reflection.Assembly]::Load("System.Web.Extensions, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35")
    $serializer = [Web.Script.Serialization.JavaScriptSerializer]::new()
    $request = $serializer.DeserializeObject([Console]::In.ReadToEnd())
    $p = @{ id = [string]$request.id; guid = [string]$request.guid }
    $operation = $serializer.Serialize(@{
        op = [string]$request.op
        finalPath = [string]$request.finalPath
        stage = [string]$request.stage
        token = [string]$request.token
        length = [string]$request.length
        sha256 = [string]$request.sha256
    })
    $phase = 'ownership'
    $env:PSModulePath = [IO.Path]::Combine($PSHOME, 'Modules')
    Import-Module Hyper-V -ErrorAction Stop
    $mutex = [Threading.Mutex]::new($false, 'Global\SecwizVM-HyperV-Management')
    try { $held = $mutex.WaitOne(10000) } catch [Threading.AbandonedMutexException] { $held = $true }
    if (!$held) { throw 'The VM registration could not be locked.' }
    $guid = [guid]$p.guid
    $vm = OwnedVM $p
    if ($guid -eq [guid]::Empty -or $vm.Id -ne $guid -or $vm.State.ToString() -ne 'Running') {
        throw 'The verified VM is not running or its registration changed.'
    }
    $mutex.ReleaseMutex()
    $held = $false

    $phase = 'session'
    $secure = [Security.SecureString]::new()
    try {
        $password = [string]$request.password
        for ($index = 0; $index -lt $password.Length; $index++) { $secure.AppendChar($password[$index]) }
        $password = $null
        $request.password = $null
        $secure.MakeReadOnly()
        $credential = [Management.Automation.PSCredential]::new([string]$request.username, $secure)
        $request.Clear()
        $request = $null
        $session = New-PSSession -VMId $guid -Credential $credential -ErrorAction Stop
    } finally {
        $secure.Dispose()
        $credential = $null
    }
    $phase = 'ownership'
    try { $held = $mutex.WaitOne(10000) } catch [Threading.AbandonedMutexException] { $held = $true }
    if (!$held) { throw 'The VM registration could not be locked.' }
    $verified = OwnedVM $p
    if ($verified.Id -ne $guid -or $verified.State.ToString() -ne 'Running') {
        throw 'The VM registration changed while the session connected.'
    }
    $mutex.ReleaseMutex()
    $held = $false
    $phase = 'transfer'

    $result = Invoke-Command -Session $session -ArgumentList $operation -ScriptBlock {
        param([string]$json)
        $ErrorActionPreference = 'Stop'
        $request = ConvertFrom-Json -InputObject $json
        $final = [string]$request.finalPath
        $stage = [string]$request.stage
        $token = [string]$request.token
        $parent = [IO.Path]::GetDirectoryName($final)
        if ($token -cnotmatch '\A[a-f0-9]{32}\z' -or $stage -cne [IO.Path]::Combine($parent, ".svm-file-$token")) {
            throw 'Invalid guest staging location.'
        }
        for ($dir = [IO.DirectoryInfo]::new($parent); $null -ne $dir; $dir = $dir.Parent) {
            $item = Get-Item -LiteralPath $dir.FullName -Force
            if ($item -isnot [IO.DirectoryInfo] -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
                throw 'The guest destination crosses a link or junction.'
            }
        }
        $marker = [IO.Path]::Combine($stage, 'owner')
        $part = [IO.Path]::Combine($stage, 'data.part')
        $current = [Security.Principal.WindowsIdentity]::GetCurrent().User
        $system = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')
        function ExactGuestFile([string]$path) {
            $item = Get-Item -LiteralPath $path -Force
            if ($item -isnot [IO.FileInfo] -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
                throw 'A regular guest file is required.'
            }
            return $item
        }
        function StageExists {
            try { $item = Get-Item -LiteralPath $stage -Force -ErrorAction Stop }
            catch {
                if ($_.CategoryInfo.Category -eq [Management.Automation.ErrorCategory]::ObjectNotFound) { return $false }
                throw
            }
            if ($item -isnot [IO.DirectoryInfo] -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
                throw 'The private upload folder changed.'
            }
            $acl = $item.GetAccessControl()
            if (!$acl.AreAccessRulesProtected -or !$acl.GetOwner([Security.Principal.SecurityIdentifier]).Equals($current)) {
                throw 'The private upload folder permissions changed.'
            }
            $allowed = $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])
            if ($allowed.Count -lt 1 -or @($allowed | Where-Object {
                !$_.IdentityReference.Equals($current) -and !$_.IdentityReference.Equals($system)
            }).Count) {
                throw 'The private upload folder permissions changed.'
            }
            return $true
        }
        if ($request.op -ceq 'prepare') {
            if (Get-Item -LiteralPath $final -Force -ErrorAction SilentlyContinue) { return @{ error = 'destination' } }
            if (Get-Item -LiteralPath $stage -Force -ErrorAction SilentlyContinue) {
                throw 'The proposed guest staging folder already exists.'
            }
            $acl = [Security.AccessControl.DirectorySecurity]::new()
            $acl.SetAccessRuleProtection($true, $false)
            $acl.SetOwner($current)
            foreach ($sid in @($current, $system)) {
                $rule = [Security.AccessControl.FileSystemAccessRule]::new(
                    $sid, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
                $acl.AddAccessRule($rule)
            }
            $null = [IO.Directory]::CreateDirectory($stage, $acl)
            if (!(StageExists)) { throw 'Could not verify the private upload folder.' }
            $handle = [IO.File]::Open($marker, 'CreateNew', 'Write', 'None')
            try {
                $bytes = [Text.Encoding]::ASCII.GetBytes($token)
                $handle.Write($bytes, 0, $bytes.Length)
            } finally { $handle.Dispose() }
            return @{ ok = $true }
        }
        if (!(StageExists)) {
            if ($request.op -ceq 'clear') { return @{ ok = $true } }
            throw 'The private upload folder is missing.'
        }
        $markerItem = ExactGuestFile $marker
        if ($markerItem.Length -ne 32 -or [IO.File]::ReadAllText($marker) -cne $token) {
            throw 'The private upload folder owner marker changed.'
        }
        switch -CaseSensitive ($request.op) {
            'verify' {
                $file = ExactGuestFile $part
                $handle = [IO.File]::Open($file.FullName, 'Open', 'Read', 'Read')
                $digest = [Security.Cryptography.SHA256]::Create()
                try {
                    $actual = [BitConverter]::ToString($digest.ComputeHash($handle)).Replace('-', '').ToLowerInvariant()
                    if ($handle.Length.ToString([Globalization.CultureInfo]::InvariantCulture) -cne $request.length -or
                        $actual -cne $request.sha256) { return @{ error = 'checksum' } }
                } finally {
                    $digest.Dispose()
                    $handle.Dispose()
                }
            }
            'publish' {
                $null = ExactGuestFile $part
                try { [IO.File]::Move($part, $final) }
                catch {
                    if (Get-Item -LiteralPath $final -Force -ErrorAction SilentlyContinue) { return @{ error = 'destination' } }
                    throw
                }
            }
            'clear' {
                if (Get-Item -LiteralPath $part -Force -ErrorAction SilentlyContinue) {
                    $null = ExactGuestFile $part
                    [IO.File]::Delete($part)
                }
                [IO.File]::Delete($marker)
                [IO.Directory]::Delete($stage, $false)
            }
            default { throw 'Unknown guest file operation.' }
        }
        return @{ ok = $true }
    }
    [Console]::Out.WriteLine((ConvertTo-Json -InputObject $result -Compress -Depth 3))
} catch {
    [Console]::Out.WriteLine((ConvertTo-Json -InputObject @{ error = $phase } -Compress))
} finally {
    if ($held) { $mutex.ReleaseMutex() }
    if ($mutex) { $mutex.Dispose() }
    if ($session) { Remove-PSSession -Session $session -ErrorAction SilentlyContinue }
}
}
