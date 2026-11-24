$session = $null
$mutex = $null
$held = $false
$phase = 'request'
$filePath = ''
try {
    [Console]::InputEncoding = [Text.UTF8Encoding]::new($false)
    $null = [Reflection.Assembly]::Load("System.Web.Extensions, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35")
    $serializer = [Web.Script.Serialization.JavaScriptSerializer]::new()
    $request = $serializer.DeserializeObject([Console]::In.ReadToEnd())
    $p = @{ id=[string]$request.id; guid=[string]$request.guid }
    $filePath = [string]$request.filePath
    $argument = if (!$filePath) { $serializer.Serialize($request.command) }
    $env:PSModulePath = [IO.Path]::Combine($PSHOME, 'Modules')
    $phase = 'ownership'
    Import-Module Hyper-V -ErrorAction Stop
    $mutex = [Threading.Mutex]::new($false, 'Global\SecwizVM-HyperV-Management')
    try { $held = $mutex.WaitOne(10000) } catch [Threading.AbandonedMutexException] { $held = $true }
    if (!$held) { throw 'The VM registration could not be locked.' }
    $vm = OwnedVM $p
    $guid = [guid]$p.guid
    if ($guid -eq [guid]::Empty -or $vm.Id -ne $guid -or $vm.State.ToString() -ne 'Running') {
        throw 'The verified VM is not running or its registration changed.'
    }
    $mutex.ReleaseMutex()
    $held = $false
    $phase = 'session'
    $secure = [Security.SecureString]::new()
    $password = [string]$request.password
    for ($index = 0; $index -lt $password.Length; $index++) { $secure.AppendChar($password[$index]) }
    $password = $null
    $request.password = $null
    $secure.MakeReadOnly()
    $credential = [Management.Automation.PSCredential]::new([string]$request.username, $secure)
    $request.Clear()
    $request = $null
    try { $session = New-PSSession -VMId $guid -Credential $credential -ErrorAction Stop }
    finally {
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
    $phase = 'command'

    if ($filePath) {
        # Only one regular file is sent. Frame its checksum and length before the bytes.
        $output = [Console]::OpenStandardOutput()
        $first = $true
        Invoke-Command -Session $session -ArgumentList $filePath -ScriptBlock {
            param([string]$literal)
            $ErrorActionPreference = 'Stop'
            $item = Get-Item -LiteralPath $literal -Force
            if ($item -isnot [IO.FileInfo] -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
                throw 'A regular guest file is required.'
            }
            $file = [IO.File]::Open($item.FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
            try {
                $digest = [Security.Cryptography.SHA256]::Create()
                try { $hash = [BitConverter]::ToString($digest.ComputeHash($file)).Replace('-', '').ToLowerInvariant() }
                finally { $digest.Dispose() }
                $file.Position = 0
                'SVMFILE {0} {1}' -f ($file.Length.ToString([Globalization.CultureInfo]::InvariantCulture)), $hash
                $buffer = [byte[]]::new(65536)
                while (($count = $file.Read($buffer, 0, $buffer.Length)) -gt 0) {
                    [Convert]::ToBase64String($buffer, 0, $count)
                }
            } finally { $file.Dispose() }
        } | ForEach-Object {
            $frame = [string]$_
            if ($first) {
                if ($frame -cnotmatch '\ASVMFILE [0-9]{1,20} [a-f0-9]{64}\z') { throw 'Invalid file metadata.' }
                $bytes = [Text.Encoding]::ASCII.GetBytes($frame + [char]10)
                $first = $false
            } else {
                if ($frame.Length -gt 87384) { throw 'Invalid file data size.' }
                $bytes = [Convert]::FromBase64String($frame)
                if (!$bytes.Length -or $bytes.Length -gt 65536) { throw 'Invalid file data size.' }
            }
            $output.Write($bytes, 0, $bytes.Length)
        }
        if ($first) { throw 'The guest file header was missing.' }
        $output.Flush()
        return
    }

    # Only the command fields cross the session. Credentials remain with PowerShell Direct.
    $result = Invoke-Command -Session $session -ArgumentList $argument -ScriptBlock {
        param([string]$request)
        $ErrorActionPreference = 'Stop'
        $command = ConvertFrom-Json -InputObject $request

        function Quote-Argument([string]$value) {
            $escaped = [regex]::Replace($value, '(\\*)("|$)', [Text.RegularExpressions.MatchEvaluator]{
                param($match)
                $count = 2 * $match.Groups[1].Length
                if ($match.Groups[2].Value -eq '"') { return ('\' * ($count + 1)) + '"' }
                return ('\' * $count)
            })
            return '"' + $escaped + '"'
        }

        $start = [Diagnostics.ProcessStartInfo]::new()
        $start.FileName = [string]$command.argv[0]
        $args = @($command.argv | Select-Object -Skip 1 | ForEach-Object { Quote-Argument $_ })
        $start.Arguments = $args -join ' '
        $start.UseShellExecute = $false
        $start.RedirectStandardInput = $true
        $start.RedirectStandardOutput = $true
        $start.RedirectStandardError = $true
        $start.CreateNoWindow = $true
        $child = [Diagnostics.Process]::new()
        $child.StartInfo = $start
        $streams = @()
        try {
            if (!$child.Start()) { return @{ error='start' } }
            $clock = [Diagnostics.Stopwatch]::StartNew()
            $stdin = $child.StandardInput.BaseStream
            $inputBytes = [Text.Encoding]::UTF8.GetBytes([string]$command.stdin)
            $write = $null
            if ($inputBytes.Length) { $write = $stdin.WriteAsync($inputBytes, 0, $inputBytes.Length) }
            else { $stdin.Close() }

            foreach ($pipe in @($child.StandardOutput.BaseStream, $child.StandardError.BaseStream)) {
                $buffer = [byte[]]::new(16384)
                $streams += [pscustomobject]@{
                    pipe = $pipe
                    buffer = $buffer
                    read = $pipe.ReadAsync($buffer, 0, $buffer.Length)
                    kept = [IO.MemoryStream]::new()
                    cut = $false
                }
            }
            while ($true) {
                $progress = $false
                if ($write -and $write.IsCompleted) {
                    $stdin.Close()
                    $write = $null
                }
                foreach ($stream in $streams) {
                    if (!$stream.read -or !$stream.read.IsCompleted) { continue }
                    $progress = $true
                    $count = $stream.read.GetAwaiter().GetResult()
                    if (!$count) { $stream.read = $null; continue }
                    $keep = [int][Math]::Min($count, 1048576 - $stream.kept.Length)
                    if ($keep) { $stream.kept.Write($stream.buffer, 0, $keep) }
                    if ($keep -ne $count) { $stream.cut = $true }
                    $stream.read = $stream.pipe.ReadAsync($stream.buffer, 0, $stream.buffer.Length)
                }
                if ($child.HasExited -and !$streams[0].read -and !$streams[1].read) { break }
                if ($clock.Elapsed.TotalSeconds -ge [double]$command.timeoutSec) { return @{ timeout=$true } }
                if (!$progress) { Start-Sleep -Milliseconds 10 }
            }
            return @{
                exitCode = $child.ExitCode
                stdoutB64 = [Convert]::ToBase64String($streams[0].kept.ToArray())
                stderrB64 = [Convert]::ToBase64String($streams[1].kept.ToArray())
                stdoutTruncated = $streams[0].cut
                stderrTruncated = $streams[1].cut
            }
        } catch {
            return @{ error='start' }
        } finally {
            foreach ($stream in $streams) { $stream.kept.Dispose() }
            $child.Dispose()
        }
    }
    [Console]::Out.WriteLine((ConvertTo-Json -InputObject $result -Compress -Depth 4))
} catch {
    if ($filePath) { exit 3 }
    # Native error messages can contain submitted values. Only the stage is returned.
    [Console]::Out.WriteLine((ConvertTo-Json -InputObject @{ error=$phase } -Compress))
} finally {
    if ($held) { $mutex.ReleaseMutex() }
    if ($mutex) { $mutex.Dispose() }
    if ($session) { Remove-PSSession -Session $session -ErrorAction SilentlyContinue }
}
}
