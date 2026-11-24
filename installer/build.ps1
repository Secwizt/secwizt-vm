[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string] $PayloadDirectory,
    [string] $OutputDirectory = (Join-Path $PSScriptRoot '..\target\installer'),
    [ValidatePattern('^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.+-]+)?$')]
    [string] $Version
)

$ErrorActionPreference = 'Stop'
$compiler = 'C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe'
if (-not (Test-Path -LiteralPath $compiler -PathType Leaf)) {
    throw "The required .NET Framework compiler was not found at $compiler."
}

$payload = (Get-Item -LiteralPath $PayloadDirectory).FullName
$output = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputDirectory)
$binaries = 'svm-app.exe', 'svmd.exe', 'svm.exe'
foreach ($name in $binaries) {
    if (-not (Test-Path -LiteralPath (Join-Path $payload $name) -PathType Leaf)) {
        throw "The payload folder is missing $name."
    }
}
# The licence, NOTICE and third-party licence texts must travel with the programs.
# Keep this list in step with Payload in Setup.cs.
$repository = (Get-Item -LiteralPath (Join-Path $PSScriptRoot '..')).FullName
$documents = 'LICENSE', 'NOTICE', 'THIRD-PARTY-NOTICES.md', 'THIRD-PARTY-LICENSES.txt'
foreach ($name in $documents) {
    if (-not (Test-Path -LiteralPath (Join-Path $repository $name) -PathType Leaf)) {
        throw "The repository is missing $name."
    }
}
if (-not $Version) {
    $manifest = Get-Content -Raw -LiteralPath (Join-Path $PSScriptRoot '..\crates\svm-app\Cargo.toml')
    $match = [regex]::Match($manifest, '(?m)^version\s*=\s*"([0-9]+\.[0-9]+\.[0-9]+)"')
    if (-not $match.Success) { throw 'Supply -Version because the app version could not be read.' }
    $Version = $match.Groups[1].Value
}

$stage = Join-Path ([IO.Path]::GetTempPath()) ('secwizvm-build-' + [Guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($stage)
try {
    foreach ($name in $binaries) {
        [IO.File]::Copy((Join-Path $payload $name), (Join-Path $stage $name))
    }
    foreach ($name in $documents) {
        [IO.File]::Copy((Join-Path $repository $name), (Join-Path $stage $name))
    }
    $files = $binaries + $documents + 'VERSION.txt'
    Set-Content -LiteralPath (Join-Path $stage 'VERSION.txt') -Encoding Ascii -Value $Version
    $hashes = foreach ($name in $files) {
        $hash = (Get-FileHash -LiteralPath (Join-Path $stage $name) -Algorithm SHA256).Hash
        "$hash  $name"
    }
    Set-Content -LiteralPath (Join-Path $stage 'payload.sha256') -Encoding Ascii -Value $hashes

    $setup = Join-Path $stage 'SecwizVM-Setup.exe'
    $compilerArgs = @('/nologo', '/target:winexe', '/platform:anycpu', '/optimize+', '/warnaserror+',
        '/reference:System.Windows.Forms.dll', '/reference:Microsoft.CSharp.dll',
        "/win32manifest:$(Join-Path $PSScriptRoot 'setup.manifest')",
        "/win32icon:$(Join-Path $PSScriptRoot '..\crates\svm-app\assets\svm.ico')", "/out:$setup")
    foreach ($name in $files + 'payload.sha256') {
        $compilerArgs += "/resource:$(Join-Path $stage $name),$name"
    }
    $compilerArgs += Join-Path $PSScriptRoot 'Setup.cs'
    & $compiler @compilerArgs
    if ($LASTEXITCODE -ne 0) { throw "The .NET Framework compiler exited with code $LASTEXITCODE." }

    [void][IO.Directory]::CreateDirectory($output)
    $releaseSetup = Join-Path $output 'SecwizVM-Setup.exe'
    [IO.File]::Copy($setup, $releaseSetup, $true)

    # Optional: sign $releaseSetup with your own code-signing certificate here.
    # Run the next two lines again after signing to publish the hash of the signed file.
    $releaseHash = (Get-FileHash -LiteralPath $releaseSetup -Algorithm SHA256).Hash
    Set-Content -LiteralPath (Join-Path $output 'SHA256SUMS.txt') -Encoding Ascii -Value "$releaseHash  SecwizVM-Setup.exe"
    Get-Item -LiteralPath $releaseSetup
} finally {
    foreach ($name in $binaries + $documents + 'VERSION.txt' + 'payload.sha256' + 'SecwizVM-Setup.exe') {
        [IO.File]::Delete((Join-Path $stage $name))
    }
    [IO.Directory]::Delete($stage)
}
