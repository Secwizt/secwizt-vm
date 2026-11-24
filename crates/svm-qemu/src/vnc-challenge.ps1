$ErrorActionPreference = 'Stop'
if ([Security.Cryptography.CryptoConfig]::AllowOnlyFipsAlgorithms) { exit 3 }
$inputPipe = [Console]::OpenStandardInput()
$outputPipe = [Console]::OpenStandardOutput()
$provider = [Security.Cryptography.DESCryptoServiceProvider]::new()
$provider.Mode = [Security.Cryptography.CipherMode]::ECB
$provider.Padding = [Security.Cryptography.PaddingMode]::None
$key = New-Object byte[] 8
$challenge = New-Object byte[] 16
$reply = $null
function Read-Block([byte[]] $buffer) {
    $offset = 0
    while ($offset -lt $buffer.Length) {
        $got = $inputPipe.Read($buffer, $offset, $buffer.Length - $offset)
        if ($got -eq 0) { throw 'Incomplete display challenge.' }
        $offset += $got
    }
}
try {
    # Check the host provider against a public two-block DES known answer.
    $provider.Key = [byte[]] (0x13,0x34,0x57,0x79,0x9b,0xbc,0xdf,0xf1)
    $sample = [byte[]] (0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef,0x01,0x23,0x45,0x67,0x89,0xab,0xcd,0xef)
    $probe = $provider.CreateEncryptor()
    try {
        if ([BitConverter]::ToString($probe.TransformFinalBlock($sample,0,16)) -cne '85-E8-13-54-0F-0A-B4-05-85-E8-13-54-0F-0A-B4-05') { exit 4 }
    } finally { $probe.Dispose() }

    Read-Block $key
    Read-Block $challenge
    $provider.Key = $key
    $cipher = $provider.CreateEncryptor()
    try {
        $reply = $cipher.TransformFinalBlock($challenge, 0, $challenge.Length)
        $outputPipe.Write($reply, 0, $reply.Length)
        $outputPipe.Flush()
    } finally { $cipher.Dispose() }
} finally {
    [Array]::Clear($key, 0, $key.Length)
    [Array]::Clear($challenge, 0, $challenge.Length)
    if ($null -ne $reply) { [Array]::Clear($reply, 0, $reply.Length) }
    $provider.Dispose()
}
