$ErrorActionPreference = 'Stop'
$installer = Get-AppxPackage -Name Microsoft.DesktopAppInstaller |
    Where-Object { $_.PublisherId -eq '8wekyb3d8bbwe' } |
    Sort-Object Version -Descending | Select-Object -First 1
if (!$installer) { throw 'Install Microsoft App Installer for this Windows guest account first.' }
$winget = Join-Path $installer.InstallLocation 'winget.exe'
$details = & $winget source export --name winget --disable-interactivity
if ($LASTEXITCODE -ne 0) { throw 'WinGet could not read the Microsoft community repository.' }
$source = $details | ConvertFrom-Json
if ($source.Name -cne 'winget' -or
    $source.Arg -cne 'https://cdn.winget.microsoft.com/cache' -or
    $source.Identifier -cne 'Microsoft.Winget.Source_8wekyb3d8bbwe' -or
    $source.Type -cne 'Microsoft.PreIndexed.Package') {
    throw 'The winget source is not the Microsoft community repository.'
}
