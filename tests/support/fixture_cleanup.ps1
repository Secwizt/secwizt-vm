$ErrorActionPreference = 'Stop'
$root = $env:SVM_FIXTURE_FOLDER
if ($root.StartsWith('\\?\')) { $root = $root.Substring(4) }
$root = [IO.Path]::GetFullPath($root).TrimEnd('\') + '\'
$id = $env:SVM_FIXTURE_MACHINE
if ($id) {
    if ($id -notmatch '^test-[a-z0-9-]+$') { throw 'Missing fixture identity.' }
    $guests = @(Get-VM -ErrorAction Stop | Where-Object Name -eq ('svm-' + $id))
    foreach ($v in $guests) {
        $location = [IO.Path]::GetFullPath($v.ConfigurationLocation)
        if ($v.Notes -cne ('secwiz-vm:' + $id) -or !$location.StartsWith($root,[StringComparison]::OrdinalIgnoreCase)) {
            throw 'The machine does not belong to this fixture directory.'
        }
        if ($v.State.ToString() -eq 'Paused') { Resume-VM -VM $v }
        if ($v.State.ToString() -ne 'Off') { Stop-VM -VM $v -TurnOff -Force -Confirm:$false }
        Remove-VM -VM $v -Force -Confirm:$false
    }
}
$id = $env:SVM_FIXTURE_NETWORK
if ($id) {
    if ($id -notmatch '^test-[a-z0-9-]+$') { throw 'Missing fixture network identity.' }
    foreach ($s in @(Get-VMSwitch -ErrorAction Stop | Where-Object Name -eq ('SVM-' + $id))) {
        if ($s.Notes -cne ('secwiz-switch:' + $id) -or $s.SwitchType.ToString() -ne 'Internal') { throw 'The switch does not belong to this fixture.' }
        $guests = @(Get-VMNetworkAdapter -All | Where-Object { $_.SwitchId -eq $s.Id -and !$_.IsManagementOs })
        if ($guests.Count) { throw 'Another machine is connected to the fixture switch.' }
        Remove-VMSwitch -VMSwitch $s -Force -Confirm:$false
    }
}
