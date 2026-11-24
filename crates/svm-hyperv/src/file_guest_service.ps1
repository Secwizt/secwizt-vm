function FileGuestService($vm) {
    $id = 'Microsoft:{0}\6C09BB55-D683-4DA0-8931-C9BF705F6480' -f $vm.Id
    $services = @(Get-VMIntegrationService -VM $vm | Where-Object { $_.Id -eq $id })
    if ($services.Count -eq 1) { return $services[0] }
}
function FileGuestServiceStatus($p, $vm) {
    $canChange = $vm.State.ToString() -eq 'Off'
    $service = FileGuestService $vm
    if ($null -eq $service) {
        if ($p.op -eq 'setFileGuestService') { Refuse 'Hyper-V could not identify the Guest Service Interface for this machine.' }
        return @{available=$false;enabled=$false;canChange=$false;reason='Guest Service Interface is unavailable for this machine.'}
    }
    if ($p.op -eq 'setFileGuestService') {
        if (!$canChange) { Refuse 'Shut down the machine before changing Guest Service Interface.' }
        if ($p.enabled -isnot [bool]) { Refuse 'Choose whether Guest Service Interface should be enabled.' }
        if ($service.Enabled -ne $p.enabled) {
            if ($p.enabled) { Enable-VMIntegrationService -VMIntegrationService $service -Confirm:$false }
            else { Disable-VMIntegrationService -VMIntegrationService $service -Confirm:$false }
        }
        $vm = OwnedVM $p
        $service = FileGuestService $vm
        if ($null -eq $service -or $service.Enabled -ne $p.enabled) { Refuse 'Hyper-V did not confirm Guest Service Interface.' }
        $canChange = $vm.State.ToString() -eq 'Off'
    }
    return @{available=$true;enabled=[bool]$service.Enabled;canChange=$canChange}
}
function Dispatch($p) {
    $vm = OwnedVM $p
    return FileGuestServiceStatus $p $vm
}
