function ThrowawayMachine($p, $folder) {
 $v = OwnedVM $p
 $location = if ($v.ConfigurationLocation) { $v.ConfigurationLocation } else { $v.Path }
 if (!$location -or !(IsBelow (ExactPath $location) $folder)) {
  Refuse 'The machine is not in its own bundle.'
 }
 return $v
}

function OnlyDisk($vm) {
 $drives = @(Get-VMHardDiskDrive -VM $vm)
 if ($drives.Count -ne 1 -or !$drives[0].Path) {
  Refuse 'Throwaway mode needs exactly one VHDX.'
 }
 return $drives[0]
}

function AssertNoCheckpoints($vm) {
 if (@(Get-VMSnapshot -VM $vm).Count) {
  Refuse 'Remove the checkpoints first.'
 }
}

function ReadBackDisk($p, $folder, $expected) {
 $v = ThrowawayMachine $p $folder
 $drive = OnlyDisk $v
 if ($v.State.ToString() -ne 'Off' -or (ExactPath $drive.Path) -ine $expected) {
  Refuse 'Hyper-V did not confirm the disk swap.'
 }
}

function WriteThrowawayRecord($journal, $record) {
 $stage = $journal + '.' + [guid]::NewGuid().ToString('N') + '.tmp'
 try {
  $bytes = [Text.Encoding]::UTF8.GetBytes(($record | ConvertTo-Json -Compress))
  $file = [IO.File]::Open($stage, 'CreateNew', 'Write', 'None')
  try { $file.Write($bytes, 0, $bytes.Length); $file.Flush($true) } finally { $file.Dispose() }
  [IO.File]::Move($stage, $journal)
 } finally { if (Test-Path -LiteralPath $stage) { [IO.File]::Delete($stage) } }
}

function RestoreThrowaway($p, $v, $folder, $journal, $base, $leaf) {
 if (!(Test-Path -LiteralPath $journal)) { return @{ recovered=$false } }
 $state = $v.State.ToString()
 if ($state -notmatch '^Off$|Saved|Hibernated') { return @{ recovered=$false } }
 $item = Get-Item -LiteralPath $journal -Force
 if ($item.PSIsContainer -or $item.Length -gt 4096) { Refuse 'The throwaway record is invalid.' }
 $record = [IO.File]::ReadAllText($journal) | ConvertFrom-Json
 if ($record.id -cne $p.id -or $record.guid -ine $v.Id.ToString() -or
  $record.original -cne 'system.vhdx' -or $record.overlay -cne '.svm-throwaway.vhdx' -or @($record.auto).Count -ne 3) {
  Refuse 'The throwaway record does not match this machine.'
 }
 if (!(Test-Path -LiteralPath $base -PathType Leaf)) { Refuse 'The original VHDX is missing.' }
 $disk = Get-Item -LiteralPath $base -Force
 AssertNoCheckpoints $v
 $drive = OnlyDisk $v
 $attached = ExactPath $drive.Path
 if ($attached -ine $base -and $attached -ine $leaf) {
  Refuse 'The disk attachment changed outside the throwaway run.'
 }
 if ($state -ne 'Off') {
  if ($attached -ine $leaf) { Refuse 'Kept a session saved on the original disk. Discard it to finish recovery.' }
  Remove-VMSavedState -VM $v
  if ((OwnedVM $p).State.ToString() -ne 'Off') { return @{ recovered=$false } }
  $drive = OnlyDisk (OwnedVM $p)
 }
 if ($attached -ieq $leaf) { $disk.IsReadOnly = $false; try { Set-VMHardDiskDrive -VMHardDiskDrive $drive -Path $base } finally { $disk.IsReadOnly = $true } }
 $disk.IsReadOnly = $true
 ReadBackDisk $p $folder $base
 Set-VM -VM (OwnedVM $p) -AutomaticStartAction $record.auto[0] -AutomaticStopAction $record.auto[1] -CheckpointType $record.auto[2]
 if (Test-Path -LiteralPath $leaf) {
  $file = [IO.File]::Open($leaf, 'Open', 'Read', 'None')
  $file.Dispose()
  [IO.File]::Delete($leaf)
 }
 [IO.File]::Delete($journal)
 return @{ recovered=$true }
}

function Dispatch($p) {
 $folder = Bundle $p
 $v = ThrowawayMachine $p $folder
 $journal = ExactPath ([IO.Path]::Combine($folder, 'hyperv-throwaway.json'))
 $base = ExactPath ([IO.Path]::Combine($folder, 'system.vhdx'))
 $leaf = ExactPath ([IO.Path]::Combine($folder, '.svm-throwaway.vhdx'))
 if ($p.op -ceq 'throwawayRecover') { return (RestoreThrowaway $p $v $folder $journal $base $leaf) }
 if ($p.op -cne 'throwawayStart') { Refuse 'Unknown Hyper-V throwaway operation.' }
 if ($v.State.ToString() -ne 'Off' -or (Test-Path -LiteralPath $journal) -or (Test-Path -LiteralPath $leaf)) {
  Refuse 'Power off and recover the previous throwaway run first.'
 }
 AssertNoCheckpoints $v
 $security = Get-VMSecurity -VM $v
 if ($null -eq $security -or $null -eq $security.TpmEnabled -or $security.TpmEnabled) {
  Refuse 'Throwaway mode requires a disabled virtual TPM.'
 }
 $drive = OnlyDisk $v
 if ((ExactPath $drive.Path) -ine $base -or !(Test-Path -LiteralPath $base -PathType Leaf)) {
  Refuse 'Throwaway mode requires the bundle system VHDX.'
 }
 $info = Get-VHD -Path $base
 if ($info.VhdFormat -ne 'VHDX' -or !$info.Path -or (ExactPath $info.Path) -ine $base) {
  Refuse 'Hyper-V could not verify the persistent disk.'
 }
 if ($p.templateDisk) {
  $parent = ExactPath $p.templateDisk
  if ($info.VhdType -ne 'Differencing' -or !$info.ParentPath -or (ExactPath $info.ParentPath) -ine $parent -or
   !((Get-Item -LiteralPath $parent -Force).Attributes -band [IO.FileAttributes]::ReadOnly)) {
   Refuse 'The linked disk no longer matches its read-only template.'
  }
 } elseif ($info.VhdType -notin @('Fixed','Dynamic') -or $info.ParentPath) {
  Refuse 'A standalone machine needs a standalone VHDX.'
 }
 $auto = @("$($v.AutomaticStartAction)", "$($v.AutomaticStopAction)", "$($v.CheckpointType)")
 WriteThrowawayRecord $journal @{ id=$p.id; guid=$v.Id.ToString(); original='system.vhdx'; overlay='.svm-throwaway.vhdx'; auto=$auto }
 try {
  Set-VM -VM $v -AutomaticStartAction Nothing -AutomaticStopAction TurnOff -CheckpointType Disabled
  $null = New-VHD -Path $leaf -ParentPath $base -Differencing
  $delta = Get-VHD -Path $leaf
  if ($delta.VhdFormat -ne 'VHDX' -or $delta.VhdType -ne 'Differencing' -or !$delta.ParentPath -or
   (ExactPath $delta.ParentPath) -ine $base) {
   Refuse 'Hyper-V could not verify the throwaway disk.'
  }
  Set-VMHardDiskDrive -VMHardDiskDrive $drive -Path $leaf
  ReadBackDisk $p $folder $leaf
  $owned = ThrowawayMachine $p $folder
  GrantChainAccess $owned $p
  $null = Start-VM -VM $owned
  return @{ started=$true }
 } catch {
  try { $null = RestoreThrowaway $p (ThrowawayMachine $p $folder) $folder $journal $base $leaf } catch {}
  throw
 }
}
